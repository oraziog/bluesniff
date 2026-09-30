//! Log raw per-pacchetto degli annunci BLE.
//!
//! A differenza di `presenze.csv` (una riga per dispositivo per finestra di
//! scansione), questo log registra **ogni pacchetto** ricevuto con il payload
//! esadecimale completo e la decodifica dei record AD. Serve per analisi
//! forensi: cadenza di trasmissione, cambi di payload nel tempo, beacon
//! sporadici che una finestra di 8 s può perdere.
//!
//! Design:
//! - **Scrittura non bloccante**: il handler WinRT non fa mai I/O; gli eventi
//!   passano per un canale limitato verso un thread writer dedicato. A canale
//!   pieno il pacchetto viene contato come scartato (mai blocchi, mai crescita
//!   di memoria senza limite).
//! - **Rotazione**: il file attivo `raw_log.jsonl` ruota a 64 MB in
//!   `raw_log.<YYYYmmdd-HHMMSS>.jsonl`; la retention cancella i ruotati più
//!   vecchi di 7 giorni (valutata all'avvio e poi una volta all'ora).
//! - **Spegnibile a runtime**: `set_enabled(false)` dalla dashboard ferma la
//!   registrazione senza toccare la scansione.
//!
//! Nota di fedeltà: l'hex è ciò che **Windows consegna** al watcher WinRT.
//! Se il driver/controller filtra o tronca dei payload, qui non compare.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};

use crate::logging::exe_dir;

/// Dimensione massima del file attivo prima della rotazione (64 MB).
pub const ROTATE_BYTES: u64 = 64 * 1024 * 1024;
/// Età massima dei file ruotati, in giorni (7 giorni).
pub const RETENTION_DAYS: u64 = 7;
/// Tetto di righe per l'export in memoria (protegge il processo).
pub const EXPORT_ROW_CAP: usize = 500_000;
/// Coda del writer: abbastanza grande per un burst, abbastanza piccola da
/// non far crescere la memoria se il disco rallenta.
const CHANNEL_CAP: usize = 16_384;

/// Un pacchetto BLE ricevuto, pronto per il log.
#[derive(Clone, Debug, Default)]
pub struct RawEvent {
    /// Epoch millisecondi (dal timestamp WinRT).
    pub ts_ms: i64,
    pub mac: String,
    /// `public` | `random` | `unspecified`.
    pub addr_type: &'static str,
    /// Tipo di annuncio per direzione e risposte (stringa stabile).
    pub adv_type: &'static str,
    pub rssi: Option<i16>,
    /// Bit LE General Discoverable (AD 0x01) quando presente.
    pub connectable: Option<bool>,
    /// Vero se questo pacchetto è una SCAN_RSP.
    pub scan_response: bool,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub hint: Option<String>,
    /// Fast Pair Model ID (0xFE2C) quando presente.
    pub model_id: Option<u32>,
    pub tx_power: Option<i8>,
    /// Record AD completi in hex (una stringa continua, es. `0201060aff...`).
    pub hex: String,
    /// Decodifica leggibile, una voce per record AD.
    pub decode: Vec<String>,
}

impl RawEvent {
    /// Riga JSONL esattamente come finisce sul file.
    pub fn to_line(&self) -> String {
        let ts = crate::logging::rfc3339_millis(self.ts_ms);
        let obj = serde_json::json!({
            "ts": ts,
            "mac": self.mac,
            "addr_type": self.addr_type,
            "adv_type": self.adv_type,
            "rssi": self.rssi,
            "connectable": self.connectable,
            "scan_response": self.scan_response,
            "name": self.name,
            "vendor": self.vendor,
            "hint": self.hint,
            "model_id": self.model_id,
            "tx_power": self.tx_power,
            "hex": self.hex,
            "decode": self.decode,
        });
        obj.to_string()
    }
}

// Interruttore globale (default ON, disattivabile dalla dashboard o da CLI).
static ENABLED: AtomicBool = AtomicBool::new(true);
// Contatori diagnostici (dashboard + log).
static RECORDED: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub fn recorded() -> u64 {
    RECORDED.load(Ordering::Relaxed)
}

pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

enum WriterMsg {
    Event(RawEvent),
}

struct WriterState {
    file: Option<std::fs::File>,
    path: PathBuf,
    written: u64,
    rotations: usize,
}

static WRITER_TX: OnceLock<Mutex<SyncSender<WriterMsg>>> = OnceLock::new();
static FILE_PATH: OnceLock<Mutex<PathBuf>> = OnceLock::new();

/// Percorso del file attivo (letto dalla dashboard).
pub fn active_path() -> PathBuf {
    FILE_PATH
        .get()
        .and_then(|m| m.lock().ok().map(|g| g.clone()))
        .unwrap_or_else(|| exe_dir().join("raw_log.jsonl"))
}

/// Nome del file attivo, solo il nome (per la UI).
pub fn active_file_name() -> String {
    active_path()
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Dimensione del file attivo in byte (0 se non esiste ancora).
pub fn active_file_size() -> u64 {
    std::fs::metadata(active_path())
        .map(|m| m.len())
        .unwrap_or(0)
}

/// Avvia il thread writer e la retention. Idempotente: chiamate successive
/// all'avvio sono no-op (il canale è creato una sola volta).
pub fn init() {
    // Canale limitato: `record` non blocca mai (try_send) e a coda piena
    // conta il pacchetto come scartato invece di far crescere la memoria.
    let (tx, rx) = mpsc::sync_channel::<WriterMsg>(CHANNEL_CAP);

    // Registro il canale e il percorso del file attivo.
    let path = exe_dir().join("raw_log.jsonl");
    let _ = WRITER_TX.set(Mutex::new(tx));
    let _ = FILE_PATH.set(Mutex::new(path.clone()));

    // Thread writer: apre il file, consuma la coda, ruota quando serve.
    std::thread::Builder::new()
        .name("rawlog-writer".to_string())
        .spawn(move || {
            let mut st = WriterState {
                file: None,
                path,
                written: 0,
                rotations: 0,
            };
            // All'avvio: retention sui vecchi, poi riprendi dal file attivo
            // esistente (append, così un riavvio non perde la continuità).
            apply_retention();
            while let Ok(WriterMsg::Event(ev)) = rx.recv() {
                write_event(&mut st, ev);
            }
            // Il canale è chiuso (processo in uscita): nulla da fare, il file
            // è flushato dopo ogni riga.
        })
        .expect("rawlog: spawn writer thread");
}

/// Registra un pacchetto. Non fa I/O e non blocca mai: a canale pieno il
/// pacchetto è contato come scartato. Se il log è spento, non fa nulla.
pub fn record(ev: RawEvent) {
    if !enabled() {
        return;
    }
    let Some(tx) = WRITER_TX.get().and_then(|m| m.lock().ok()) else {
        return;
    };
    match tx.try_send(WriterMsg::Event(ev)) {
        Ok(()) => {
            RECORDED.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Scrittura vera (sul thread writer).
fn write_event(st: &mut WriterState, ev: RawEvent) {
    if st.file.is_none() {
        // Append: se il file esiste già dal run precedente continuiamo da lì.
        match OpenOptions::new().create(true).append(true).open(&st.path) {
            Ok(f) => {
                st.written = std::fs::metadata(&st.path).map(|m| m.len()).unwrap_or(0);
                st.file = Some(f);
            }
            Err(e) => {
                crate::be!(
                    "[BLUESNIFF] rawlog: impossibile aprire {}: {e}",
                    st.path.display()
                );
                // Riproverà al prossimo evento: un disco pieno o un permesso
                // mancante non devono uccidere la scansione.
                return;
            }
        }
    }
    let line = ev.to_line();
    if let Some(f) = st.file.as_mut() {
        if let Err(e) = writeln!(f, "{line}") {
            crate::be!("[BLUESNIFF] rawlog: scrittura fallita: {e}");
            st.file = None; // riapre al prossimo evento
            return;
        }
        st.written += line.len() as u64 + 1;
    }
    if st.written >= ROTATE_BYTES {
        rotate(st);
    }
}

/// Chiusura del file attivo + rinomina con timestamp, poi riapre uno nuovo.
fn rotate(st: &mut WriterState) {
    st.file = None; // chiude (Drop flusha)
    let stamp = crate::logging::utc_now_rfc3339()
        .replace(['-', ':'], "")
        .replace('T', "-")
        .trim_end_matches('Z')
        .to_string();
    let mut rotated = st.path.with_extension(format!("jsonl.{stamp}"));
    // Anti-collisione: due rotazioni nello stesso secondo.
    while rotated.exists() {
        rotated = rotated.with_extension(format!("{stamp}.{}", st.rotations + 1));
        st.rotations += 1;
    }
    if std::fs::rename(&st.path, &rotated).is_ok() {
        st.written = 0;
        apply_retention();
    }
}

/// Cancella i file ruotati più vecchi di `RETENTION_DAYS` giorni (mtime).
/// Non tocca mai il file attivo. Best-effort: un fallimento viene ignorato.
pub fn apply_retention() {
    let dir = match exe_dir().read_dir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(RETENTION_DAYS * 86_400);
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("raw_log.") || !name.contains(".jsonl.") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if modified < cutoff {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Percorsi di tutti i file di log che intersecano l'intervallo: attivo
/// prima, poi i ruotati in ordine cronologico.
fn log_files() -> Vec<PathBuf> {
    log_files_with(&exe_dir(), active_path())
}

/// Come [`log_files`], ma su una directory esplicita (per il report e i test).
fn log_files_in(dir: &Path) -> Vec<PathBuf> {
    log_files_with(dir, dir.join("raw_log.jsonl"))
}

/// Percorsi dei log con il file attivo indicato esplicitamente.
///
/// Il file attivo non e' sempre `dir/raw_log.jsonl`: a runtime lo decide
/// `rawlog::init()`, che puo` averlo spostato (ed e' cosi' nei test, che lo
/// puntano su un temporaneo). Per questo la versione normale passa
/// `active_path()` e solo quella con `dir` usa il join.
fn log_files_with(dir: &Path, active: PathBuf) -> Vec<PathBuf> {
    let mut files = vec![active];
    if let Ok(entries) = dir.read_dir() {
        let mut rotated: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let n = p
                    .file_name()
                    .map(|x| x.to_string_lossy().to_string())
                    .unwrap_or_default();
                n.starts_with("raw_log.") && n.contains(".jsonl.")
            })
            .collect();
        rotated.sort();
        files.extend(rotated);
    }
    files
}

/// Tutte le righe di log con timestamp nell'intervallo `[from_ms, to_ms]`,
/// in ordine di file (cronologico: i nomi dei ruotati ordinano per data).
pub fn iter_lines_in_range(from_ms: i64, to_ms: i64) -> Vec<String> {
    // Non delega a `iter_lines_in_dir`: li' il file attivo e` per convenzione
    // `dir/raw_log.jsonl`, mentre qui e` quello che `init()` ha deciso, che
    // puo` essere un'altra cartella (ed e' cosi' nei test).
    lines_in(&log_files(), from_ms, to_ms)
}

/// Come [`iter_lines_in_range`], ma su una directory esplicita.
///
/// Il report usa questa forma perche' `presenze.csv` non porta il campo
/// `hint` (da li non si ricava se un annuncio e' un localizzatore), quindi
/// per i tracker deve leggere il `raw_log` — e senza un percorso iniettabile
/// un test scriverebbe nel log vero accanto all'eseguibile. Il resto del
/// progetto continua a usare la forma senza `dir`.
pub fn iter_lines_in_dir(dir: &Path, from_ms: i64, to_ms: i64) -> Vec<String> {
    lines_in(&log_files_in(dir), from_ms, to_ms)
}

/// Lettura delle righe da una lista di file gia' nota: la parte comune delle
/// due varianti pubbliche, che differiscono solo da dove arrivano i path.
fn lines_in(files: &[PathBuf], from_ms: i64, to_ms: i64) -> Vec<String> {
    let mut out = Vec::new();
    for path in files {
        let Ok(f) = std::fs::File::open(path) else {
            continue;
        };
        for line in BufReader::new(f).lines().map_while(|l| l.ok()) {
            let Some(ts_str) = line_ts(&line) else {
                continue;
            };
            let Some(ts) = crate::logging::parse_rfc3339_millis(ts_str) else {
                continue;
            };
            if ts >= from_ms && ts <= to_ms {
                out.push(line);
            }
        }
    }
    out
}

/// Tetto di byte scansionati per una query: la coda recente del log, non tutto
/// il file. Serve a tenere la richiesta sotto controllo quando il file da 64 MB
/// viene filtrato per un device che ha trasmesso tanto tempo fa.
const QUERY_BYTE_BUDGET: u64 = 32 * 1024 * 1024;

/// Pacchetti che corrispondono a una ricerca, dall'intervallo indicato.
///
/// `needle` viene cercato (minuscolo, senza distinzione di maiuscole) in tutta
/// la riga, quindi matcha MAC, nome, vendor ed esadecimale. Restituisce gli
/// ultimi `limit` risultati in ordine cronologico.
///
/// Restituisce gli ultimi `limit` risultati in ordine cronologico: la coda
/// "calda" è quella che interessa, e il limite di byte impedisce di scansionare
/// un file da 64 MB a ogni refresh.
pub fn query(from_ms: i64, to_ms: i64, needle: Option<&str>, limit: usize) -> Vec<String> {
    let needle = needle
        .map(|n| n.trim().to_lowercase())
        .filter(|n| !n.is_empty());
    let mut out: Vec<String> = Vec::new();
    let mut budget = QUERY_BYTE_BUDGET;

    for path in log_files().into_iter().rev() {
        if budget == 0 {
            break;
        }
        let Ok(f) = std::fs::File::open(&path) else {
            continue;
        };
        let Ok(meta) = f.metadata() else { continue };
        let mut reader = BufReader::new(f);
        // Se il file supera il budget, leggiamo solo la coda.
        let start = meta.len().saturating_sub(budget);
        if start > 0 {
            use std::io::Seek;
            if reader.seek(std::io::SeekFrom::Start(start)).is_err() {
                continue;
            }
            // Scarta la prima riga, quasi certamente parziale.
            let mut junk = String::new();
            let _ = reader.read_line(&mut junk);
        }

        let mut matched: Vec<String> = Vec::new();
        for line in reader.lines().map_while(|l| l.ok()) {
            budget = budget.saturating_sub(line.len() as u64 + 1);
            let Some(ts_str) = line_ts(&line) else {
                continue;
            };
            let Some(ts) = crate::logging::parse_rfc3339_millis(ts_str) else {
                continue;
            };
            if ts < from_ms || ts > to_ms {
                continue;
            }
            if let Some(n) = &needle {
                if !line.to_lowercase().contains(n) {
                    continue;
                }
            }
            matched.push(line);
        }
        // I file ruotati sono più vecchi: appendiamo in coda a quelli letti
        // prima (che sono i più recenti) e teniamo solo gli ultimi `limit`.
        out = matched.into_iter().chain(out).collect();
    }

    let skip = out.len().saturating_sub(limit);
    out.into_iter().skip(skip).collect()
}

/// Formato dell'export.
#[derive(Clone, Copy, PartialEq)]
pub enum ExportFormat {
    Csv,
    Jsonl,
    Pcapng,
}

/// Esporta gli eventi nell'intervallo `[from_ms, to_ms]` (inclusi agli
/// estremi). Scorre il file attivo e i ruotati che intersecano l'intervallo.
/// La stringa di ritorno è già pronta per la risposta HTTP; `truncated`
/// dice se è stato raggiunto il tetto di righe.
pub fn export(from_ms: i64, to_ms: i64, format: ExportFormat) -> (Vec<u8>, bool) {
    let mut files = vec![active_path()];
    if let Ok(entries) = exe_dir().read_dir() {
        let mut rotated: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let n = p
                    .file_name()
                    .map(|x| x.to_string_lossy().to_string())
                    .unwrap_or_default();
                n.starts_with("raw_log.") && n.contains(".jsonl.")
            })
            .collect();
        rotated.sort();
        files.extend(rotated);
    }

    let mut out = String::new();
    let mut count = 0usize;
    let mut truncated = false;

    if matches!(format, ExportFormat::Csv) {
        out.push_str(RAW_CSV_HEADER);
        out.push('\n');
    }

    if matches!(format, ExportFormat::Pcapng) {
        return (build_pcapng(from_ms, to_ms), false);
    }

    for path in files {
        if count >= EXPORT_ROW_CAP {
            truncated = true;
            break;
        }
        let Ok(f) = std::fs::File::open(&path) else {
            continue;
        };
        for line in BufReader::new(f).lines().map_while(|l| l.ok()) {
            if count >= EXPORT_ROW_CAP {
                truncated = true;
                break;
            }
            // Filtro leggero sul prefisso senza fare il parse JSON completo
            // di ogni riga: il campo "ts" è sempre il primo.
            let Some(ts_str) = line_ts(&line) else {
                continue;
            };
            let Some(ts) = crate::logging::parse_rfc3339_millis(ts_str) else {
                continue;
            };
            if ts < from_ms || ts > to_ms {
                continue;
            }
            count += 1;
            match format {
                ExportFormat::Jsonl => out.push_str(&line),
                // Pcapng gestito sopra (restituisce byte, non testo).
                ExportFormat::Csv => {
                    let csv = line_to_csv(&line);
                    out.push_str(&csv);
                }
                ExportFormat::Pcapng => unreachable!("gestito prima del loop"),
            }
            out.push('\n');
        }
    }
    (out.into_bytes(), truncated)
}

// ---------------------------------------------------------------------------
// Export PCAPNG: cattura apribile con Wireshark/tshark senza plugin.
// ---------------------------------------------------------------------------

/// Linktype per Bluetooth LE Link Layer (usato da Wireshark e dal formato
/// di cattura dell'nRF Sniffer): 251 = BLUETOOTH_LE_LL.
const LINKTYPE_BLE_LL: u16 = 251;

/// Header del file pcapng: Block Type 0x0A0D0D0A, byte-order magic 0x1A2B3C4D.
const PCAPNG_SHB: u32 = 0x0A0D_0D0A;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_EPB: u32 = 0x0000_0006;

/// Scrive un blocco pcapng: tipo, lunghezza totale, payload con padding a
/// 4 byte, lunghezza finale.
fn write_block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let len = (12 + body.len() as u32 + 3) & !3; // 8 (hdr) + body + 4 (len)
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    // Padding a 4 byte (tipicamente 1 byte di zero).
    for _ in 0..(len as usize - 12 - body.len()) {
        out.push(0);
    }
    out.extend_from_slice(&len.to_le_bytes());
}

/// Opzione pcapng: codice (u16), lunghezza (u16), valore con padding a 4.
fn write_opt(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    for _ in 0..((4 - value.len() % 4) % 4) {
        out.push(0);
    }
}

/// Access address (32 bit, little-endian) che Wireshark riconosce come canale
/// pubblicitario: `packet-bluetooth.h` lo confronta con
/// `ACCESS_ADDRESS_ADVERTISING` (0x8e89bed6) per scegliere il dissector degli
/// annunci. I 16 bit bassi non sono l'AA della specifica (0x8e89) ma il
/// valore con cui Wireshark identifica il PDU: va usato cosi' com'e'.
const AA_ADVERTISING: u32 = 0x8e89_bed6;

/// Traduce l'etichetta `adv_type` del log nel codice PDU pubblicitario del
/// Bluetooth Core 6.0 Vol 6 Part B sezione 2.3 (Advertising PDU type).
fn adv_pdu_type_code(adv_type: &str, scan_response: bool) -> u8 {
    if scan_response || adv_type == "scan_response" {
        0x04 // SCAN_RSP
    } else {
        match adv_type {
            "connectable" => 0x00,          // ADV_IND
            "connectable_directed" => 0x01, // ADV_DIRECT_IND
            "scannable" => 0x06,            // ADV_SCAN_IND
            "extended" => 0x07,             // ADV_EXT_IND
            _ => 0x02,                      // ADV_NONCONN_IND
        }
    }
}

/// Costruisce la PDU pubblicitaria completa (senza preambolo):
/// `AccessAddress | Header | Length | AdvA | AD data | CRC`.
/// Il CRC e' azzerato perche' il controller non ce lo consegna: Wireshark lo
/// segnala come "Incorrect CRC", il resto viene dissertato correttamente.
fn ble_advertising_pdu(
    mac: &str,
    addr_type: &str,
    adv_type: &str,
    scan_response: bool,
    ad: &[u8],
) -> Vec<u8> {
    let addr = mac_to_le_bytes(mac);
    let payload_len = addr.len() + ad.len();
    let header = adv_pdu_type_code(adv_type, scan_response)
        | if addr_type == "random" { 0x40 } else { 0x00 }; // TxAdd
    let mut pdu = Vec::with_capacity(4 + 2 + payload_len + 3);
    pdu.extend_from_slice(&AA_ADVERTISING.to_le_bytes());
    pdu.push(header);
    pdu.push((payload_len + 2) as u8); // Length: header + length + payload
    pdu.extend_from_slice(&addr);
    pdu.extend_from_slice(ad);
    pdu.extend_from_slice(&[0x00, 0x00, 0x00]); // CRC non disponibile
    pdu
}

/// "AA:BB:CC:DD:EE:FF" -> 6 byte little-endian, l'ordine che il controller
/// mette in onda (primo byte = LSB del MAC stampato).
fn mac_to_le_bytes(mac: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    let hex: Vec<u8> = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_digit(16).unwrap_or(0) as u8)
        .collect();
    for i in 0..6 {
        let hi = hex.get(i * 2).copied().unwrap_or(0);
        let lo = hex.get(i * 2 + 1).copied().unwrap_or(0);
        out[5 - i] = (hi << 4) | lo;
    }
    out
}

/// Costruisce un file pcapng (byte) dagli eventi del log nell'intervallo.
///
/// Ogni pacchetto diventa un Enhanced Packet Block con una PDU pubblicitaria
/// LL completa (access address, header, AdvA, record AD, CRC), quindi
/// Wireshark/tshark la disserta nativamente: indirizzo, Flags, Manufacturer
/// Specific con Company ID, UUID, nome. RSSI e canale non hanno un campo
/// nel linktype 251, quindi vi finiscono come commento del pacchetto.
fn build_pcapng(from_ms: i64, to_ms: i64) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    // Section Header Block con un paio di opzioni descrittive.
    let mut shb: Vec<u8> = Vec::new();
    shb.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes()); // major
    shb.extend_from_slice(&0u16.to_le_bytes()); // minor
    shb.extend_from_slice(&(-1i64).to_le_bytes()); // section length: sconosciuto
    write_opt(&mut shb, 2, b"bluesniff"); // shb_hardware
    write_opt(&mut shb, 3, b"bluesniff rawlog"); // shb_os
    write_opt(&mut shb, 4, &1u64.to_le_bytes()); // shb_userappl
    write_opt(&mut shb, 0, &[]); // opt_endofopt
    write_block(&mut out, PCAPNG_SHB, &shb);

    // Interface Description Block: linktype 251 (BLE LL), snaplen 0.
    let mut idb: Vec<u8> = Vec::new();
    idb.extend_from_slice(&LINKTYPE_BLE_LL.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes()); // reserved
    idb.extend_from_slice(&0u32.to_le_bytes()); // snaplen
    let name = b"bluesniff-rawlog";
    write_opt(&mut idb, 2, name); // if_name
    write_opt(&mut idb, 9, &1u32.to_le_bytes()); // if_tsresol: 1 = microsecondi
    write_opt(&mut idb, 0, &[]);
    write_block(&mut out, BLOCK_IDB, &idb);

    for line in iter_lines_in_range(from_ms, to_ms) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let ts_ms = v
            .get("ts")
            .and_then(|x| x.as_str())
            .and_then(crate::logging::parse_rfc3339_millis)
            .unwrap_or(0);
        let rssi = v.get("rssi").and_then(|x| x.as_i64()).unwrap_or(0);
        let hex = v.get("hex").and_then(|x| x.as_str()).unwrap_or("");
        let mac = v.get("mac").and_then(|x| x.as_str()).unwrap_or("");
        let addr_type = v.get("addr_type").and_then(|x| x.as_str()).unwrap_or("");
        let adv_type = v.get("adv_type").and_then(|x| x.as_str()).unwrap_or("");
        let scan_rsp = v
            .get("scan_response")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);

        let ad = hex_decode(hex).unwrap_or_default();
        let pkt = ble_advertising_pdu(mac, addr_type, adv_type, scan_rsp, &ad);

        // Enhanced Packet Block: interface 0, timestamp (µs), caplen, len.
        let mut epb: Vec<u8> = Vec::new();
        epb.extend_from_slice(&0u32.to_le_bytes()); // interface id
        let ts_us = (ts_ms.max(0) as u64) * 1000;
        epb.extend_from_slice(&((ts_us >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(ts_us as u32).to_le_bytes());
        epb.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        epb.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        epb.extend_from_slice(&pkt);
        // Padding del pacchetto a 4 byte secondo lo standard pcapng.
        epb.extend(std::iter::repeat_n(0u8, (4 - pkt.len() % 4) % 4));
        // Il linktype 251 non ha un campo RSSI: lo portiamo come commento.
        let mut comment = format!(
            "rssi={} dBm ch=37 addr={} adv={}{}",
            rssi,
            addr_type,
            adv_type,
            if scan_rsp { " (scan response)" } else { "" }
        );
        if let Some(name) = v.get("name").and_then(|x| x.as_str()) {
            comment.push_str(&format!(" name={name}"));
        }
        write_opt(&mut epb, 1, comment.as_bytes()); // epb_comment
        epb.extend_from_slice(&0u32.to_le_bytes()); // opt_endofopt
        write_block(&mut out, BLOCK_EPB, &epb);
    }

    out
}

/// Da esadecimale (stringa di byte) a vettore di byte. Le coppie non valide
/// vengono saltate: meglio un pacchetto incompleto che nessuno.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16);
        let lo = (bytes[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
            _ => return Some(out),
        }
        i += 2;
    }
    Some(out)
}

pub const RAW_CSV_HEADER: &str = "ts;mac;addr_type;adv_type;rssi;connectable;scan_response;name;vendor;hint;model_id;tx_power;hex;decode";

/// Statistiche aggregate per dispositivo, calcolate sulle righe del log
/// nell'intervallo indicato. È la vista che serve a chi studia un device:
/// quante volte trasmette, con che RSSI, con quanti payload diversi.
#[derive(Clone, Debug, Default)]
pub struct DeviceStats {
    pub mac: String,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub hint: Option<String>,
    pub addr_type: String,
    pub packets: usize,
    pub first_ms: i64,
    pub last_ms: i64,
    pub rssi_min: i16,
    pub rssi_max: i16,
    pub rssi_sum: i64,
    /// Payload distinti visti (hash dell'esadecimale): più di uno suggerisce
    /// un beacon che cambia contenuto (es. contatore, rotazione di stato).
    pub distinct_payloads: usize,
    /// Tipo di annuncio più frequente.
    pub adv_type: String,
    /// Intervallo mediano e P95 tra pacchetti consecutivi (ms): la cadenza
    /// di trasmissione, la firma di un tracker.
    pub interval_median_ms: Option<i64>,
    pub interval_p95_ms: Option<i64>,
}

impl DeviceStats {
    fn rssi_avg(&self) -> i16 {
        if self.packets == 0 {
            return 0;
        }
        (self.rssi_sum / self.packets as i64) as i16
    }
}

/// Aggrega gli eventi del log nell'intervallo `[from_ms, to_ms]` per
/// dispositivo. Deduplica il file attivo e i ruotati come `export`.
pub fn stats(from_ms: i64, to_ms: i64) -> Vec<DeviceStats> {
    stats_of_lines(&iter_lines_in_range(from_ms, to_ms))
}

/// Aggregazione pura sulle righe: separa dalla lettura dei file, così è
/// testabile senza toccare lo stato globale del writer.
fn stats_of_lines(lines: &[String]) -> Vec<DeviceStats> {
    use std::collections::HashMap;

    struct Acc {
        s: DeviceStats,
        payloads: Vec<String>,
        times: Vec<i64>,
        adv_counts: HashMap<String, usize>,
    }

    let mut accs: HashMap<String, Acc> = HashMap::new();
    for line in lines {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(mac) = v.get("mac").and_then(|x| x.as_str()).map(|s| s.to_string()) else {
            continue;
        };
        let ts = v
            .get("ts")
            .and_then(|x| x.as_str())
            .and_then(crate::logging::parse_rfc3339_millis)
            .unwrap_or(0);
        let hex = v
            .get("hex")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let adv = v
            .get("adv_type")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let rssi = v.get("rssi").and_then(|x| x.as_i64()).unwrap_or(0) as i16;

        let acc = accs.entry(mac.clone()).or_insert_with(|| Acc {
            s: DeviceStats {
                mac: mac.clone(),
                addr_type: v
                    .get("addr_type")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                first_ms: ts,
                last_ms: ts,
                rssi_min: rssi,
                rssi_max: rssi,
                rssi_sum: 0,
                ..Default::default()
            },
            payloads: Vec::new(),
            times: Vec::new(),
            adv_counts: HashMap::new(),
        });

        // I campi descrittivi si riempiono alla prima occorrenza utile: i
        // pacchetti successivi possono non portarli (es. la scan response).
        if acc.s.name.is_none() {
            acc.s.name = v
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
        }
        if acc.s.vendor.is_none() {
            acc.s.vendor = v
                .get("vendor")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
        }
        if acc.s.hint.is_none() {
            acc.s.hint = v
                .get("hint")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
        }
        if ts < acc.s.first_ms {
            acc.s.first_ms = ts;
        }
        if ts > acc.s.last_ms {
            acc.s.last_ms = ts;
        }
        if rssi < acc.s.rssi_min {
            acc.s.rssi_min = rssi;
        }
        if rssi > acc.s.rssi_max {
            acc.s.rssi_max = rssi;
        }
        acc.s.rssi_sum += rssi as i64;
        acc.s.packets += 1;
        if !hex.is_empty() && !acc.payloads.contains(&hex) {
            acc.payloads.push(hex);
        }
        *acc.adv_counts.entry(adv.clone()).or_insert(0) += 1;
        acc.times.push(ts);
    }

    let mut out: Vec<DeviceStats> = accs
        .into_values()
        .map(|mut acc| {
            acc.s.distinct_payloads = acc.payloads.len();
            acc.s.adv_type = acc
                .adv_counts
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .map(|(t, _)| t)
                .unwrap_or_default();
            // Intervalli tra pacchetti consecutivi: mediana e P95.
            acc.times.sort_unstable();
            let gaps: Vec<i64> = acc.times.windows(2).map(|w| (w[1] - w[0]).max(0)).collect();
            if !gaps.is_empty() {
                let mut g = gaps.clone();
                g.sort_unstable();
                // Mediana vera: con un numero pari di campioni è la media dei
                // due centrali (non il secondo, che falserebbe la cadenza).
                let n = g.len();
                acc.s.interval_median_ms = Some(if n.is_multiple_of(2) {
                    (g[n / 2 - 1] + g[n / 2]) / 2
                } else {
                    g[n / 2]
                });
                // P95: indice arrotondato in alto sul vettore ordinato.
                let idx = ((n as f64) * 0.95).ceil() as usize;
                acc.s.interval_p95_ms = Some(g[idx.clamp(1, n) - 1]);
            }
            acc.s
        })
        .collect();
    // Più attivi prima: è l'ordine che serve per capire chi sta parlando.
    out.sort_by(|a, b| b.packets.cmp(&a.packets).then(a.mac.cmp(&b.mac)));
    out
}

/// Istanze JSON delle statistiche, ordinate come `stats`.
pub fn stats_json(from_ms: i64, to_ms: i64) -> Vec<serde_json::Value> {
    stats(from_ms, to_ms)
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "mac": s.mac,
                "name": s.name,
                "vendor": s.vendor,
                "hint": s.hint,
                "addr_type": s.addr_type,
                "packets": s.packets,
                "first": crate::logging::rfc3339_millis(s.first_ms),
                "last": crate::logging::rfc3339_millis(s.last_ms),
                "rssi_min": s.rssi_min,
                "rssi_max": s.rssi_max,
                "rssi_avg": s.rssi_avg(),
                "distinct_payloads": s.distinct_payloads,
                "adv_type": s.adv_type,
                "interval_median_ms": s.interval_median_ms,
                "interval_p95_ms": s.interval_p95_ms,
            })
        })
        .collect()
}

/// Estrae il valore del campo `"ts"` senza fare il parse dell'intera riga:
/// le prime ~40 byte bastano (`{"ts":"2026-09-29T07:15:27.123Z",`).
fn line_ts(line: &str) -> Option<&str> {
    // serde_json ordina le chiavi alfabeticamente: `ts` può stare anche a
    // metà riga (con decode lunghe supera i 200 byte). Ricerca su tutta la
    // riga: `str::find` è vettorizzata e il costo è irrilevante rispetto
    // alla scrittura su disco.
    let pos = line.find("\"ts\":\"")?;
    let rest = &line[pos + 6..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Converte una riga JSONL in una riga CSV (separatore `;` come presenze.csv,
/// con escape per i campi che lo contengono).
fn line_to_csv(line: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        // Riga corrotta: meglio una riga CSV con l'hex decodificabile a mano
        // che perderla in silenzio.
        return format!(";;;;;;corrupt;;;;;;;;;;;;;;;;;\"{}\"", escape_csv(line));
    };
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let n = |k: &str| {
        v.get(k)
            .map(|x| match x {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };
    let decode = v
        .get("decode")
        .and_then(|d| d.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_default();
    [
        s("ts"),
        s("mac"),
        s("addr_type"),
        s("adv_type"),
        n("rssi"),
        n("connectable"),
        n("scan_response"),
        s("name"),
        s("vendor"),
        s("hint"),
        n("model_id"),
        n("tx_power"),
        s("hex"),
        decode,
    ]
    .iter()
    .map(|f| escape_csv(f))
    .collect::<Vec<_>>()
    .join(";")
}

fn escape_csv(s: &str) -> String {
    if s.contains(';') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Decodifica dei record AD.
// ---------------------------------------------------------------------------

/// Decodifica i record AD in stringhe leggibili, una per sezione. Il formato
/// hex resta la fonte di verità: la decodifica è un aiuto alla lettura.
pub fn decode_ad_sections(sections: &[(u8, Vec<u8>)]) -> Vec<String> {
    let mut out = Vec::new();
    for (dt, data) in sections {
        let label = match dt {
            0x01 => {
                let flags = data.first().copied().unwrap_or(0);
                let mut f: Vec<&str> = Vec::new();
                if flags & 0x01 != 0 {
                    f.push("LE Limited Discoverable");
                }
                if flags & 0x02 != 0 {
                    f.push("LE General Discoverable");
                }
                if flags & 0x04 != 0 {
                    f.push("BR/EDR Not Supported");
                }
                if flags & 0x08 != 0 {
                    f.push("Simultaneous LE+BR/EDR");
                }
                format!("Flags (0x01): {} [{flags:02x}]", f.join(", "))
            }
            0x02 | 0x03 => {
                let mut uuids: Vec<String> = Vec::new();
                for chunk in data.chunks(2) {
                    if chunk.len() == 2 {
                        uuids.push(format!("0x{:02x}{:02x}", chunk[1], chunk[0]));
                    }
                }
                format!(
                    "{} (0x{:02x}): {}",
                    if *dt == 0x02 {
                        "UUID16 incompleti"
                    } else {
                        "UUID16 completi"
                    },
                    dt,
                    uuids.join(", ")
                )
            }
            0x06 | 0x07 => format!("UUID128 (0x{dt:02x}): {}", uuid_from_bytes(data)),
            0x08 | 0x09 => format!(
                "{} (0x{dt:02x}): \"{}\"",
                if *dt == 0x08 {
                    "Nome corto"
                } else {
                    "Nome completo"
                },
                String::from_utf8_lossy(data)
            ),
            0x0A => format!(
                "Tx Power (0x0A): {} dBm",
                data.first().map(|&b| b as i8).unwrap_or(0)
            ),
            0x16 => {
                if data.len() >= 2 {
                    let uuid = format!("0x{:02x}{:02x}", data[1], data[0]);
                    let payload = &data[2..];
                    match uuid.to_lowercase().as_str() {
                        // Samsung SmartTag/FMM: service data 0xFD5A con
                        // prefisso 0x10-mask, contiene stato e livello
                        // batteria del tag.
                        "0xfd5a" if payload.first().is_some_and(|&b| b & 0xF8 == 0x10) => {
                            let batt = payload.get(1).copied().unwrap_or(0);
                            let status = payload.get(2).copied().unwrap_or(0);
                            format!("Samsung SmartTag/FMM (0x16 0xfd5a): batt={batt}% status=0x{status:02x} raw={}", hex_str(payload))
                        }
                        "0xfeaa" => decode_eddystone_or_fmdn(payload),
                        "0xfe2c" if payload.len() >= 3 => {
                            let model = ((payload[0] as u32) << 16)
                                | ((payload[1] as u32) << 8)
                                | payload[2] as u32;
                            let mut s = format!(
                                "Service Data Fast Pair (0x16 0xfe2c): model_id=0x{model:06X}"
                            );
                            if let Some(n) = fastpair_model_name(model) {
                                s.push_str(&format!(" ({n})"));
                            }
                            s
                        }
                        "0xfe33" => format!("Chipolo (0x16 0xfe33): {}", hex_str(payload)),
                        "0xfa25" => format!("Pebblebee (0x16 0xfa25): {}", hex_str(payload)),
                        "0xfe91" => format!("Samsung tag (0x16 0xfe91): {}", hex_str(payload)),
                        _ => format!("Service Data (0x16) {uuid}: {}", hex_str(payload)),
                    }
                } else {
                    format!("Service Data (0x16): {}", hex_str(data))
                }
            }
            0x19 => {
                let v = if data.len() >= 2 {
                    u16::from_le_bytes([data[0], data[1]])
                } else {
                    0
                };
                format!("Appearance (0x19): {v:#06x}")
            }
            0xFF => {
                if data.len() >= 2 {
                    let id = u16::from_le_bytes([data[0], data[1]]);
                    let vendor = crate::bluetooth::company_name(id).unwrap_or("sconosciuto");
                    let payload = &data[2..];
                    // Casi specifici che conosciamo bene.
                    if id == 0x004C
                        && payload.first() == Some(&0x02)
                        && payload.get(1) == Some(&0x15)
                        && payload.len() >= 23
                    {
                        let uuid = uuid_from_bytes(&payload[2..18]);
                        let major = u16::from_be_bytes([payload[18], payload[19]]);
                        let minor = u16::from_be_bytes([payload[20], payload[21]]);
                        let tx = payload[22] as i8;
                        format!("iBeacon (0xFF Apple): uuid={uuid} major={major} minor={minor} tx={tx} dBm")
                    } else if let Some(continuity) = decode_apple_continuity(payload) {
                        continuity
                    } else if id == 0x00E0 && payload.len() >= 3 {
                        // Google Fast Pair: i primi 3 byte sono il Model ID,
                        // che identifica il modello esatto del dispositivo.
                        let model = ((payload[0] as u32) << 16)
                            | ((payload[1] as u32) << 8)
                            | payload[2] as u32;
                        let mut s = format!("Fast Pair (0xFF Google): model_id=0x{model:06X}");
                        if let Some(n) = fastpair_model_name(model) {
                            s.push_str(&format!(" ({n})"));
                        }
                        s
                    } else if id == 0x0075 && payload.len() >= 3 && payload[0] == 0x42 {
                        // Samsung Easy Setup (0x42): contiene l'hint code
                        // della procedura di pairing.
                        format!(
                            "Samsung Easy Setup (0xFF): type=0x42 hint=0x{:02x}",
                            payload[1]
                        )
                    } else {
                        format!(
                            "Manufacturer (0xFF) {} [{id:04x}]: {}",
                            vendor,
                            hex_str(payload)
                        )
                    }
                } else {
                    format!("Manufacturer (0xFF): {}", hex_str(data))
                }
            }
            _ => format!("AD type 0x{dt:02x}: {}", hex_str(data)),
        };
        out.push(label);
    }
    out
}

/// Sottotipi Apple Continuity (manufacturer 0x004C). I payload sono
/// documentati da AirGuard/OpenHaystack e dai progetti di ricerca pubblici
/// (knob: il primo byte del payload seleziona la famiglia).
fn apple_continuity_kind(t: u8) -> Option<&'static str> {
    Some(match t {
        0x01 => "Nearby Info",
        0x02 => "Nearby Action / AirDrop",
        0x03 => "UltraSonic (AirPods)",
        0x05 => "AirDrop (reale)",
        0x07 => "AirPods (popup)",
        0x09 => "AirPlay",
        0x0A => "AirPlay (target)",
        0x0B => "MagicSwitch",
        0x0C => "Handoff",
        0x0D => "Tethering Target",
        0x0E => "Tethering Source",
        0x0F => "Nearby Action (altro)",
        0x10 => "Nearby (opp2017 / BLE proximity)",
        0x12 => "Find My (payload rete non connesso)",
        0x14 => "Find My (payload connesso)",
        0x17 => "Watch / HomeKit",
        0x19 => "Phone (iCloud)",
        _ => return None,
    })
}

/// Decodifica il payload Apple Continuity (0x004C, senza prefisso company id).
/// Ritorna None se non e' un tipo Continuity noto, cosi' il chiamante puo'
/// ripiegare sul generico.
fn decode_apple_continuity(payload: &[u8]) -> Option<String> {
    let t = *payload.first()?;
    let kind = apple_continuity_kind(t)?;
    let mut extra: Vec<String> = Vec::new();
    if payload.len() >= 2 {
        extra.push(format!("flags=0x{:02x}", payload[1]));
    }
    if payload.len() >= 4 {
        // Byte 2-3: lunghezza del resto del payload (continuity TLV-like).
        extra.push(format!(
            "len={}",
            u16::from_le_bytes([payload[2], payload[3]])
        ));
    }
    if payload.len() >= 5 {
        // Ultimo byte dei tipi con batteria: 0xFF = sconosciuta, altrimenti
        // percentuale (stessa codifica di Nearby Info).
        let b = payload[payload.len() - 1];
        if b != 0xFF && b != 0x00 {
            extra.push(format!("batt={}%", b.min(100)));
        }
    }
    Some(format!(
        "Apple Continuity (0xFF Apple): {kind} [{}{}]",
        t,
        if extra.is_empty() {
            String::new()
        } else {
            format!(" — {}", extra.join(", "))
        }
    ))
}

/// Nome leggibile del Model ID Fast Pair, dal DB `fastpair_models.txt`
/// accanto all'eseguibile (formato `0xXXXXXX: Nome`).
fn fastpair_model_name(model: u32) -> Option<String> {
    let path = exe_dir().join("fastpair_models.txt");
    let text = std::fs::read_to_string(path).ok()?;
    let needle = format!("{model:06X}");
    for line in text.lines() {
        let line = line.trim();
        let Some((id, name)) = line.split_once(':') else {
            continue;
        };
        if id
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .eq_ignore_ascii_case(&needle)
        {
            let n = name.trim();
            if !n.is_empty() {
                return Some(n.to_string());
            }
        }
    }
    None
}

/// Decodifica l'URL Eddystone (0xFEAA frame 0x20): il primo byte e' lo
/// schema, poi la stringa con gli schemi piu' frequenti gia' sostituiti.
fn eddystone_url(data: &[u8]) -> String {
    let Some(&scheme) = data.first() else {
        return String::new();
    };
    let raw = String::from_utf8_lossy(&data[1..]);
    match scheme {
        0x00 => format!("http://www.{raw}"),
        0x01 => format!("https://www.{raw}"),
        0x02 => format!("http://{raw}"),
        0x03 => format!("https://{raw}"),
        _ => format!("schema=0x{scheme:02x} {raw}"),
    }
}

/// Decodifica il service data 0xFEAA: la stessa UUID serve sia Eddystone
/// (frame 0x10/0x20/0x30) sia la Find My Device Network di Google
/// (frame 0x40/0x41, con la variante anti-stalking a MAC fisso).
fn decode_eddystone_or_fmdn(payload: &[u8]) -> String {
    let Some(&frame) = payload.first() else {
        return "Eddystone/FMDN (0x16 0xfeaa): vuoto".to_string();
    };
    match frame {
        0x10 => format!(
            "Eddystone-UID (0x16 0xfeaa): tx={} dBm, rssi_cal={}, uid={}",
            payload.get(1).map(|&b| b as i8).unwrap_or(0),
            payload.get(2).map(|&b| b as i8).unwrap_or(0),
            hex_str(&payload[3..])
        ),
        0x20 => format!(
            "Eddystone-URL (0x16 0xfeaa): tx={} dBm, url={}",
            payload.get(1).map(|&b| b as i8).unwrap_or(0),
            eddystone_url(&payload[2..])
        ),
        0x30 => {
            let vbatt = payload.get(1).map(|&b| b as i8).unwrap_or(0);
            let temp = payload.get(2).map(|&b| b as i8).unwrap_or(0) as f32 / 16.0;
            let adv = u16::from_be_bytes([
                payload.get(4).copied().unwrap_or(0),
                payload.get(5).copied().unwrap_or(0),
            ]);
            format!(
                "Eddystone-TLM (0x16 0xfeaa): vbatt={vbatt} dBm, temp={temp:.1}°C, adv_cnt={adv}"
            )
        }
        0x40 | 0x41 => {
            let kind = if frame == 0x41 {
                "protezione anti-stalking (MAC fissa 24h)"
            } else {
                "normale"
            };
            format!(
                "Google Find My Device (0x16 0xfeaa frame 0x{frame:02x}, {kind}): {}",
                hex_str(&payload[1..])
            )
        }
        _ => format!("0xfeaa frame 0x{frame:02x}: {}", hex_str(&payload[1..])),
    }
}

fn uuid_from_bytes(b: &[u8]) -> String {
    if b.len() != 16 {
        return hex_str(b);
    }
    let hex: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    // Ordine little-endian dei primi 4+2+2 byte (time-low/mid/hi).
    let s = hex.join("");
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}{}{}{}{}{}{}",
        &s[6..8],
        &s[4..6],
        &s[2..4],
        &s[0..2],
        &s[10..12],
        &s[8..10],
        &s[14..16],
        &s[12..14],
        &s[16..18],
        &s[18..20],
        &s[20..22],
        &s[22..24],
        &s[24..26],
        &s[26..28],
        &s[28..30],
        &s[30..32]
    )
}

pub fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Da esadecimale a byte, con fallback su vettore vuoto: comodo per chi
/// lavora su dati dove un hex malformato non deve far fallire l'analisi.
pub fn hex_bytes(hex: &str) -> Vec<u8> {
    hex_decode(hex).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_flags_bit_per_bit() {
        // 0x06 = LE General Discoverable + BR/EDR Not Supported.
        let d = decode_ad_sections(&[(0x01, vec![0x06])]);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("LE General Discoverable"), "{}", d[0]);
        assert!(d[0].contains("BR/EDR Not Supported"), "{}", d[0]);
    }

    #[test]
    fn decode_nome_e_tx_power() {
        let d = decode_ad_sections(&[
            (0x09, b"moto g73".to_vec()),
            (0x0A, vec![0xC8]), // -56 in i8
        ]);
        assert!(d[0].contains("Nome completo"), "{}", d[0]);
        assert!(d[0].contains("moto g73"), "{}", d[0]);
        assert!(d[1].contains("-56 dBm"), "{}", d[1]);
    }

    #[test]
    fn decode_manufacturer_con_vendor() {
        // Apple (0x004C) con payload non-iBeacon.
        let d = decode_ad_sections(&[(0xFF, vec![0x4C, 0x00, 0x10, 0x05])]);
        assert!(d[0].to_lowercase().contains("apple"), "{}", d[0]);
    }

    #[test]
    fn decode_ibeacon_completo() {
        let mut payload = vec![0x4C, 0x00, 0x02, 0x15];
        payload.extend_from_slice(&[
            0xE2, 0xC5, 0x6D, 0xB5, 0xDF, 0x48, 0x2C, 0xD5, 0xA9, 0xAC, 0xA1, 0x9D, 0x4A, 0xF3,
            0x66, 0x25,
        ]);
        payload.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0xC8]);
        let d = decode_ad_sections(&[(0xFF, payload)]);
        assert!(d[0].contains("iBeacon"), "{}", d[0]);
        assert!(d[0].contains("major=4660"), "{}", d[0]);
        assert!(d[0].contains("minor=22136"), "{}", d[0]);
    }

    #[test]
    fn hex_str_e_vuoto_senza_byte() {
        assert_eq!(hex_str(&[]), "");
        assert_eq!(hex_str(&[0x02, 0x01, 0x06]), "020106");
    }

    #[test]
    fn line_ts_estrae_il_timestamp() {
        let line = r#"{"ts":"2026-09-29T07:15:27.123Z","mac":"AA:BB:CC:DD:EE:FF"}"#;
        assert_eq!(line_ts(line), Some("2026-09-29T07:15:27.123Z"));
        // serde_json ordina le chiavi: ts può non essere il primo campo.
        let sorted = r#"{"addr_type":"random","ts":"2026-09-29T07:15:27.123Z"}"#;
        assert_eq!(line_ts(sorted), Some("2026-09-29T07:15:27.123Z"));
        // Con decode lunghe, ts può cadere anche oltre i 200 byte di riga.
        let far = format!(
            "{{\"decode\":\"{}\",\"ts\":\"2026-09-29T07:15:27.123Z\"}}",
            "x".repeat(300)
        );
        assert_eq!(line_ts(&far), Some("2026-09-29T07:15:27.123Z"));
        assert_eq!(line_ts(r#"{"mac":"..."}"#), None);
    }

    #[test]
    fn escape_csv_gestisce_semicolon_e_virgolette() {
        assert_eq!(escape_csv("semplice"), "semplice");
        assert_eq!(escape_csv("a;b"), "\"a;b\"");
        // su"melo" -> "su""melo"""  (le virgolette interne raddoppiano,
        // poi tutto viene avvolto da una coppia esterna).
        assert_eq!(escape_csv("su\"melo\""), "\"su\"\"melo\"\"\"");
    }

    #[test]
    fn timestamp_epoch_ms_converte_i_tick_winrt() {
        // 2026-09-29T07:15:27.123Z in tick .NET (da 1601-01-01):
        // epoch_ms = 1_790_666_127_123 -> epoch_s*10_000_000 + 123 ms
        // + diff 1601->1970 (11_644_473_600 s).
        let epoch_ms: i64 = 1_790_666_127_123;
        let ticks = epoch_ms.div_euclid(1000) * 10_000_000
            + (epoch_ms.rem_euclid(1000)) * 10_000
            + 11_644_473_600 * 10_000_000;
        let dt = windows::Foundation::DateTime {
            UniversalTime: ticks,
        };
        // Stessa aritmetica di timestamp_epoch_ms (test immagine della funzione).
        let conv = (dt.UniversalTime - 11_644_473_600i64 * 10_000_000) / 10_000;
        assert_eq!(conv, epoch_ms);
    }

    #[test]
    fn hex_decode_da_stringa_esadecimale() {
        assert_eq!(
            hex_decode("07ff4c0012020002").unwrap(),
            vec![0x07, 0xFF, 0x4C, 0x00, 0x12, 0x02, 0x00, 0x02]
        );
        assert!(hex_decode("").is_none());
        // Coppia dispari: prende i byte completi senza panic.
        assert_eq!(hex_decode("aab").unwrap(), vec![0xAA]);
        // Carattere non esadecimale: si ferma l\u00ec, non va in panic.
        assert_eq!(hex_decode("aazz").unwrap(), vec![0xAA]);
    }

    #[test]
    fn decode_apple_continuity_riconosce_i_sottotipi() {
        // AirDrop (0x05) con flags e batteria.
        let d = decode_apple_continuity(&[0x05, 0x9A, 0x02, 0x00, 0x64]).expect("AirDrop");
        assert!(d.contains("AirDrop"), "{}", d);
        assert!(d.contains("batt=100%"), "{}", d);
        // Find My (0x12): il payload dell'AirTag reale.
        let d = decode_apple_continuity(&[0x12, 0x00, 0x02]).expect("Find My");
        assert!(d.contains("Find My"), "{}", d);
        // Tipo sconosciuto: None, il chiamante ripiega sul generico.
        assert!(decode_apple_continuity(&[0xEE, 0x00]).is_none());
    }

    #[test]
    fn decode_eddystone_url_ricostruisce_il_link() {
        assert_eq!(eddystone_url(&[0x03, b'e', b'x', b'a']), "https://exa");
        assert_eq!(eddystone_url(&[0x00, b'e', b'x', b'a']), "http://www.exa");
    }

    #[test]
    fn decode_eddystone_e_fmdn_per_frame() {
        // Eddystone-URL (frame 0x20).
        let d = decode_eddystone_or_fmdn(&[0x20, 0xC5, 0x03, b'e', b's', b'a']);
        assert!(d.contains("Eddystone-URL"), "{}", d);
        assert!(d.contains("https://esa"), "{}", d);
        // Google Find My Device anti-stalking (frame 0x41).
        let d = decode_eddystone_or_fmdn(&[0x41, 0xDE, 0xAD]);
        assert!(d.contains("anti-stalking"), "{}", d);
        // TLM: temperatura 0x1C = 28/16 = 1.75°C.
        let d = decode_eddystone_or_fmdn(&[0x30, 0xC5, 0x1C, 0x00, 0x01, 0x2C]);
        assert!(d.contains("1.8"), "{}", d);
    }

    #[test]
    fn decode_fastpair_usando_il_db_accanto_alle_eseguibile() {
        // Il ramo Fast Pair copre il model id dai primi 3 byte sia nel
        // manufacturer 0x00E0 sia nel service data 0xFE2C. Uso un model id
        // non Apple-Continuity.
        let d = decode_ad_sections(&[(0xFF, vec![0xE0, 0x00, 0x00, 0x12, 0x34, 0x56])]);
        assert!(d[0].contains("Fast Pair"), "{}", d[0]);
        assert!(d[0].contains("model_id=0x001234"), "{}", d[0]);
    }

    /// Nei test non parte `init()`, quindi `FILE_PATH` va inizializzato
    /// esplicitamente e i test che leggono il file condividono lo stesso
    /// percorso e un lock (i test girano in parallelo).
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_file_path() -> PathBuf {
        exe_dir().join("raw_log.test-fixture.jsonl")
    }

    /// Scrive le righe di test nel fixture e restituisce il guard: il file
    /// viene rimosso quando il test finisce.
    fn write_fixture(lines: &[String]) -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = test_file_path();
        let _ = FILE_PATH.set(Mutex::new(path.clone()));
        std::fs::write(&path, lines.join("\n")).unwrap();
        guard
    }

    fn remove_fixture() {
        let _ = std::fs::remove_file(test_file_path());
    }

    #[test]
    fn pcapng_ha_magic_e_blocchi_validi() {
        // Scriviamo due righe di test con orari noti.
        let _guard = write_fixture(&[
            r#"{"ts":"2026-09-29T07:00:00.000Z","mac":"AA:BB:CC:DD:EE:FF","addr_type":"random","adv_type":"non_connectable","rssi":-70,"hex":"020106","decode":["Flags"]}"#.to_string(),
            r#"{"ts":"2026-09-29T07:00:01.500Z","mac":"AA:BB:CC:DD:EE:FF","addr_type":"random","adv_type":"non_connectable","rssi":-72,"hex":"020106","decode":["Flags"]}"#.to_string(),
        ]);

        let bytes = build_pcapng(
            crate::logging::parse_rfc3339_millis("2026-09-29T07:00:00Z").unwrap(),
            crate::logging::parse_rfc3339_millis("2026-09-29T07:01:00Z").unwrap(),
        );
        remove_fixture();

        // Magic del Section Header Block in little-endian.
        assert_eq!(&bytes[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
        // Byte-order magic 0x1A2B3C4D.
        assert_eq!(&bytes[8..12], &[0x4D, 0x3C, 0x2B, 0x1A]);

        // Percorri tutta la catena di blocchi: ogni blocco deve dichiarare
        // la stessa lunghezza in testa e in coda e multipli di 4.
        let rd32 = |o: usize| -> u32 {
            u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
        };
        let mut off = 0usize;
        let mut epbs = 0usize;
        let mut saw_idb = false;
        while off + 12 <= bytes.len() {
            let btype = rd32(off);
            let blen = rd32(off + 4) as usize;
            assert!(
                blen >= 12,
                "lunghezza blocco invalida {blen} a offset {off}"
            );
            assert_eq!(blen % 4, 0, "lunghezza blocco non multipla di 4: {blen}");
            assert!(
                off + blen <= bytes.len(),
                "blocco ({btype:#x}) dichiara {blen} byte ma il file ne ha {}",
                bytes.len() - off
            );
            let trailer = rd32(off + blen - 4);
            assert_eq!(blen as u32, trailer, "lunghezza non coerente in testa/coda");
            if btype == BLOCK_IDB {
                // Linktype 251 (BLUETOOTH_LE_LL) subito dopo l'intestazione.
                assert_eq!(
                    u16::from_le_bytes([bytes[off + 8], bytes[off + 9]]),
                    LINKTYPE_BLE_LL
                );
                saw_idb = true;
            }
            if btype == BLOCK_EPB {
                epbs += 1;
                // caplen (offset 20 dal tipo) e lunghezza originaria coincidono.
                assert_eq!(rd32(off + 20), rd32(off + 24));
                let caplen = rd32(off + 20) as usize;
                let pkt = off + 28;
                // La PDU deve iniziare con l'access address pubblicitario che
                // Wireshark riconosce, poi header e lunghezza coerenti.
                assert_eq!(
                    &bytes[pkt..pkt + 4],
                    &AA_ADVERTISING.to_le_bytes(),
                    "access address non riconosciuto da Wireshark"
                );
                let pdu_len = bytes[pkt + 5] as usize;
                // caplen = 4 (AA) + 1 (header) + 1 (length) + payload + 3 (CRC)
                assert_eq!(pdu_len + 7, caplen, "Length byte e caplen non coerenti");
                // Indirizzo AdvA little-endian = AA:BB:CC:DD:EE:FF.
                assert_eq!(
                    &bytes[pkt + 6..pkt + 12],
                    &[0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]
                );
                // Header ADV_NONCONN_IND con TxAdd=1 (indirizzo random).
                assert_eq!(bytes[pkt + 4] & 0x0F, 0x02);
                assert_eq!(bytes[pkt + 4] & 0x40, 0x40);
                // I record AD sono subito dopo l'indirizzo.
                assert_eq!(&bytes[pkt + 12..pkt + 15], &[0x02, 0x01, 0x06]);
            }
            off += blen;
        }
        assert_eq!(
            off,
            bytes.len(),
            "ci sono byte finali non coperti da un blocco"
        );
        assert!(saw_idb, "manca l'Interface Description Block");
        assert_eq!(epbs, 2, "attesi 2 pacchetti, trovati {epbs}");
    }

    #[test]
    fn stats_aggregano_per_dispositivo() {
        let lines: Vec<String> = [
            r#"{"ts":"2026-09-29T07:00:00.000Z","mac":"AA:BB:CC:DD:EE:01","rssi":-70,"hex":"0201","name":"uno"}"#,
            r#"{"ts":"2026-09-29T07:00:00.500Z","mac":"AA:BB:CC:DD:EE:01","rssi":-60,"hex":"0201"}"#,
            r#"{"ts":"2026-09-29T07:00:02.000Z","mac":"AA:BB:CC:DD:EE:01","rssi":-80,"hex":"0202"}"#,
            r#"{"ts":"2026-09-29T07:00:00.100Z","mac":"AA:BB:CC:DD:EE:02","rssi":-75,"hex":"03"}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let s = stats_of_lines(&lines);

        assert_eq!(s.len(), 2, "attesi 2 dispositivi, trovati {}", s.len());
        // Il più attivo viene primo.
        let a = &s[0];
        assert_eq!(a.mac, "AA:BB:CC:DD:EE:01");
        assert_eq!(a.packets, 3);
        assert_eq!(a.rssi_min, -80);
        assert_eq!(a.rssi_max, -60);
        assert_eq!(a.rssi_avg(), -70);
        assert_eq!(a.distinct_payloads, 2);
        assert_eq!(a.name.as_deref(), Some("uno"));
        // Intervalli 500ms e 1500ms -> mediana 1000 (media dei due centrali).
        assert_eq!(a.interval_median_ms, Some(1000));
        assert_eq!(a.interval_p95_ms, Some(1500));
        // Un solo pacchetto -> nessun intervallo calcolabile.
        let b = &s[1];
        assert_eq!(b.mac, "AA:BB:CC:DD:EE:02");
        assert!(b.interval_median_ms.is_none());
    }

    #[test]
    fn query_filtra_per_mac_e_mai_oltre_la_coda() {
        // 40 eventi di 3 device distinti: solo l'ultimo device è nella coda
        // "calda", ma con il filtro lo si deve trovare lo stesso.
        let mut lines: Vec<String> = Vec::new();
        for i in 0..40 {
            let mac = if i < 20 {
                "AA:BB:CC:DD:EE:01"
            } else if i < 30 {
                "AA:BB:CC:DD:EE:02"
            } else {
                "AA:BB:CC:DD:EE:03"
            };
            let ts = format!("2026-09-29T07:00:{:02}.000Z", i % 60);
            lines.push(format!(
                "{{\"ts\":\"{ts}\",\"mac\":\"{mac}\",\"hex\":\"0201\",\"vendor\":\"Apple\"}}"
            ));
        }
        let _guard = write_fixture(&lines);

        // MAC di un device "vecchio": deve trovarlo anche se non è nella coda.
        let found = query(0, i64::MAX, Some("AA:BB:CC:DD:EE:01"), 100);
        assert_eq!(found.len(), 20, "attesi 20 pacchetti del device 01");
        assert!(found.iter().all(|l| l.contains("AA:BB:CC:DD:EE:01")));

        // Limite: con limit piccolo torna solo la coda dei risultati.
        let last = query(0, i64::MAX, Some("AA:BB:CC:DD:EE:01"), 3);
        assert_eq!(last.len(), 3);

        // Filtro per vendor: funziona anche su un campo non-MAC.
        let by_vendor = query(0, i64::MAX, Some("apple"), 100);
        assert_eq!(by_vendor.len(), 40);
        remove_fixture();
    }

    #[test]
    fn stats_ignora_righe_corrotte() {
        // Una riga non-JSON o senza MAC non deve far fallire l'aggregazione.
        let lines: Vec<String> = [
            "non sono json",
            r#"{"ts":"2026-09-29T07:00:00.000Z","rssi":-70}"#,
            r#"{"ts":"2026-09-29T07:00:00.000Z","mac":"AA:BB:CC:DD:EE:09","rssi":-70,"hex":"01"}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let s = stats_of_lines(&lines);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].mac, "AA:BB:CC:DD:EE:09");
    }

    #[test]
    fn decode_ad_sections_non_panica_su_input_strani() {
        // Dati troncati o vuoti: mai panic, sempre una voce per sezione.
        let d = decode_ad_sections(&[(0x16, vec![]), (0xFF, vec![0x4C]), (0x01, vec![])]);
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn raw_event_to_line_e_json_valido() {
        let ev = RawEvent {
            ts_ms: 1_790_666_127_123,
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            addr_type: "random",
            adv_type: "connectable",
            rssi: Some(-56),
            connectable: Some(true),
            scan_response: false,
            name: Some("test".to_string()),
            hex: "020106".to_string(),
            decode: vec!["Flags (0x01): LE General Discoverable [06]".to_string()],
            ..Default::default()
        };
        let line = ev.to_line();
        let v: serde_json::Value = serde_json::from_str(&line).expect("JSON valido");
        assert_eq!(v["ts"], "2026-09-29T07:15:27.123Z");
        assert_eq!(v["mac"], "AA:BB:CC:DD:EE:FF");
        assert_eq!(v["decode"].as_array().map(|a| a.len()), Some(1));
    }
}
