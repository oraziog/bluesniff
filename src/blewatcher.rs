//! Event-driven BLE scanning via the Windows Runtime advertisement watcher.
//!
//! Replaces btleplug's `peripherals()` for the `--listen` recorder. btleplug
//! keeps an *infinite* cache: a device seen once keeps appearing in
//! `peripherals()` forever, with its RSSI frozen at the last received packet.
//! That made devices "never disappear" and RSSI look constant (the analysis
//! of the overnight run showed 52% of fingerprints with a single RSSI value).
//!
//! The WinRT `BluetoothLEAdvertisementWatcher` instead raises an event *per
//! received packet*: a device that stops advertising simply stops generating
//! events, so each scan window reflects exactly what is on air right now.
//!
//! We also need the advertisement payload (manufacturer data, service UUIDs,
//! service data) to build the stable fingerprint and hint, exactly like the
//! old path did via btleplug's `PeripheralProperties`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows::core::GUID;
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisement, BluetoothLEAdvertisementReceivedEventArgs,
    BluetoothLEAdvertisementType, BluetoothLEAdvertisementWatcher, BluetoothLEScanningMode,
};
use windows::Devices::Radios::{Radio, RadioKind, RadioState};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::DataReader;

use crate::bluetooth::{classify, company_name, stable_fingerprint};

/// Etichetta stabile per il tipo di annuncio (log raw e UI).
fn adv_type_label(t: BluetoothLEAdvertisementType) -> &'static str {
    use BluetoothLEAdvertisementType as T;
    if t == T::ConnectableUndirected {
        "connectable"
    } else if t == T::ConnectableDirected {
        "connectable_directed"
    } else if t == T::ScannableUndirected {
        "scannable"
    } else if t == T::NonConnectableUndirected {
        "non_connectable"
    } else if t == T::ScanResponse {
        "scan_response"
    } else if t == T::Extended {
        "extended"
    } else {
        "altro"
    }
}

/// Etichetta stabile per il tipo di indirizzo (pubblico vs randomizzato):
/// è la distinzione che guida i filtri "solo randomizzati" della UI.
fn addr_type_label(t: windows::Devices::Bluetooth::BluetoothAddressType) -> &'static str {
    use windows::Devices::Bluetooth::BluetoothAddressType;
    match t {
        BluetoothAddressType::Public => "public",
        BluetoothAddressType::Random => "random",
        _ => "unspecified",
    }
}

/// Ricostruisce i record AD grezzi (`[len][type][data]`) dalle DataSections
/// WinRT: è l'hex fedele a ci@ che il controller ha messo in onda, come
/// apparirebbe in una cattura HCI. La conversione da IBuffer riusa
/// `buffer_bytes`.
fn ad_sections(adv: &BluetoothLEAdvertisement) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    if let Ok(sections) = adv.DataSections() {
        for s in sections {
            let Ok(dt) = s.DataType() else { continue };
            let Ok(buf) = s.Data() else { continue };
            out.push((dt, buffer_bytes(&buf)));
        }
    }
    out
}

/// Timestamp WinRT (DateTime .NET, tick da 1601-01-01, 100 ns) -> epoch ms.
fn timestamp_epoch_ms(t: windows::Foundation::DateTime) -> i64 {
    // Tick .NET: 10_000_000 per secondo (100 ns l'uno).
    const TICKS_PER_SEC: i64 = 10_000_000;
    const TICKS_PER_MS: i64 = 10_000;
    // 1601-01-01 -> 1970-01-01: 11_644_473_600 secondi, in TICK.
    const EPOCH_DIFF_TICKS: i64 = 11_644_473_600 * TICKS_PER_SEC;
    let ticks = t.UniversalTime;
    ((ticks - EPOCH_DIFF_TICKS) / TICKS_PER_MS).max(0)
}

/// Costruisce l'evento raw per il log per-pacchetto. Chiamato SOLO se il
/// rawlog è attivo (a log spento non si costruisce nulla: costo zero).
fn raw_event_from(
    args: &BluetoothLEAdvertisementReceivedEventArgs,
    mac: &str,
    rssi: Option<i16>,
    adv: Option<&BluetoothLEAdvertisement>,
    p: &AdvParsed,
) -> RawEvent {
    let sections = adv.map(ad_sections).unwrap_or_default();
    let hex = sections
        .iter()
        .map(|(dt, data)| {
            let mut rec = vec![data.len() as u8 + 1, *dt];
            rec.extend_from_slice(data);
            crate::rawlog::hex_str(&rec)
        })
        .collect::<Vec<_>>()
        .join("");
    let decode = crate::rawlog::decode_ad_sections(&sections);
    let addr_type = args
        .BluetoothAddressType()
        .map(addr_type_label)
        .unwrap_or("unspecified");
    let adv_type = args
        .AdvertisementType()
        .map(adv_type_label)
        .unwrap_or("altro");
    let scan_response = args.IsScanResponse().unwrap_or(false);
    RawEvent {
        ts_ms: args.Timestamp().map(timestamp_epoch_ms).unwrap_or(0),
        mac: mac.to_string(),
        addr_type,
        adv_type,
        rssi,
        connectable: p.connectable,
        scan_response,
        name: p.name.clone(),
        vendor: p.vendor.clone(),
        hint: p.hint.clone(),
        model_id: p.model_id,
        tx_power: p.tx_power,
        hex,
        decode,
    }
}

use crate::rawlog::RawEvent;

/// One unique BLE device seen in the current scan window (mirrors
/// `listen::PassiveSeen` so the CSV format stays identical).
#[derive(Clone)]
pub struct Seen {
    pub mac: String,
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub vendor: Option<String>,
    pub hint: Option<String>,
    pub fingerprint: Option<String>,
    /// Google Fast Pair Model ID (0xFE2C, first 3 bytes BE): exact product
    /// model, used for the known-vulnerability (CVE) checks.
    pub model_id: Option<u32>,
    /// Famiglia "popup/spoof"/tracker dell'annuncio (apple-popup,
    /// apple-findmy, swift-pair, samsung-easysetup, samsung-smarttag,
    /// samsung-fmm, chipolo, pebblebee, google-findmy, tile, fast-pair) —
    /// per il rilevamento spam del monitor e i filtri tracker.
    pub phantom: Option<&'static str>,
    /// Tx Power dichiarata (AD type 0x0A, dBm) quando presente: con RSSI
    /// permette di stimare la distanza (path-loss) del dispositivo. Se l'AD
    /// 0x0A manca, viene ripiegato sul measured power del payload iBeacon
    /// (0x004C) — stesso significato fisico, segnalato da `tx_ibeacon`.
    pub tx_power: Option<i8>,
    /// Vero quando `tx_power` proviene dal payload iBeacon (0x004C) invece
    /// che dall'AD type 0x0A.
    pub tx_ibeacon: bool,
    /// Connettibile (bit LE General Discoverable dei flags AD type 0x01):
    /// distingue i device che invitano a connettersi dai beacon passivi.
    pub connectable: Option<bool>,
}

/// Convert a WinRT `u64` Bluetooth address to the `AA:BB:CC:DD:EE:FF` string
/// used everywhere else (same order as btleplug's `BDAddr`: `to_be_bytes`
/// then drop the two high zero bytes).
fn mac_str(addr: u64) -> String {
    let b = addr.to_be_bytes();
    let bytes = &b[2..]; // high 16 bits are zero padding
    bytes
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format a WinRT `GUID` as a lowercase UUID string (no `Display` impl in
/// windows-core 0.61, only `Debug`), matching btleplug's UUID strings.
fn uuid_str(guid: &GUID) -> String {
    let b = guid.to_u128().to_be_bytes();
    let h: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        h[8],
        h[9],
        h[10],
        h[11],
        h[12],
        h[13],
        h[14],
        h[15]
    )
}

/// Read all bytes from an `IBuffer` (same approach as btleplug's `to_vec`).
fn buffer_bytes(buffer: &windows::Storage::Streams::IBuffer) -> Vec<u8> {
    if let Ok(reader) = DataReader::FromBuffer(buffer) {
        if let Ok(len) = reader.UnconsumedBufferLength() {
            let mut data = vec![0u8; len as usize];
            if reader.ReadBytes(&mut data).is_ok() {
                return data;
            }
        }
    }
    Vec::new()
}

/// Risultato del parsing dell'annuncio: tutto ciò che il winrt Advertisement
/// object espone, in un'unica struct (evita tuple lunghe e fragili).
#[derive(Default)]
struct AdvParsed {
    name: Option<String>,
    vendor: Option<String>,
    hint: Option<String>,
    fingerprint: Option<String>,
    model_id: Option<u32>,
    phantom: Option<&'static str>,
    tx_power: Option<i8>,
    tx_ibeacon: bool,
    connectable: Option<bool>,
}

/// Best-effort parsing completo dell'annuncio, sullo stile del `parseAdTypes`
/// del progetto ESP32-Bit-Pirate: si percorrono tutti i record AD
/// (`[len][type][data]`) ricostruendo i pixel dell'annuncio.
///
/// WinRT espone già i dati strutturati (ManufacturerData, ServiceUuids,
/// DataSections), quindi qui "parsing completo" significa:
/// - Flags AD 0x01 -> bit LE General Discoverable = "connettibile";
/// - Local name AD 0x08/0x09 come fallback del nome;
/// - Tx Power AD 0x0A -> stima distanza (path-loss) col RSSI;
/// - Service data AD 0x16/0x20/0x21 -> fingerprint/hint/Model ID;
/// - Manufacturer AD 0xFF come fonte vendor quando WinRT non la normalizza.
fn adv_fingerprint(adv: &BluetoothLEAdvertisement, name_from_local: Option<String>) -> AdvParsed {
    let mut manufacturer: HashMap<u16, Vec<u8>> = HashMap::new();
    if let Ok(mfr_data) = adv.ManufacturerData() {
        for d in mfr_data {
            if let (Ok(id), Ok(buf)) = (d.CompanyId(), d.Data()) {
                let bytes = buffer_bytes(&buf);
                if !bytes.is_empty() {
                    manufacturer.insert(id, bytes);
                }
            }
        }
    }

    // Service UUIDs -> "0000xxxx-0000-1000-8000-00805f9b34fb" strings.
    let mut services: Vec<String> = Vec::new();
    if let Ok(uuids) = adv.ServiceUuids() {
        for u in uuids {
            services.push(uuid_str(&u));
        }
    }

    // Camminata dei record AD nei data section (tipi 0x01, 0x08/0x09, 0x0A,
    // 0x16, 0x20/0x21, 0xFF...). I campi utili vengono estratti uno a uno.
    let mut service_data: HashMap<String, Vec<u8>> = HashMap::new();
    let mut tx_power: Option<i8> = None;
    let mut connectable: Option<bool> = None;
    let mut ad_name: Option<String> = None;
    if let Ok(sections) = adv.DataSections() {
        for s in sections {
            let Ok(data_type) = s.DataType() else {
                continue;
            };
            let Ok(buf) = s.Data() else { continue };
            let bytes = buffer_bytes(&buf);
            match data_type {
                0x01 => {
                    // Flags: bit 0x02 = LE General Discoverable.
                    if let Some(&f) = bytes.first() {
                        connectable = Some((f & 0x02) != 0);
                    }
                }
                0x08 | 0x09 => {
                    // Local Name (short/full) — fallback se WinRT non la dà.
                    if !bytes.is_empty() {
                        let n = String::from_utf8_lossy(&bytes).trim().to_string();
                        if !n.is_empty() {
                            ad_name = Some(n);
                        }
                    }
                }
                0x0A => {
                    if let Some(&b) = bytes.first() {
                        tx_power = Some(b as i8);
                    }
                }
                0x16 => {
                    if bytes.len() >= 3 {
                        let uuid = format!("0000{:04x}-0000-1000-8000-00805f9b34fb",
                                           u16::from_le_bytes([bytes[0], bytes[1]]));
                        service_data.insert(uuid, bytes[2..].to_vec());
                    }
                }
                0x20 | 0x21 => {
                    if bytes.len() >= 5 {
                        let mut b = [0u8; 16];
                        b[0..4].copy_from_slice(&bytes[0..4]);
                        b[4..6].copy_from_slice(&[0, 0]);
                        b[6..8].copy_from_slice(&[0x10, 0x00]);
                        b[8..16].copy_from_slice(&[0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB]);
                        let uuid = uuid_str_from_128(&b);
                        service_data.insert(uuid, bytes[4..].to_vec());
                    }
                }
                0xFF
                    // Manufacturer Specific: company id (LE) + payload (riga
                    // AD 0xFF come fonte vendor quando WinRT non normalizza).
                    if bytes.len() >= 3 => {
                        let id = u16::from_le_bytes([bytes[0], bytes[1]]);
                        manufacturer.entry(id).or_insert_with(|| bytes[2..].to_vec());
                    }
                _ => {}
            }
        }
    }

    // Riferimento di distanza: se l'AD type 0x0A non è annunciato, usa il
    // measured power del payload iBeacon (0x004C) — stesso significato fisico
    // (RSSI atteso a 1 metro) e segnala l'origine con `tx_ibeacon`.
    let mut tx_ibeacon = false;
    if tx_power.is_none() {
        if let Some(t) = crate::bluetooth::apple_ibeacon_tx(&manufacturer) {
            tx_power = Some(t);
            tx_ibeacon = true;
        }
    }

    let vendor = {
        let mut ids: Vec<u16> = manufacturer.keys().copied().collect();
        ids.sort_unstable();
        ids.first()
            .and_then(|&id| company_name(id))
            .map(|n| n.to_string())
    };
    let hint = classify(&manufacturer, &services, &service_data).map(|(label, _)| label);
    let fingerprint = stable_fingerprint(&manufacturer, &services, &service_data);
    let model_id = crate::bluetooth::fastpair_model_id(&service_data);
    let phantom = crate::bluetooth::phantom_kind(&manufacturer, &services, &service_data);
    // Nome: preferisce il LocalName WinRT, altrimenti il record AD 0x08/0x09.
    let name = name_from_local.or(ad_name);

    AdvParsed {
        name,
        vendor,
        hint,
        fingerprint,
        model_id,
        phantom,
        tx_power,
        tx_ibeacon,
        connectable,
    }
}

fn uuid_str_from_128(b: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    let hex: Vec<String> = b.iter().map(|x| format!("{:02x}", x)).collect();
    out.push_str(&hex[0..4].join(""));
    out.push('-');
    out.push_str(&hex[4..6].join(""));
    out.push('-');
    out.push_str(&hex[6..8].join(""));
    out.push('-');
    out.push_str(&hex[8..10].join(""));
    out.push('-');
    out.push_str(&hex[10..16].join(""));
    out
}

/// Total BLE advertisement packets received since the process started,
/// counted in the watcher's event handler (every received packet, not just
/// the first per device). Used by the dashboard radio panel and `--inq` to
/// tell "radio receiving nothing" apart from "nothing advertising".
static PACKETS_RECEIVED: AtomicU64 = AtomicU64::new(0);

pub fn packets_received() -> u64 {
    PACKETS_RECEIVED.load(Ordering::Relaxed)
}

/// True if the OS reports at least one Bluetooth radio powered on. Used to
/// warn clearly when `--listen` runs with no radio (e.g. this VM without the
/// USB passthrough from Proxmox) instead of silently recording 0 BLE.
pub async fn radio_present() -> bool {
    radio_status().await.map(|(_, on)| on).unwrap_or(false)
}

/// Name + power state of the first Bluetooth radio reported by the WinRT
/// radios API (`None` when the OS reports no Bluetooth radio).
pub async fn radio_status() -> Option<(String, bool)> {
    let radio = find_bluetooth_radio().await?;
    let name = radio.Name().ok().map(|h| h.to_string()).unwrap_or_default();
    let on = matches!(radio.State(), Ok(RadioState::On));
    Some((name, on))
}

/// La prima radio Bluetooth riportata dall'API WinRT `Radio`, tenuta viva per
/// poterla interrogare o riconfigurare (es. reset off/on).
async fn find_bluetooth_radio() -> Option<Radio> {
    let op = Radio::GetRadiosAsync().ok()?;
    let radios = op.await.ok()?;
    for r in radios {
        if let Ok(kind) = r.Kind() {
            if kind == RadioKind::Bluetooth {
                return Some(r);
            }
        }
    }
    None
}

/// Etichetta leggibile dello stato della radio (il `Debug` di WinRT stampa
/// `RadioState(1)`, che non dice nulla a chi legge il log).
fn radio_state_label(s: RadioState) -> &'static str {
    match s {
        RadioState::On => "ON",
        RadioState::Off => "OFF",
        RadioState::Unknown => "sconosciuto",
        _ => "?",
    }
}

/// Etichetta leggibile dell'esito di `SetStateAsync` (es. negato da policy).
fn radio_access_label(s: windows::Devices::Radios::RadioAccessStatus) -> &'static str {
    use windows::Devices::Radios::RadioAccessStatus;
    match s {
        RadioAccessStatus::Allowed => "consentito",
        RadioAccessStatus::DeniedByUser => "negato dall'utente",
        RadioAccessStatus::DeniedBySystem => "negato dal sistema",
        RadioAccessStatus::Unspecified => "non specificato",
        _ => "esito sconosciuto",
    }
}

/// Spegne e riaccende la radio Bluetooth via WinRT (`Radio::SetStateAsync`).
///
/// Serve a recuperare uno scanner LE bloccato senza riavviare il PC: il
/// driver viene riposizionato e il watcher successivo riparte pulito. È una
/// operazione che interrompe la scansione in corso (comprese eventuali
/// connessioni audio/input sulla stessa radio), quindi va invocata solo
/// quando il BLE è muto: `--reset-radio` da riga di comando o il pulsante
/// "Reset radio" nella dashboard.
///
/// Ritorna una descrizione dell'esito; l'errore è una stringa già leggibile
/// (mai un panic), così CLI e HTTP possono mostrarlo così com'è.
pub async fn reset_radio(off_secs: u64) -> Result<String, String> {
    use windows::Devices::Radios::RadioAccessStatus;

    let radio = find_bluetooth_radio()
        .await
        .ok_or_else(|| "nessuna radio Bluetooth riportata dal sistema".to_string())?;
    let name = radio
        .Name()
        .ok()
        .map(|h| h.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Bluetooth".to_string());
    let before = match radio.State() {
        Ok(s) => radio_state_label(s),
        Err(_) => "sconosciuto",
    };

    // 1) Spegni. Un rifiuto del sistema (criterio di accesso o policy) è un
    //    errore riportato all'utente, non un fallimento silenzioso.
    let status = radio
        .SetStateAsync(RadioState::Off)
        .map_err(|e| format!("spegnimento radio non richiedibile: {e}"))?
        .await
        .map_err(|e| format!("spegnimento radio fallito: {e}"))?;
    if status != RadioAccessStatus::Allowed {
        return Err(format!(
            "spegnimento radio non eseguito: {}",
            radio_access_label(status)
        ));
    }

    tokio::time::sleep(Duration::from_secs(off_secs)).await;

    // 2) Riaccendi.
    let status = radio
        .SetStateAsync(RadioState::On)
        .map_err(|e| format!("riaccensione radio non richiedibile: {e}"))?
        .await
        .map_err(|e| format!("riaccensione radio fallita: {e}"))?;
    if status != RadioAccessStatus::Allowed {
        return Err(format!(
            "riaccensione radio non eseguita: {}",
            radio_access_label(status)
        ));
    }

    // 3) Attendi che la radio sia davvero tornata ON (fino a ~6 s): il driver
    //    impiega qualche centinaio di ms a ripresentarsi allo stack.
    let mut on = false;
    for _ in 0..30 {
        if matches!(radio.State(), Ok(RadioState::On)) {
            on = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let esito = if on { "ON" } else { "stato non confermato" };
    Ok(format!(
        "radio '{name}': {before} -> OFF ({off_secs}s) -> {esito}"
    ))
}

/// MAC address of the default local Bluetooth adapter (the "stazione" that
/// recorded `presenze.csv`), e.g. "AA:BB:CC:DD:EE:FF". None when the OS
/// doesn't expose an adapter (e.g. no radio / VM without USB passthrough).
pub async fn local_adapter_mac() -> Option<String> {
    let Ok(op) = windows::Devices::Bluetooth::BluetoothAdapter::GetDefaultAsync() else {
        return None;
    };
    let Ok(adapter) = op.await else { return None };
    let Ok(addr) = adapter.BluetoothAddress() else {
        return None;
    };
    Some(mac_str(addr))
}

/// Open an event-driven scan window of `window` seconds and return the unique
/// devices with their **latest** RSSI/name/payload received during the window.
/// Devices not seen during the window are absent from the result.
/// Se `passive` è true, usa la modalità passive (no SCAN_REQ).
pub async fn scan_window(window: Duration, passive: bool) -> Vec<Seen> {
    let Some((watcher, seen)) = open_scan(passive) else {
        return Vec::new();
    };
    // Wait for the scan window; events arrive on a separate thread.
    tokio::time::sleep(window).await;
    let _ = watcher.Stop();
    collect_seen(&seen)
}

/// Versione bloccante di `scan_window` (sleep con `std::thread::sleep`), per
/// essere eseguita dentro `spawn_blocking` da handler HTTP: il futuro di
/// `scan_window` non è `Send` (il watcher WinRT trattiene event handlers), e
/// un handler axum esige un future `Send`.
pub fn scan_window_blocking(window: Duration, passive: bool) -> Vec<Seen> {
    let Some((watcher, seen)) = open_scan(passive) else {
        return Vec::new();
    };
    std::thread::sleep(window);
    let _ = watcher.Stop();
    collect_seen(&seen)
}

/// Crea il watcher, registra il gestore degli eventi e avvia la scansione.
/// Restituisce (watcher, mappa dei dispositivi) da tenere vivo durante la
/// finestra.
/// Se `passive` è true, usa la modalità passive (no SCAN_REQ).
type ScanHandles = (
    BluetoothLEAdvertisementWatcher,
    Arc<Mutex<HashMap<String, Seen>>>,
);

fn open_scan(passive: bool) -> Option<ScanHandles> {
    let watcher = match BluetoothLEAdvertisementWatcher::new() {
        Ok(w) => w,
        Err(e) => {
            crate::be!("[BLUESNIFF] blewatcher: creating watcher: {e}");
            return None;
        }
    };
    // Scanning mode: active (richiede SCAN_RSP) o passive (solo ascolto).
    let mode = if passive {
        BluetoothLEScanningMode::Passive
    } else {
        BluetoothLEScanningMode::Active
    };
    let _ = watcher.SetScanningMode(mode);

    let seen: Arc<Mutex<HashMap<String, Seen>>> = Arc::new(Mutex::new(HashMap::new()));
    let seen2 = seen.clone();
    let handler = TypedEventHandler::new(
        move |_watcher: windows::core::Ref<'_, BluetoothLEAdvertisementWatcher>,
              args: windows::core::Ref<'_, BluetoothLEAdvertisementReceivedEventArgs>| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            PACKETS_RECEIVED.fetch_add(1, Ordering::Relaxed);
            let Ok(addr) = args.BluetoothAddress() else {
                return Ok(());
            };
            let mac = mac_str(addr);
            let rssi = args.RawSignalStrengthInDBm().ok();
            let adv = args.Advertisement().ok();
            let name_local = adv.as_ref().and_then(|a| a.LocalName().ok()).and_then(|h| {
                let s = h.to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            });
            let p = adv
                .as_ref()
                .map(|a| adv_fingerprint(a, name_local))
                .unwrap_or_default();
            // Log raw per-pacchetto: costruito solo se il log è attivo.
            if crate::rawlog::enabled() {
                crate::rawlog::record(raw_event_from(args, &mac, rssi, adv.as_ref(), &p));
            }
            // Battito radio: qualunque pacchetto BLE prova che l'adapter sta
            // producendo. È l'unico segnale che permette all'analisi di presenza di
            // distinguere "il dispositivo è sparito" da "l'adapter è muto".
            crate::radiostate::note_ble_packet(
                args.Timestamp().map(timestamp_epoch_ms).unwrap_or(0),
            );
            let name = p.name;
            let vendor = p.vendor;
            let hint = p.hint;
            let fingerprint = p.fingerprint;
            let model_id = p.model_id;
            let phantom = p.phantom;
            let tx_power = p.tx_power;
            let tx_ibeacon = p.tx_ibeacon;
            let connectable = p.connectable;

            let mut map = seen2.lock().unwrap();
            match map.get_mut(&mac) {
                Some(existing) => {
                    // Latest packet wins for RSSI; keep first-seen name/payload.
                    if rssi.is_some() {
                        existing.rssi = rssi;
                    }
                    if existing.name.is_none() {
                        existing.name = name;
                    }
                    if existing.fingerprint.is_none() {
                        existing.fingerprint = fingerprint;
                        existing.vendor = vendor;
                        existing.hint = hint;
                        existing.model_id = model_id;
                        existing.phantom = phantom;
                    }
                    if tx_power.is_some() {
                        existing.tx_power = tx_power;
                        existing.tx_ibeacon = tx_ibeacon;
                    }
                    if connectable.is_some() {
                        existing.connectable = connectable;
                    }
                }
                None => {
                    map.insert(
                        mac.clone(),
                        Seen {
                            mac,
                            name,
                            rssi,
                            vendor,
                            hint,
                            fingerprint,
                            model_id,
                            phantom,
                            tx_power,
                            tx_ibeacon,
                            connectable,
                        },
                    );
                }
            }
            Ok(())
        },
    );
    if watcher.Received(&handler).is_err() {
        crate::be!("[BLUESNIFF] blewatcher: subscribing to Received failed");
        return None;
    }
    if let Err(e) = watcher.Start() {
        crate::be!("[BLUESNIFF] blewatcher: Start failed: {e}");
        return None;
    }
    Some((watcher, seen))
}

/// Ferma il watcher e restituisce i dispositivi unici ordinati per MAC.
fn collect_seen(seen: &Arc<Mutex<HashMap<String, Seen>>>) -> Vec<Seen> {
    let mut out: Vec<Seen> = seen.lock().unwrap().values().cloned().collect();
    out.sort_by(|a, b| a.mac.cmp(&b.mac));
    out
}
