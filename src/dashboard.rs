//! Web dashboard live in stile bluehood: una pagina HTML servita su localhost
//! che replica la struttura dell'interfaccia del progetto bluehood
//! (https://github.com/dannymcc/bluehood): topbar con brand e stato, sidebar
//! con statistiche e filtri per classe, tabella dispositivi con ricerca,
//! ordinamento e paginazione, modale di dettaglio e radar di prossimità live.
//!
//! Oltre alla tabella, la dashboard offre:
//! - **Heatmap oraria/giornaliera** per dispositivo, calcolata da
//!   `presenze.csv` (endpoint `/api/heatmap?mac=...`).
//! - **Gestione notifiche ntfy** dal browser (topic/server + toggle arrivo/
//!   partenza), condivise a runtime con `AlertTracker` (endpoint `/api/ntfy`).
//! - **Radar di prossimità** nella sidebar: i dispositivi sono punti la cui
//!   distanza dal centro dipende dall'RSSI e la cui posizione angolare è
//!   stabile (hash del MAC); la spazzata animata gira in tempo reale.
//!
//! Architettura: il loop `--listen` aggiorna uno stato condiviso
//! (`Arc<DashboardApp>`) ad ogni sample; il server axum serve la pagina
//! statica su `/` e i dati JSON su `/api/*`. La pagina si auto-aggiorna ogni
//! 5 secondi.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use axum::extract::{Query, State};
use axum::response::{Html, Response};
use axum::routing::{get, post};
use axum::Router;

/// Mittente del canale di shutdown del server HTTP corrente.
///
/// Serve a riaprire la dashboard su un altro indirizzo di bind a runtime
/// (per condividerla in rete) senza dover riavviare il processo.
static SHUTDOWN: std::sync::RwLock<Option<tokio::sync::oneshot::Sender<()>>> =
    std::sync::RwLock::new(None);

/// True mentre un riavvio della dashboard (cambio di bind address) e' in corso.
///
/// Serve a serializzare i riavvii: due click rapidi su "Condividi" avrebbero
/// altrimenti due task che chiamano entrambi `stop_dashboard()`, e il secondo
/// colpirebbe il sender del server appena avviato dal primo, lasciandolo orfano.
static RESTARTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Fermo il server HTTP corrente, se attivo.
fn stop_dashboard() {
    let sender = SHUTDOWN.write().ok().and_then(|mut s| s.take());
    if let Some(tx) = sender {
        let _ = tx.send(());
    }
}

/// Middleware: registra l'indirizzo IP di ogni client che chiama la dashboard.
///
/// L'IP arriva da `ConnectInfo`, quindi il server va avviato con
/// `into_make_service_with_connect_info` (vedi `serve`). Se manca, non
/// registriamo nulla: inventare un "sconosciuto" per richiesta produrrebbe un
/// elenco di clienti falso.
///
/// Sul percorso registriamo solo il nome, mai query string o header: la
/// dashboard non deve diventare un registro di cosa fa ogni utente.
async fn record_client(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    let path = req.uri().path().to_string();
    crate::clients::note(peer, &path);
    next.run(req).await
}

/// GET /api/share -> stato della condivisione in rete.
///
/// POST /api/share {"on": true|false} -> accende o spegne la condivisione.
///
/// Accenderla significa riaprire il server HTTP su 0.0.0.0: la scelta viene
/// salvata e ripetuta al prossimo avvio. NON apriamo il firewall di Windows:
/// richiede diritti di amministratore e resta una decisione dell'utente. Se la
/// porta resta chiusa dopo l'attivazione, lo diciamo esplicitamente invece di
/// far credere che la condivisione funzioni.
async fn share_get(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    let port = state.port();
    let urls = state.urls.read().map(|u| u.clone()).unwrap_or_default();
    let active = !urls.is_empty()
        && urls
            .iter()
            .any(|(u, _)| !u.contains("127.0.0.1") && !u.contains("localhost"));
    let mut v = crate::share::status_json(active, port);
    if let serde_json::Value::Object(ref mut o) = v {
        o.insert("urls".into(), serde_json::json!(urls));
        // Gli indirizzi li calcoliamo qui e non nel modulo: sono di una
        // macchina specifica, mentre `share` e' pensato per essere
        // indipendente dalla rete (e testabile senza schede di rete).
        let addrs: Vec<std::net::IpAddr> = crate::lan::local_ipv4_addrs()
            .into_iter()
            .map(std::net::IpAddr::V4)
            .collect();
        o.insert(
            "addresses".into(),
            serde_json::json!(if active {
                addrs
            } else {
                Vec::<std::net::IpAddr>::new()
            }),
        );
    }
    axum::Json(v)
}

#[derive(serde::Deserialize)]
struct ShareReq {
    on: bool,
}

async fn share_post(
    State(state): State<DashboardState>,
    axum::Json(req): axum::Json<ShareReq>,
) -> axum::Json<serde_json::Value> {
    let port = state.port();
    let addrs = crate::lan::local_ipv4_addrs();
    // Logger separato ma sullo stesso file in append: le righe di mDNS e di
    // condivisione restano accanto a tutto il resto del log.
    let logger = match Logger::open_default() {
        Ok(l) => l,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "ok": false,
                "error": format!("log non apribile: {e}"),
            }))
        }
    };

    if let Err(e) = crate::share::set_wanted(req.on) {
        return axum::Json(serde_json::json!({
            "ok": false,
            "error": format!("salvataggio non riuscito: {e}"),
        }));
    }

    // Apriamo (o chiudiamo) la porta nel firewall. Va fatto DOPO aver salvato
    // la scelta, cosi' anche se l'apertura fallisce la dashboard resta
    // condivisa sul bind e l'utente vede esattamente cosa e' successo.
    let fw = if req.on {
        crate::share::ensure_port(port)
    } else {
        crate::share::close_port()
    };
    logger.log(&format!(
        "share: porta {port} -> {} ({})",
        fw.state, fw.detail
    ));

    // Riapriamo il server sulla nuova direzione. Fermare l'attuale e farne
    // partire uno nuovo e' l'unico modo: il bind non e' modificabile a caldo.
    //
    // Lo facciamo in un task con qualche ritardo, perche' fermare il server
    // uccide anche la connessione che sta servendo questa risposta: se lo
    // facessimo qui dentro, il browser vedrebbe una connessione interrotta e
    // non saprebbe se la condivisione e' riuscita. Un ritardo di 400 ms
    // basta perche' la risposta venga serializzata e inviata prima del teardown.
    let addr = if req.on { "0.0.0.0" } else { "127.0.0.1" };
    let st = state.clone();
    // Riavvii serializzati: un secondo click durante un riavvio viene
    // scartato invece di fare concorrenza sul sender di shutdown.
    if RESTARTING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        logger.log("share: riavvio gia' in corso, richiesta ignorata");
        return axum::Json(serde_json::json!({ "ok": true, "restarting": true }));
    }
    // `Logger` ora e' clonabile (handle condiviso via Arc): clonarlo evita di
    // aprire un nuovo file descriptor a ogni riavvio del server.
    let lg = logger.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        stop_dashboard();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        // Qui l'utente sta guardando la pagina che sta per morire: se il
        // riavvio fallisce, il reload successivo gli mostrerebbe "connessione
        // rifiutata" senza spiegazione. Lo diciamo, e nel log per poterlo
        // diagnosticare dopo.
        if let Err(e) = spawn_server(&lg, st, parse_bind(addr), port) {
            lg.log(&format!("share: riavvio del server fallito: {e}"));
            crate::be!("[BLUESNIFF] dashboard: riavvio fallito dopo il cambio di bind: {e}");
        }
        RESTARTING.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    // Su richiesta esplicita annunciamo anche il servizio via mDNS, cosi' chi
    // e' vicino lo trova da solo invece di digitare l'IP.
    if req.on {
        match crate::mdns_register::start_mdns_responder(&logger, port) {
            Ok(_daemon) => {
                // Il daemon va tenuto vivo: qui lo droppiamo, e in realta'
                // mdns_register lo registra in un globale, quindi l'annuncio
                // continua. Segniamo comunque l'esito reale.
                crate::share::set_mdns_live(true);
                logger.log(&format!("share: annuncio mDNS attivo sulla porta {port}"));
            }
            Err(e) => {
                crate::share::set_mdns_live(false);
                logger.log(&format!("share: annuncio mDNS non riuscito: {e}"));
            }
        }
    }

    let mut s = crate::share::load();
    s.last_bind = Some(addr.to_string());
    s.last_port = Some(port);
    let _ = crate::share::save(&s);

    axum::Json(serde_json::json!({
        "ok": true,
        "active": req.on,
        "bind": addr,
        "port": port,
        "addresses": if req.on { addrs.clone() } else { Vec::new() },
        "firewall": fw,
        "firewall_note": crate::share::status_json(req.on, port)["firewall_note"],
    }))
}

fn parse_bind(s: &str) -> std::net::IpAddr {
    s.parse().unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]))
}

/// GET /api/clients -> quanti e quali IP hanno contattato la dashboard.
///
/// `note` sul nome: un IP puo' corrispondere a piu' clienti reali (NAT, proxy)
/// e uno stesso client puo' cambiare IP. Sono stime, non identita'.
async fn clients_json_route() -> axum::Json<serde_json::Value> {
    axum::Json(crate::clients::clients_json())
}

use crate::alerts::NtfySettings;
use crate::classify::{classify_device, proximity_zone};
use crate::logging::Logger;

/// Numero massimo di campioni RSSI conservati per il grafico del modale.
const RSSI_HISTORY_CAP: usize = 120;

/// Un dispositivo con le informazioni necessarie alla dashboard. Lo stato è
/// cumulativo: un dispositivo visto più volte accumula `sightings`, la data
/// del primo avvistamento e lo storico RSSI (a differenza della finestra
/// "on-air now" della versione precedente, qui i dispositivi restano in
/// elenco finché il processo è attivo, come nel DB di bluehood).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DashboardDevice {
    pub mac: String,
    pub name: String,
    pub vendor: String,
    pub rssi: Option<i16>,
    pub zone: String,
    pub category: String,
    pub randomized: bool,
    pub identified: bool,
    pub watched: bool,
    /// L'utente ha deciso di non vedere questo dispositivo (`ignore.txt`).
    ///
    /// Non e' la stessa cosa di `watched`: ignorato vuol dire "togliamolo
    /// dalla tabella", seguito vuol dire "cercalo e avvisami". Un
    /// dispositivo puo' essere entrambi, e in quel caso continua a notificare
    /// e sparisce dalla lista. I due file sono separati perche' i due
    /// desideri sono separati.
    pub ignored: bool,
    /// Questo dispositivo e' quello che ha dichiarato l'utente come suo
    /// (`is_me.txt`). Vale al massimo per un MAC: con due non sapremmo
    /// quale dei due sia "lui", e l'utente finirebbe per non scegliere.
    pub is_me: bool,
    /// Persona associata in `bt_known.txt` (terza colonna, "di chi e'").
    /// Vuota se il dispositivo non e' seguito o se l'utente non l'ha ancora
    /// compilata: e' un dato che solo l'utente ha, nessuno puo' indovinarlo.
    pub persona: String,
    /// Visto nell'ultima finestra di scansione (filtro "Attivi").
    pub active: bool,
    pub sightings: u32,
    pub first_seen: String,
    pub last_seen: String,
    pub rssi_history: Vec<i16>,
    /// Google Fast Pair Model ID (0xFE2C) quando annunciato.
    pub model_id: Option<u32>,
    /// Nome prodotto risolto dal Model ID (model_names.txt), anche quando
    /// l'annuncio non pubblicizza un nome.
    pub model_name: Option<String>,
    /// Famiglia "popup/phantom" dell'annuncio (per il marcatore 👻).
    pub phantom: Option<String>,
    /// Vulnerabilità note che matchano questo dispositivo (es. WhisperPair).
    pub cves: Vec<crate::cves::CveEntry>,
    /// Tx Power dichiarata (AD 0x0A, dBm) quando presente; se manca, il
    /// fallback è il measured power del payload iBeacon (0x004C) con
    /// `tx_ibeacon = true`.
    pub tx_power: Option<i8>,
    /// Vero quando `tx_power` proviene dal payload iBeacon invece che dall'AD
    /// 0x0A (indicato nella scheda come "· iBeacon").
    pub tx_ibeacon: bool,
    /// Connettibile (flags AD 0x01: LE General Discoverable).
    pub connectable: Option<bool>,
    /// Distanza stimata in metri (path-loss n=2.0, corretta con
    /// l'attenuazione ambiente quando disponibile) da RSSI + Tx Power.
    pub distance_m: Option<f32>,
    /// Stato del filtro alpha-beta per l'RSSI: livello stimato corrente
    /// (idea da BTScan/kalman_filter.py di bluetooth-arsenal). Non
    /// serializzato: serve solo a stabilizzare tracciati, zone e distanze.
    #[serde(skip)]
    pub rssi_smooth: Option<f32>,
    /// Componente di tendenza del filtro alpha-beta.
    #[serde(skip)]
    pub rssi_vel: f32,
    /// Fingerprint dell'annuncio BLE: serve a riconoscere i MAC rotanti
    /// (stesso fingerprint su più MAC = stesso dispositivo fisico che cambia
    /// indirizzo). Non serializzato (è solo una chiave interna).
    #[serde(skip)]
    pub fingerprint: String,
    /// Dispositivo statico = falso positivo ambientale (logica fpfilter):
    /// RSSI a varianza quasi nulla per >= 5 campioni — Smart-Tag dietro il
    /// muro, PC/TV fisso, antenna. Badge 📌 + filtro sidebar.
    pub static_dev: bool,
    /// Il MAC fa parte di una famiglia di MAC rotanti (stesso fingerprint su
    /// >= 2 MAC): un solo dispositivo fisico. Badge 🔄 + filtro sidebar.
    pub rotating: bool,
    /// Quanti MAC condividono il fingerprint (dimensione famiglia rotante).
    pub rotating_n: usize,
}

/// Un dispositivo trovato dall'inquiry classic, pronto per la serializzazione.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InquiryDevice {
    pub mac: String,
    pub name: String,
    pub class: String,
    pub flags: String,
}

/// Ultimo risultato dell'inquiry classic (condiviso con la dashboard).
#[derive(Debug, Clone, Default)]
pub struct InquirySnapshot {
    pub devices: Vec<InquiryDevice>,
    pub timestamp: String,
}

/// Converte una Tx Power dichiarata nell'RSSI atteso a 1 metro. Le Tx Power
/// "measured power" (es. iBeacon 0x004C, -40..-70 dBm) sono già l'RSSI a
/// 1 m; le potenze irradiate AD 0x0A (tipicamente 0..+10 dBm) vanno corrette
/// con l'accoppiamento a 1 m in interno (~41 dB: rssi@1m = tx - 41).
fn eff_ref_dbm(tx: f32) -> f32 {
    if (-80.0..=-20.0).contains(&tx) {
        tx
    } else {
        tx - 41.0
    }
}

/// Campioni di percorso (path loss) per la stima della portata del dongle:
/// collezionati dai dispositivi che dichiarano Tx Power, servono a stimare
/// l'attenuazione ambiente (P10 dei path loss = dispositivi più vicini) e la
/// portata teorica, e ad affinare le distanze mostrate nel radar/scheda.
#[derive(Default)]
pub struct PathlossStat {
    /// Coppie (tx dichiarata, path loss = tx - rssi) — rolling, cap 600.
    samples: VecDeque<(f32, f32)>,
    /// Attenuazione ambiente in dB (None finché non ci sono >= 10 campioni).
    pub atten_db: Option<f32>,
    /// Tx Power dichiarata mediana dei campioni.
    pub tx_median: Option<f32>,
    /// Portata teorica stimata in metri (spazio libero n=2.0, floor -96 dBm).
    pub range_m: Option<f32>,
}

impl PathlossStat {
    const FLOOR_DBM: f32 = -96.0;
    const MIN_SAMPLES: usize = 10;
    const CAP: usize = 600;

    fn push(&mut self, tx: f32, rssi: f32) {
        // Normalizza ogni dichiarazione all'RSSI atteso a 1 metro (frammenti
        // "measured power" vs potenze irradiate), così campioni eterogenei
        // contribuiscono alla stessa scala di path loss.
        let er = eff_ref_dbm(tx);
        // Ignora campioni inverosimili (path loss negativo = rssi > atteso).
        let pl = er - rssi;
        if pl < 0.0 {
            return;
        }
        self.samples.push_back((er, pl));
        if self.samples.len() > Self::CAP {
            self.samples.pop_front();
        }
        if self.samples.len() >= Self::MIN_SAMPLES {
            let mut pls: Vec<f32> = self.samples.iter().map(|s| s.1).collect();
            pls.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            // P10: i dispositivi più vicini (path loss minori) approssimano
            // l'attenuazione dell'ambiente a corta distanza. Cap a 25 dB per
            // non sovra-correggere le distanze con stime fuori scala (una
            // stanza tipica a 1 m dà 5..15 dB oltre lo spazio libero).
            let idx = ((pls.len() as f32) * 0.10) as usize;
            let p10 = pls[idx.min(pls.len() - 1)];
            self.atten_db = Some(p10.clamp(0.0, 25.0));
            let mut txs: Vec<f32> = self.samples.iter().map(|s| s.0).collect();
            txs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let med = txs[txs.len() / 2];
            self.tx_median = Some(med);
            let floor = Self::FLOOR_DBM;
            self.range_m = Some(10f32.powf((med - p10.max(0.0) - floor) / 20.0));
        }
    }
}

/// Stato condiviso tra il recorder e il server HTTP.
pub struct DashboardApp {
    pub devices: RwLock<Vec<DashboardDevice>>,
    /// Impostazioni ntfy runtime (modificabili dal browser).
    pub ntfy: Arc<RwLock<NtfySettings>>,
    /// Percorso di `presenze.csv` per le heatmap (None = non disponibile).
    pub presenze: Option<PathBuf>,
    /// Ultima inquiry classic (alimentata dal loop di `--listen` e dal
    /// pulsante "Ripeti inquiry" del pannello).
    pub inquiry: RwLock<InquirySnapshot>,
    /// Contatore pacchetti BLE per finestra di campionamento (5s), per il
    /// grafico "la radio respira". Cap: 60 campioni (~5 min).
    pub packets: RwLock<VecDeque<u32>>,
    /// URL raggiungibili del listener con etichetta (es. http://192.168.1.15:9000 / "intranet",
    /// 100.x.x.x / "tailnet"), mostrati nella barra "Collegato a" e copiabili.
    pub urls: RwLock<Vec<(String, String)>>,
    /// Nomi personalizzati (MAC maiuscolo -> nome), caricati/salvati in
    /// `names.txt` accanto all'eseguibile e applicati ai dispositivi visti.
    pub names: RwLock<HashMap<String, String>>,
    /// PID del monitor `--inq` avviato dalla dashboard (None = mai avviato).
    pub monitor_pid: RwLock<Option<u32>>,
    /// Statistiche path-loss per la stima portata/attenuazione del dongle.
    pub pathloss: RwLock<PathlossStat>,
    /// Ultimi risultati delle sonde GATT/SDP (chiave `gatt:<mac>` / `sdp:<mac>`),
    /// da mostrare di nuovo sulla scheda ai prossimi refresh.
    pub probes: RwLock<HashMap<String, serde_json::Value>>,
    /// Ordine di inserimento delle chiavi in `probes`: serve per l'eviction
    /// FIFO (le più vecchie escono per prime). Senza questo, `HashMap::keys()`
    /// darebbe un ordine arbitrario e la cache butterebbe fuori a caso.
    pub probe_order: RwLock<VecDeque<String>>,
    /// Stato pausa della scansione BLE (true = in pausa).
    pub paused: Arc<std::sync::atomic::AtomicBool>,
    /// Modalità di scansione (true = passive, false = active).
    pub passive: std::sync::atomic::AtomicBool,
    /// Porta su cui ascolta il server HTTP: serve a riaprirlo sulla stessa
    /// porta quando l'utente attiva o disattiva la condivisione in rete.
    pub port: RwLock<u16>,
}

pub type DashboardState = Arc<DashboardApp>;

impl DashboardApp {
    /// Imposta la porta effettivamente in ascolto. Chiamata da `spawn_server`
    /// dopo il bind riuscito.
    fn set_port(&self, port: u16) {
        if let Ok(mut p) = self.port.write() {
            *p = port;
        }
    }

    /// La porta su cui ascoltiamo davvero. Se il lock e' corrotto (poisoned)
    /// prendiamo comunque il valore: una dashboard che non sa su che porta
    /// e' peggio di una che sbaglia di 9000.
    pub fn port(&self) -> u16 {
        self.port.read().map(|p| *p).unwrap_or(9000)
    }
}

/// Stato condiviso vuoto con il percorso di `presenze.csv` per le heatmap.
pub fn new_state_with(presenze: Option<PathBuf>) -> DashboardState {
    Arc::new(DashboardApp {
        devices: RwLock::new(Vec::new()),
        ntfy: Arc::new(RwLock::new(NtfySettings::load_default())),
        presenze,
        inquiry: RwLock::new(InquirySnapshot::default()),
        packets: RwLock::new(VecDeque::new()),
        urls: RwLock::new(Vec::new()),
        names: RwLock::new(load_names()),
        monitor_pid: RwLock::new(None),
        pathloss: RwLock::new(PathlossStat::default()),
        paused: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        passive: std::sync::atomic::AtomicBool::new(false),
        probes: RwLock::new(HashMap::new()),
        probe_order: RwLock::new(VecDeque::new()),
        port: RwLock::new(9000),
    })
}

/// Distanza massima ritenuta plausibile per il path-loss BLE indoor (n=2.0):
/// oltre questo limite il risultato è inverosimile (condizioni di visibilità
/// eccezionali, dati corrotti o Tx Power irreali) e non viene esposto.
const MAX_DISTANCE_M: f32 = 100.0;

/// Stima di distanza path-loss: `10^((ref - atten - rssi) / 20)` con n=2.0
/// (indoor), dove `ref` è la Tx Power normalizzata all'RSSI atteso a 1 metro
/// (`eff_ref_dbm`). `atten_db` è l'attenuazione ambiente stimata dal dongle
/// (None = nessuna correzione). Ritorna None senza RSSI o Tx Power, e anche
/// quando il valore stimato supera `MAX_DISTANCE_M` (non viene esposto).
fn estimate_distance_m(
    rssi: Option<i16>,
    tx_power: Option<i8>,
    atten_db: Option<f32>,
) -> Option<f32> {
    let r = rssi? as f32;
    let t = eff_ref_dbm(tx_power? as f32);
    let a = atten_db.unwrap_or(0.0);
    let dist = 10f32.powf((t - a - r) / 20.0);
    if dist > MAX_DISTANCE_M {
        return None;
    }
    Some(if dist < 0.1 { 0.1 } else { dist })
}

/// Filtro alpha-beta 1-D per stabilizzare l'RSSI (idea da
/// BTScan/kalman_filter.py di bluetooth-arsenal): tiene traccia di un
/// livello stimato e di una piccola componente di tendenza, così un singolo
/// campione anomalo (es. cambio di potenza di trasmissione del telefono)
/// non fa saltare tutto il tracciato. `state` = livello stimato precedente
/// (None = primo campione, si inizializza al valore grezzo), `vel` =
/// tendenza. Restituisce (nuovo livello, nuova tendenza).
fn rssi_smooth_step(state: Option<f32>, vel: f32, y: f32) -> (f32, f32) {
    const ALPHA: f32 = 0.35;
    const BETA: f32 = 0.06;
    match state {
        None => (y, 0.0),
        Some(x) => {
            let x_pred = x + vel;
            let r = y - x_pred;
            (x_pred + ALPHA * r, vel + BETA * r)
        }
    }
}

/// Percorso del file con i nomi personalizzati (`MAC;Nome` per riga).
fn names_path() -> PathBuf {
    crate::logging::exe_dir().join("names.txt")
}

/// Carica `names.txt`: righe `MAC;Nome` -> mappa MAC maiuscolo -> nome.
fn load_names() -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(names_path()) {
        for line in content.lines() {
            let mut it = line.split(';');
            if let (Some(mac), Some(name)) = (it.next(), it.next()) {
                let mac = mac.trim();
                let name = name.trim();
                if !mac.is_empty() && !name.is_empty() {
                    map.insert(mac.to_uppercase(), name.to_string());
                }
            }
        }
    }
    map
}

/// Persiste la mappa dei nomi personalizzati in `names.txt`.
pub fn save_names(state: &DashboardState) {
    if let Ok(map) = state.names.read() {
        let mut out = String::new();
        let mut v: Vec<(&String, &String)> = map.iter().collect();
        v.sort();
        for (mac, name) in v {
            out.push_str(&format!("{mac};{name}\n"));
        }
        let _ = std::fs::write(names_path(), out);
    }
}

/// Etichetta dell'interfaccia in base all'indirizzo IP: la CGNAT di Tailscale
/// (100.64.0.0/10) è "tailnet", le classi private classiche sono "intranet",
/// tutto il resto (tunnel/VPN vari) è "VPN".
fn ip_label(ip: std::net::Ipv4Addr) -> &'static str {
    let o = ip.octets();
    match o {
        [100, b, _, _] if (64..=127).contains(&b) => "tailnet",
        [10, _, _, _] => "intranet",
        [172, b, _, _] if (16..=31).contains(&b) => "intranet",
        [192, 168, _, _] => "intranet",
        _ => "VPN",
    }
}

/// Aggiorna lo stato della dashboard con i dispositivi visti nell'ultima
/// finestra di scansione. I dispositivi si accumulano per MAC (conteggio
/// avvistamenti, primo/ultimo avvistamento, storico RSSI); quelli visti in
/// questa finestra vengono marcati `active`. I MAC di `known_macs` (i telefoni
/// noti di `bt_known.txt`) vengono marcati `watched`.
pub fn update(
    state: &DashboardState,
    seen: &[crate::blewatcher::Seen],
    known_bt: &[crate::btclassic::KnownBt],
) {
    let now = crate::logging::utc_now_rfc3339();
    // MAC e persona associate. Passiamo i `KnownBt` interi, non una lista di
    // MAC: la scheda mostra anche "di chi e'", e derivarla qui evita di
    // portare in giro due liste parallelas che possono divergere.
    let known: HashMap<String, String> = known_bt
        .iter()
        .map(|k| (k.mac.trim().to_uppercase(), k.persona.trim().to_string()))
        .collect();
    // Le due scelte "cosa non voglio" e "cosa sono io" arrivano da file
    // editabili a mano, quindi sono rilette qui a ogni finestra di scansione
    // invece di essere tenute in memoria: se l'utente corregge una riga di
    // `ignore.txt` con Notepad mentre bluesniff gira, non deve aspettare il
    // riavvio. Sono due file minuscoli e una `read_to_string` ogni 5 s e'
    // trascurabile rispetto alla scansione stessa.
    let (ignored_macs, my_mac) = load_user_flags();
    // Attenuazione ambiente stimata (finestra corrente): corregge le distanze
    // path-loss dei dispositivi. Snapshot prima del lock sui devices.
    let atten_db = state.pathloss.read().ok().and_then(|p| p.atten_db);

    if let Ok(mut devices) = state.devices.write() {
        // MAC visti in questa finestra: nessun altro dispositivo resta attivo.
        for d in devices.iter_mut() {
            d.active = false;
        }
        // Nomi personalizzati (names.txt): hanno la precedenza sul nome
        // pubblicizzato, così un dispositivo rinominato resta riconoscibile
        // anche se gli annunci cambiano.
        let overrides: HashMap<String, String> =
            state.names.read().map(|m| m.clone()).unwrap_or_default();
        for s in seen {
            let category =
                classify_device(s.name.as_deref(), s.vendor.as_deref(), s.hint.as_deref());
            let advertised = s.name.clone().unwrap_or_default();
            let mac_up = s.mac.to_uppercase();
            let name = overrides
                .get(&mac_up)
                .cloned()
                .unwrap_or_else(|| advertised.clone());
            let vendor = s.vendor.clone().unwrap_or_default();
            let identified = !name.is_empty() || !vendor.is_empty();
            let randomized = crate::vendor::is_locally_administered(&s.mac);
            let watched = known.contains_key(&mac_up);
            let persona = known.get(&mac_up).cloned().unwrap_or_default();
            let ignored = ignored_macs.contains(&mac_up);
            let is_me = my_mac.as_deref() == Some(mac_up.as_str());

            match devices.iter_mut().find(|d| d.mac.to_uppercase() == mac_up) {
                Some(existing) => {
                    existing.active = true;
                    existing.sightings += 1;
                    existing.last_seen = now.clone();
                    // Riletti a ogni passata: l'utente puo' aver ignorato
                    // questo MAC dalla dashboard (o tolto l'ignore) mentre la
                    // scheda era aperta, e il riflesso deve valere per i
                    // device gia' in lista, non solo per quelli nuovi.
                    existing.ignored = ignored;
                    existing.is_me = is_me;
                    // La persona puo' comparire dopo che l'utente l'ha
                    // compilata in bt_known.txt: la ricarichiamo a ogni
                    // finestra invece di congelarla alla prima vista.
                    if !persona.is_empty() {
                        existing.persona = persona.clone();
                    }
                    if let Some(raw) = s.rssi {
                        // Stabilizza l'RSSI col filtro alpha-beta: tracciati del
                        // radar, zona e distanza non saltano più a ogni campione.
                        let (smooth, vel) =
                            rssi_smooth_step(existing.rssi_smooth, existing.rssi_vel, raw as f32);
                        let rounded = smooth.round() as i16;
                        existing.rssi_smooth = Some(smooth);
                        existing.rssi_vel = vel;
                        existing.rssi = Some(rounded);
                        existing.rssi_history.push(rounded);
                        if existing.rssi_history.len() > RSSI_HISTORY_CAP {
                            existing
                                .rssi_history
                                .drain(..existing.rssi_history.len() - RSSI_HISTORY_CAP);
                        }
                    }
                    if !name.is_empty() {
                        existing.name = name;
                    }
                    if !vendor.is_empty() {
                        existing.vendor = vendor;
                    }
                    existing.zone = proximity_zone(existing.rssi).unwrap_or("-").to_string();
                    existing.category = category.label().to_string();
                    existing.identified = !existing.name.is_empty() || !existing.vendor.is_empty();
                    existing.randomized = randomized;
                    if s.model_id.is_some() {
                        existing.model_id = s.model_id;
                        existing.model_name = s.model_id.and_then(crate::cves::model_name);
                    }
                    if s.phantom.is_some() {
                        existing.phantom = s.phantom.map(|p| p.to_string());
                    }
                    if s.tx_power.is_some() {
                        existing.tx_power = s.tx_power;
                        existing.tx_ibeacon = s.tx_ibeacon;
                    }
                    if s.connectable.is_some() {
                        existing.connectable = s.connectable;
                    }
                    // Campione path-loss per la stima portata/attenuazione.
                    if let (Some(tx), Some(rssi)) = (existing.tx_power, existing.rssi) {
                        if let Ok(mut pl) = state.pathloss.write() {
                            pl.push(tx as f32, rssi as f32);
                        }
                    }
                    existing.distance_m =
                        estimate_distance_m(existing.rssi, existing.tx_power, atten_db);
                    // Ricalcola le vulnerabilità note con nome/vendor aggiornati.
                    existing.cves = crate::cves::match_cves(
                        crate::cves::db(),
                        existing.model_id,
                        &existing.name,
                        &existing.vendor,
                        s.hint.as_deref().unwrap_or(""),
                        &existing.mac,
                    );
                    if let Some(fp) = &s.fingerprint {
                        if !fp.is_empty() {
                            existing.fingerprint = fp.clone();
                        }
                    }
                    if watched {
                        existing.watched = true;
                    }
                }
                None => {
                    let zone = proximity_zone(s.rssi).unwrap_or("-").to_string();
                    let cves = crate::cves::match_cves(
                        crate::cves::db(),
                        s.model_id,
                        &name,
                        &vendor,
                        s.hint.as_deref().unwrap_or(""),
                        &s.mac,
                    );
                    // Campione path-loss per la stima portata/attenuazione.
                    if let (Some(tx), Some(rssi)) = (s.tx_power, s.rssi) {
                        if let Ok(mut pl) = state.pathloss.write() {
                            pl.push(tx as f32, rssi as f32);
                        }
                    }
                    // Primo campione: il filtro parte dal valore grezzo (e
                    // resta non inizializzato se la finestra non ha RSSI).
                    let (smooth0, vel0, rssi0) = match s.rssi {
                        Some(raw) => {
                            let (s, v) = rssi_smooth_step(None, 0.0, raw as f32);
                            (Some(s), v, Some(s.round() as i16))
                        }
                        None => (None, 0.0, None),
                    };
                    devices.push(DashboardDevice {
                        mac: s.mac.clone(),
                        name,
                        vendor,
                        rssi: rssi0,
                        zone,
                        category: category.label().to_string(),
                        randomized,
                        identified,
                        watched,
                        ignored,
                        is_me,
                        persona,
                        active: true,
                        sightings: 1,
                        first_seen: now.clone(),
                        last_seen: now.clone(),
                        rssi_history: rssi0.into_iter().collect(),
                        model_id: s.model_id,
                        model_name: s.model_id.and_then(crate::cves::model_name),
                        phantom: s.phantom.map(|p| p.to_string()),
                        cves,
                        tx_power: s.tx_power,
                        tx_ibeacon: s.tx_ibeacon,
                        connectable: s.connectable,
                        distance_m: estimate_distance_m(rssi0, s.tx_power, atten_db),
                        rssi_smooth: smooth0,
                        rssi_vel: vel0,
                        fingerprint: s.fingerprint.clone().unwrap_or_default(),
                        static_dev: false,
                        rotating: false,
                        rotating_n: 0,
                    });
                }
            }
        }
        // Rilevamento falsi positivi ambientali (fpfilter): dispositivi
        // statici per varianza RSSI + famiglie di MAC rotanti per fingerprint
        // (un solo dispositivo fisico con più MAC temporanei).
        recompute_env_flags(&mut devices);
    }
}

/// Marca i dispositivi come 📌 statici (varianza RSSI sotto soglia su >= 5
/// campioni) e 🔄 rotanti (stesso fingerprint su >= 2 MAC). Stessa logica
/// matematica del report offline `--static` (fpfilter).
fn recompute_env_flags(devices: &mut [DashboardDevice]) {
    use crate::fpfilter::{is_static_rssi, rotating_families, MIN_SAMPLES, VARIANCE_THRESHOLD};
    for d in devices.iter_mut() {
        d.static_dev = is_static_rssi(&d.rssi_history, MIN_SAMPLES, VARIANCE_THRESHOLD);
        d.rotating = false;
        d.rotating_n = 0;
    }
    let pairs: Vec<(&str, &str)> = devices
        .iter()
        .map(|d| (d.mac.as_str(), d.fingerprint.as_str()))
        .collect();
    for (_, macs) in rotating_families(&pairs) {
        let n = macs.len();
        for m in &macs {
            if let Some(d) = devices.iter_mut().find(|d| d.mac.eq_ignore_ascii_case(m)) {
                d.rotating = true;
                d.rotating_n = n;
            }
        }
    }
}

/// Aggiorna lo stato con i risultati del probe classic dei telefoni noti:
/// un telefono presente viene inserito (o aggiornato) nella lista come
/// dispositivo `watched` + `active`, così compare nei pannelli Seguiti/
/// Attivi della dashboard anche se non trasmette annunci BLE.
pub fn update_classic(
    state: &DashboardState,
    results: &[crate::btclassic::ProbeResult],
    known: &[crate::btclassic::KnownBt],
) {
    let now = crate::logging::utc_now_rfc3339();
    let overrides: HashMap<String, String> =
        state.names.read().map(|m| m.clone()).unwrap_or_default();
    let (ignored_macs, my_mac) = load_user_flags();
    for r in results {
        if !r.present {
            continue;
        }
        let known_entry = known.iter().find(|k| k.mac == r.mac);
        let known_name = known_entry.map(|k| k.nome.clone()).unwrap_or_default();
        let persona = known_entry
            .map(|k| k.persona.trim().to_string())
            .unwrap_or_default();
        let mac_up = r.mac.to_uppercase();
        let ignored = ignored_macs.contains(&mac_up);
        let is_me = my_mac.as_deref() == Some(mac_up.as_str());
        let name = overrides.get(&mac_up).cloned().unwrap_or(known_name);
        let category = classify_device(Some(&name), None, None).label().to_string();
        if let Ok(mut devices) = state.devices.write() {
            match devices.iter_mut().find(|d| d.mac.to_uppercase() == mac_up) {
                Some(existing) => {
                    existing.active = true;
                    existing.watched = true;
                    existing.ignored = ignored;
                    existing.is_me = is_me;
                    if !persona.is_empty() {
                        existing.persona = persona.clone();
                    }
                    existing.sightings += 1;
                    existing.last_seen = now.clone();
                    if !name.is_empty() {
                        existing.name = name;
                    }
                    existing.identified = !existing.name.is_empty() || !existing.vendor.is_empty();
                    existing.category = category;
                }
                None => {
                    devices.push(DashboardDevice {
                        mac: r.mac.clone(),
                        name: name.clone(),
                        vendor: String::new(),
                        rssi: None,
                        zone: "-".to_string(),
                        category,
                        randomized: false,
                        identified: !name.is_empty(),
                        watched: true,
                        ignored,
                        is_me,
                        persona,
                        active: true,
                        sightings: 1,
                        first_seen: now.clone(),
                        last_seen: now.clone(),
                        rssi_history: Vec::new(),
                        model_id: None,
                        model_name: None,
                        phantom: None,
                        cves: Vec::new(),
                        tx_power: None,
                        tx_ibeacon: false,
                        connectable: None,
                        distance_m: None,
                        rssi_smooth: None,
                        rssi_vel: 0.0,
                        fingerprint: String::new(),
                        static_dev: false,
                        rotating: false,
                        rotating_n: 0,
                    });
                }
            }
        }
    }
}

/// Rilegge le due scelte che l'utente ha espresso fuori dalla dashboard:
/// i MAC ignorati e il suo dispositivo personale.
///
/// Sono volutamente tenute fuori da `DashboardState`: la fonte di verita' sono
/// i file accanto all'eseguibile, e tenere una copia in memoria significherebbe
/// due stati da riconciliare con un posto dove possono divergere (l'utente
/// che edita il file a mano, un crash, un secondo processo).
fn load_user_flags() -> (HashSet<String>, Option<String>) {
    (
        crate::ignore::load_set(&crate::ignore::path()),
        crate::mine::get(&crate::mine::path()),
    )
}

/// Avvia il server HTTP in un task separato. `port` = porta di ascolto
/// (default 9000). L'indirizzo di ascolto è 127.0.0.1 per default: per
/// esporre la dashboard sulla LAN passare `--dashboard-addr 0.0.0.0`.
///
/// Ritorna `Err` se il server non e' partito. Il chiamante decide il tono
/// del messaggio: se la dashboard e' stata accesa da sola, un errore secco
/// sembrerebbe un guasto di bluesniff; se l'utente l'ha chiesta esplicitamente,
/// l'errore e' esattamente quello che si aspetta di vedere.
pub fn spawn_server(
    logger: &Logger,
    state: DashboardState,
    addr: std::net::IpAddr,
    port: u16,
) -> Result<(), String> {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/devices", get(devices_json))
        .route("/api/export", get(export_csv))
        .route("/api/export/security", get(export_security))
        .route("/api/heatmap", get(heatmap))
        .route("/api/radio", get(radio_json))
        .route("/api/inquiry", get(inquiry_get).post(inquiry_post))
        .route("/api/events", get(events_json).post(events_start))
        .route("/api/events/stop", post(events_stop))
        .route("/api/devices/rename", post(rename_device))
        .route("/api/scan/retry", post(scan_retry))
        .route("/api/scan/pause", post(scan_pause))
        .route("/api/scan/resume", post(scan_resume))
        .route("/api/scan/stop", post(scan_stop))
        .route("/api/scan/status", post(scan_status))
        .route("/api/scan/snapshot", post(scan_snapshot))
        .route("/api/radio/reset", post(radio_reset))
        .route("/api/raw", get(raw_json))
        .route("/api/raw/enable", post(raw_enable))
        .route("/api/raw/disable", post(raw_disable))
        .route("/api/raw/export", get(raw_export))
        .route("/api/raw/stats", get(raw_stats))
        .route("/api/presence", get(presence_json))
        .route("/api/clients", get(clients_json_route))
        .route("/api/share", get(share_get).post(share_post))
        .route("/api/ntfy", get(ntfy_get).post(ntfy_post))
        .route("/api/ntfy/test", post(ntfy_test))
        .route("/api/info", get(info_json))
        .route("/api/probe", get(probe_get).post(probe_post))
        .route("/api/known", get(known_get))
        .route("/api/known/follow", post(known_follow))
        .route("/api/known/unfollow", post(known_unfollow))
        .route("/api/devices/ignore", post(ignore_post))
        .route("/api/devices/unignore", post(unignore_post))
        .route("/api/devices/ignored", get(ignored_get))
        .route("/api/devices/ignored/clear", post(ignored_clear))
        .route("/api/devices/is-me", post(is_me_post))
        .route("/api/devices/is-me/clear", post(is_me_clear))
        .route("/api/report", get(report_get))
        // Risorse per l'installazione come app dal telefono. Sono file statici
        // di una ventina di byte: nessuna cache aggressiva, nessun versioning.
        .route("/manifest.json", get(manifest_json))
        .route("/sw.js", get(service_worker))
        .route("/icon-192.png", get(icon_192))
        .route("/icon-512.png", get(icon_512))
        // Ogni richiesta passa dal middleware: registra l'IP del client (solo
        // l'IP, vedi `crate::clients`) cosi' chi espone la dashboard in rete
        // locale puo' sapere chi si e' collegato.
        .layer(axum::middleware::from_fn(record_client))
        .with_state(state.clone());

    let listener_addr = std::net::SocketAddr::new(addr, port);
    logger.log(&format!(
        "dashboard: serving on http://{listener_addr} (refresh every 5s)"
    ));
    // URL raggiungibili: esposti alla pagina via /api/info e copiabili.
    // GetIpAddrTable restituisce tutte le interfacce non-loopback, quindi
    // compaiono anche le IP di tailnet/VPN (es. 100.x.x.x di Tailscale).
    let mut urls: Vec<(String, String)> = Vec::new();
    if addr.is_unspecified() {
        urls.push((format!("http://localhost:{port}"), "locale".to_string()));
        for ip in crate::lan::local_ipv4_addrs() {
            urls.push((format!("http://{ip}:{port}"), ip_label(ip).to_string()));
        }
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m Dashboard: \x1b[33mhttp://localhost:{port}\x1b[0m (locale)"
        );
        for (u, label) in urls.iter().skip(1) {
            crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m   \x1b[33m{u}\x1b[0m ({label})");
        }
    } else {
        urls.push((format!("http://{listener_addr}"), "locale".to_string()));
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Dashboard: \x1b[33mhttp://{listener_addr}\x1b[0m");
    }
    if let Ok(mut u) = state.urls.write() {
        *u = urls;
    }

    // Il server ora e' riavviabile a runtime: l'utente puo' chiedere di
    // condividere la dashboard in rete senza riavviare bluesniff.
    //
    // Il bind e' l'unica cosa che non si puo' cambiare su un socket gia'
    // ascoltato, quindi l'unico modo e' chiudere il server e riaprirlo sulla
    // nuova direzione. Lo facciamo con un canale di shutdown: il task corrente
    // riceve il segnale, chiude il listener e muore, poi ne parte uno nuovo.
    // Il costo e' una manciata di secondi di dashboard non raggiungibile, e lo
    // diciamo all'utente invece di nasconderlo.
    // Il mittente resta in un global, il destinatario va al task: e' il task
    // che ascolta il segnale di chiusura. Invertire i due non funzionerebbe,
    // perche' il Sender non permette di ricostruire il Receiver.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    if let Ok(mut slot) = SHUTDOWN.write() {
        *slot = Some(tx);
    }
    // Il bind avviene **sincronicamente**, prima di tutto il resto. Prima era
    // dentro il `tokio::spawn`, con due conseguenze sbagliate: lo stato
    // dichiarava la porta prima di sapere se il bind era riuscito (e se la
    // porta era occupata, la dashboard si credeva in ascolto su una porta
    // morta), e il messaggio "serving on ..." veniva stampato anche quando il
    // bind falliva di lì a un istante.
    //
    // `std::net::TcpListener::bind` + `from_std` fa lo stesso bind ma in
    // modo sincrono, cosi' l'errore e' qui, ora, e si puo' uscire puliti.
    let std_listener = match std::net::TcpListener::bind(listener_addr) {
        Ok(l) => l,
        Err(e) => {
            logger.log(&format!("dashboard: bind fallito su {listener_addr}: {e}"));
            // Non tocchiamo lo stato: la dashboard precedente, se c'era,
            // continua a valere. Dichiarare una porta non in ascolto farebbe
            // costruire URL e regole di condivisione su un indirizzo morto.
            return Err(format!("cannot bind {listener_addr}: {e}"));
        }
    };
    // Solo ora sappiamo davvero su che porta siamo in ascolto.
    state.set_port(port);
    // `from_std` non tocca il socket: si aspetta gia' non-bloccante, e su un
    // listener bloccante `axum::serve` non riceve mai un evento di readiness,
    // quindi accetterebbe la connessione (il backlog del kernel la fa finire in
    // ESTABLISHED) e non risponderebbe mai. Il sintomo e' una dashboard che
    // "si connette" e resta muta: per questo lo forziamo esplicitamente.
    if let Err(e) = std_listener.set_nonblocking(true) {
        logger.log(&format!("dashboard: set_nonblocking fallito: {e}"));
        return Err(format!("listener non impostato non-bloccante: {e}"));
    }
    let listener = match tokio::net::TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            return Err(format!("listener non utilizzabile: {e}"));
        }
    };

    tokio::spawn(async move {
        let shutdown = async move {
            let _ = rx.await;
        };
        // `into_make_service_with_connect_info` popola l'estensione ConnectInfo
        // che il middleware usa per sapere da quale IP arriva la richiesta:
        // senza, il tracciamento dei client non avrebbe nulla su cui basarsi.
        let serve = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown);
        if let Err(e) = serve.await {
            crate::be!("[BLUESNIFF] dashboard: server error: {e}");
        }
    });

    // Campionamento dei pacchetti BLE ogni 5s per il grafico "la radio
    // respira" del pannello Radio (indipendente dai client connessi).
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut last = crate::blewatcher::packets_received();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let now = crate::blewatcher::packets_received();
                let delta = now.saturating_sub(last);
                last = now;
                if let Ok(mut h) = state.packets.write() {
                    h.push_back(delta as u32);
                    if h.len() > 60 {
                        h.pop_front();
                    }
                }
            }
        });
    }
    Ok(())
}

/// GET / -> pagina HTML della dashboard.
async fn index(State(_state): State<DashboardState>) -> Html<String> {
    Html(INDEX_HTML.to_string())
}

/// GET /api/devices -> JSON con conteggi e dispositivi correnti.
///
/// `?include_ignored=0` esclude dal corpo i dispositivi ignorati. Di default
/// sono inclusi con `ignored: true`, perche' la UI deve poter mostrare il
/// filtro "Ignorati" senza una seconda chiamata. Il parametro esiste per il
/// caso in cui la lista si fa lunga (qualche centinaio di device) e l'utente ne
/// ha ignorati molti: inviare 150 righe che nessuno guardera' costa banda a
/// ogni aggiornamento, e la dashboard interroga questa rotta ogni 5 s.
async fn devices_json(
    State(state): State<DashboardState>,
    axum::extract::Query(q): axum::extract::Query<DevicesQuery>,
) -> axum::Json<serde_json::Value> {
    let include_ignored = q.include_ignored.as_deref() != Some("0");
    let devices = state.devices.read().map(|s| s.clone()).unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut classes: std::collections::BTreeMap<&str, usize> = [
        ("phone", 0),
        ("audio", 0),
        ("wearable", 0),
        ("computer", 0),
        ("vehicle", 0),
        ("iot", 0),
        ("phantom", 0),
        ("other", 0),
    ]
    .into_iter()
    .collect();

    let mut total = 0usize;
    let mut active = 0usize;
    let mut identified = 0usize;
    let mut unknown = 0usize;
    let mut randomized = 0usize;
    let mut watched = 0usize;
    let mut risky = 0usize;
    let mut tracker = 0usize;
    let mut static_devs = 0usize;
    let mut rotating = 0usize;
    let mut new_past_hour = 0usize;
    let mut ignored_count = 0usize;
    // Cache delle sonde (SDP) per il filtro "Con rischi": un dispositivo è
    // rischioso se ha CVE note, annuncio phantom oppure servizi SDP con note
    // di esposizione (MAP/OBEX/PBAP...).
    let probes = state.probes.read().map(|m| m.clone()).unwrap_or_default();

    let mut devs: Vec<serde_json::Value> = Vec::with_capacity(devices.len());
    for d in &devices {
        // Gli ignorati sono fuori da *tutti* i conteggi, non solo da `total`:
        // se "Telefoni: 4" contasse anche un telefono che l'utente ha chiuso
        // con "Ignora", il numero non corrisponderebbe piu' alle righe che
        // vede nella tabella, e il conteggio diventerebbe un'altra lista
        // diversa da quella reale. Contati a parte, cosi' l'utente sa quanti
        // ne ha nascosti senza che il resto dei numeri menta.
        if d.ignored {
            ignored_count += 1;
            if !include_ignored {
                continue;
            }
        }
        // `risky` e `tracker` servono anche alla serializzazione, quindi si
        // calcolano anche per un dispositivo ignorato incluso nel corpo: sono
        // la stessa definizione del filtro, mostrata nella scheda.
        let sdp_risky = probes
            .get(&format!("sdp:{}", d.mac.to_uppercase()))
            .and_then(|p| p.get("risks"))
            .and_then(|r| r.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        let d_risky = !d.cves.is_empty() || d.phantom.is_some() || sdp_risky;
        // "Tracker": annunci stile tag/popup — Apple Continuity, Swift Pair,
        // Samsung EasySetup, Fast Pair (0xFE2C) e Tile (0xFEED): riconosciuti
        // come tracker/spoof anche senza nome pubblicizzato.
        let d_tracker = d.phantom.is_some() || d.model_id.is_some();
        if !d.ignored {
            total += 1;
            if d.active {
                active += 1;
            }
            if d.identified {
                identified += 1;
            } else {
                unknown += 1;
            }
            if d.randomized {
                randomized += 1;
            }
            if d.watched {
                watched += 1;
            }
            if let Some(ts) = rfc3339_epoch(&d.first_seen) {
                if now - ts < 3600 {
                    new_past_hour += 1;
                }
            }
            let key = if classes.contains_key(d.category.as_str()) {
                d.category.as_str()
            } else {
                "other"
            };
            if let Some(c) = classes.get_mut(key) {
                *c += 1;
            }
            if d_risky {
                risky += 1;
            }
            if d_tracker {
                tracker += 1;
            }
            if d.static_dev {
                static_devs += 1;
            }
            if d.rotating {
                rotating += 1;
            }
        }
        let mut v = serde_json::to_value(d).unwrap_or(serde_json::Value::Null);
        if let Some(obj) = v.as_object_mut() {
            obj.insert("risky".to_string(), serde_json::json!(d_risky));
            obj.insert("tracker".to_string(), serde_json::json!(d_tracker));
        }
        devs.push(v);
    }

    axum::Json(serde_json::json!({
        "counts": {
            "total": total,
            "active": active,
            "identified": identified,
            "unknown": unknown,
            "randomized": randomized,
            "watched": watched,
            "ignored": ignored_count,
            "risky": risky,
            "tracker": tracker,
            "static": static_devs,
            "rotating": rotating,
            "new_past_hour": new_past_hour,
            "classes": classes,
        },
        "devices": devs,
    }))
}

/// GET /api/export -> CSV (separatore ';') di tutti i dispositivi correnti.
async fn export_csv(State(state): State<DashboardState>) -> Response {
    let devices = state.devices.read().map(|s| s.clone()).unwrap_or_default();
    let mut out = String::from(
        "mac;nome;vendor;classe;zona;rssi;avvistamenti;primo;ultimo;randomizzato;seguito\n",
    );
    for d in &devices {
        let rssi = d.rssi.map(|v| v.to_string()).unwrap_or_default();
        out.push_str(&format!(
            "{};{};{};{};{};{};{};{};{};{};{}\n",
            d.mac,
            sanitize(&d.name),
            sanitize(&d.vendor),
            d.category,
            d.zone,
            rssi,
            d.sightings,
            d.first_seen,
            d.last_seen,
            if d.randomized { "si" } else { "no" },
            if d.watched { "si" } else { "no" },
        ));
    }
    Response::new(out.into()).with_header("Content-Type", "text/csv; charset=utf-8")
}

fn sanitize(s: &str) -> String {
    s.replace(';', ",").replace('\n', " ")
}

/// GET /api/export/security -> report JSON stile BlueToolkit: per ogni
/// dispositivo con riscontri (CVE note, servizi SDP con note di esposizione,
/// annuncio phantom) riepiloga CVE, servizi e note di esposizione. I
/// dispositivi puliti compaiono solo nel conteggio totale.
async fn export_security(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    let devices = state.devices.read().map(|s| s.clone()).unwrap_or_default();
    let probes = state.probes.read().map(|m| m.clone()).unwrap_or_default();
    let db = crate::cves::db();
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for d in &devices {
        let cves = crate::cves::match_cves(db, d.model_id, &d.name, &d.vendor, "", &d.mac);
        let sdp = probes.get(&format!("sdp:{}", d.mac.to_uppercase()));
        let sdp_services: Vec<serde_json::Value> = sdp
            .and_then(|v| v.get("services"))
            .and_then(|s| s.as_array())
            .map(|a| {
                a.iter()
                    .map(|s| {
                        serde_json::json!({
                            "uuid": format!(
                                "0x{:04X}",
                                s.get("uuid").and_then(|u| u.as_u64()).unwrap_or(0)
                            ),
                            "class": s.get("class_name").and_then(|v| v.as_str()).unwrap_or(""),
                            "protocol": s.get("protocol").and_then(|v| v.as_str()).unwrap_or(""),
                            "service_name": s
                                .get("service_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(""),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let sdp_risks: Vec<serde_json::Value> = sdp
            .and_then(|v| v.get("risks"))
            .and_then(|s| s.as_array())
            .cloned()
            .unwrap_or_default();
        if cves.is_empty() && sdp_services.is_empty() && d.phantom.is_none() {
            continue; // nessun riscontro: conta solo nel totale
        }
        let cve_items: Vec<serde_json::Value> = cves
            .iter()
            .map(|c| {
                serde_json::json!({
                    "cve": c.cve,
                    "vendor": c.vendor,
                    "model": c.model,
                    "description": c.description,
                })
            })
            .collect();
        let exposure: Vec<&str> = sdp_risks
            .iter()
            .filter_map(|r| r.get("title").and_then(|t| t.as_str()))
            .collect();
        findings.push(serde_json::json!({
            "mac": d.mac,
            "name": d.name,
            "vendor": d.vendor,
            "category": d.category,
            "zone": d.zone,
            "phantom": d.phantom,
            "cves": cve_items,
            "sdp_services": sdp_services,
            "sdp_risks": sdp_risks,
            "exposure_notes": exposure,
        }));
    }
    axum::Json(serde_json::json!({
        "report": "bluesniff security summary (per-device, stile BlueToolkit)",
        "generated": crate::logging::utc_now_rfc3339(),
        "device_count": devices.len(),
        "findings_count": findings.len(),
        "devices_with_findings": findings,
    }))
}

/// Query parameter per `/api/heatmap`.
#[derive(serde::Deserialize)]
struct MacQuery {
    mac: String,
}

/// GET /api/heatmap?mac=... -> conteggi di avvistamento per ora (24) e per
/// giorno della settimana (7, Lunedì=0..Domenica=6) letti da `presenze.csv`.
async fn heatmap(
    State(state): State<DashboardState>,
    Query(q): Query<MacQuery>,
) -> axum::Json<serde_json::Value> {
    let Some(path) = state.presenze.clone() else {
        return axum::Json(serde_json::json!({ "available": false, "reason": "no csv" }));
    };
    let mut hours = [0u32; 24];
    let mut days = [0u32; 7];
    let mut total: u32 = 0;

    let mut rdr = match csv::ReaderBuilder::new()
        .delimiter(b';')
        .has_headers(true)
        .from_path(&path)
    {
        Ok(r) => r,
        Err(_) => {
            return axum::Json(serde_json::json!({ "available": false, "reason": "unreadable" }))
        }
    };
    for rec in rdr.records().flatten() {
        if rec.len() < 10 {
            continue;
        }
        if !rec[2].eq_ignore_ascii_case(&q.mac) {
            continue;
        }
        let Some(ts) = rfc3339_epoch(&rec[0]) else {
            continue;
        };
        let hour = ((ts.rem_euclid(86_400)) / 3600) as usize;
        if hour < 24 {
            hours[hour] += 1;
        }
        let wd = ((ts.div_euclid(86_400) + 3).rem_euclid(7)) as usize;
        if wd < 7 {
            days[wd] += 1;
        }
        total += 1;
    }

    axum::Json(serde_json::json!({
        "available": true,
        "mac": q.mac,
        "total": total,
        "hours": hours,
        "days": days,
    }))
}

/// GET /api/radio -> stato dell'adattatore (nome, MAC, on/off) e conteggio
/// dei pacchetti BLE ricevuti dal avvio del processo.
async fn radio_json(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    let radios = crate::radio::list_radios();
    let (rt_name, rt_on) = crate::blewatcher::radio_status().await.unwrap_or_default();
    let packets = crate::blewatcher::packets_received();
    let packet_history: Vec<u32> = state
        .packets
        .read()
        .map(|h| h.iter().copied().collect())
        .unwrap_or_default();
    // Secondi consecutivi senza pacchetti (ogni campione = 5s).
    let silent_secs: u64 = packet_history.iter().rev().take_while(|&&v| v == 0).count() as u64 * 5;
    let silent = silent_secs >= 120;
    // Stima portata del dongle: attenuazione ambiente + portata teorica.
    let range = state
        .pathloss
        .read()
        .map(|p| (p.samples.len(), p.atten_db, p.tx_median, p.range_m))
        .unwrap_or((0, None, None, None));
    let radio_list: Vec<serde_json::Value> = radios
        .iter()
        .map(|r| {
            // Caso comune: una sola radio -> lo stato WinRT vale per lei.
            let state = if radios.len() == 1 {
                if rt_on {
                    "on"
                } else {
                    "off"
                }
            } else {
                "?"
            };
            serde_json::json!({ "name": r.name, "mac": r.address, "state": state })
        })
        .collect();
    // Radio scelta con `--radio`: mostrata nel pannello Radio insieme allo
    // stato della modalità di scansione.
    let selected = crate::radio::selected()
        .map(|r| serde_json::json!({ "index": r.index, "name": r.name, "address": r.address }));
    axum::Json(serde_json::json!({
        "radios": radio_list,
        "selected": selected,
        "packets": packets,
        "packet_history": packet_history,
        "on": rt_on,
        "winrt_name": rt_name,
        "silent": silent,
        "silent_secs": silent_secs,
        "passive": state.passive.load(std::sync::atomic::Ordering::Relaxed),
        "paused": state.paused.load(std::sync::atomic::Ordering::Relaxed),
        "range": {
            "samples": range.0,
            "atten_db": range.1,
            "tx_median": range.2,
            "range_m": range.3,
        },
    }))
}

/// GET /api/info -> URL raggiungibili del listener (per la barra
/// "Collegato a" copiabile nella pagina).
async fn info_json(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    let urls: Vec<(String, String)> = state.urls.read().map(|u| u.clone()).unwrap_or_default();
    // La scelta dell'URL principale (quello del browser corrente) la fa il
    // client: qui basta la lista completa degli URL raggiungibili.
    let list: Vec<serde_json::Value> = urls
        .iter()
        .map(|(u, l)| serde_json::json!({ "url": u, "label": l }))
        .collect();
    axum::Json(serde_json::json!({ "urls": list }))
}

/// Richiesta di sonda (GATT o SDP) dalla scheda dispositivo.
#[derive(serde::Deserialize)]
struct ProbeReq {
    mac: String,
    kind: String,
}

const PROBE_CACHE_CAP: usize = 200;

/// GET /api/probe?mac=..&kind=gatt|sdp -> ultimo risultato memorizzato
/// (None se mai sonata) così la scheda lo ripropone ai refresh.
async fn probe_get(
    State(state): State<DashboardState>,
    axum::extract::Query(params): axum::extract::Query<ProbeReq>,
) -> axum::Json<serde_json::Value> {
    let key = format!(
        "{}:{}",
        params.kind.to_lowercase(),
        params.mac.trim().to_uppercase()
    );
    let value = state.probes.read().ok().and_then(|m| m.get(&key).cloned());
    axum::Json(serde_json::json!({ "result": value }))
}

/// POST /api/probe {mac, kind} -> esegue la sonda (GATT o SDP) in un thread
/// dedicato e salva il risultato. Semi-attiva ma solo in lettura: GATT stampa
/// servizi/characteristic (con Device Information per il modello), SDP elenca
/// i servizi classici del dispositivo (stile bluing `br --sdp`).
async fn probe_post(
    State(state): State<DashboardState>,
    axum::Json(req): axum::Json<ProbeReq>,
) -> axum::Json<serde_json::Value> {
    let kind = req.kind.to_lowercase();
    let mac = req.mac.trim().to_string();
    let value: Option<serde_json::Value> = {
        let mac_gatt = mac.clone();
        let mac_sdp = mac.clone();
        match kind.as_str() {
            "gatt" => tokio::task::spawn_blocking(move || crate::gatt::probe(&mac_gatt))
                .await
                .ok()
                .and_then(|p| serde_json::to_value(p).ok()),
            "sdp" => tokio::task::spawn_blocking(move || crate::sdp::probe(&mac_sdp))
                .await
                .ok()
                .and_then(|p| serde_json::to_value(p).ok()),
            _ => None,
        }
    };
    if let Some(v) = &value {
        store_probe(&state, &kind, &mac, v);
    }
    axum::Json(serde_json::json!({
        "ok": value.is_some(),
        "kind": kind,
        "mac": mac,
        "result": value,
    }))
}

/// Salva un risultato di sonda (GATT/SDP) nella cache condivisa, chiave
/// `kind:MAC`. Usato sia da POST /api/probe sia dall'auto-SDP di --listen.
pub fn store_probe(state: &DashboardState, kind: &str, mac: &str, value: &serde_json::Value) {
    let key = format!("{}:{}", kind, mac.to_uppercase());
    let Ok(mut m) = state.probes.write() else {
        return;
    };
    let inserted = m.insert(key.clone(), value.clone()).is_none();
    drop(m);
    // Evita la crescita senza fine: oltre il cap escono le voci più vecchie,
    // in ordine di primo inserimento (FIFO), non a caso.
    if let Ok(mut order) = state.probe_order.write() {
        if inserted {
            order.push_back(key.clone());
        }
        while order.len() > PROBE_CACHE_CAP {
            if let Some(old) = order.pop_front() {
                if let Ok(mut m) = state.probes.write() {
                    m.remove(&old);
                }
            }
        }
    }
}

/// Salva l'ultimo risultato dell'inquiry classic nello stato condiviso
/// (chiamata dal loop di `--listen` ad ogni inquiry periodica).
pub fn set_inquiry(state: &DashboardState, found: &[crate::btclassic::ClassicDevice]) {
    let devices: Vec<InquiryDevice> = found
        .iter()
        .map(|d| InquiryDevice {
            mac: d.mac.clone(),
            name: d.nome.clone(),
            class: format!("0x{:06X}", d.class_of_device),
            flags: d.flags.clone(),
        })
        .collect();
    let mut snap = state.inquiry.write().unwrap_or_else(|p| p.into_inner());
    snap.devices = devices;
    snap.timestamp = crate::logging::utc_now_rfc3339();
}

fn inquiry_payload(state: &DashboardState) -> serde_json::Value {
    let snap = state.inquiry.read().map(|s| s.clone()).unwrap_or_default();
    serde_json::json!({
        "devices": snap.devices,
        "timestamp": snap.timestamp,
        "count": snap.devices.len(),
    })
}

/// GET /api/inquiry -> ultimo risultato dell'inquiry classic.
async fn inquiry_get(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    axum::Json(inquiry_payload(&state))
}

/// POST /api/inquiry -> esegue subito una inquiry classic fresca (~7s) e
/// restituisce il risultato (pulsante "Ripeti inquiry" del pannello).
async fn inquiry_post(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    let found = tokio::task::spawn_blocking(|| crate::btclassic::inquiry(5))
        .await
        .unwrap_or_default();
    set_inquiry(&state, &found);
    axum::Json(inquiry_payload(&state))
}

/// Percorso del file con il PID del monitor `--inq` avviato dalla dashboard.
fn monitor_pid_path() -> PathBuf {
    crate::logging::exe_dir().join("inq_monitor.pid")
}

/// True se il PID salvato è ancora vivo (controllo via `tasklist`).
fn pid_alive(pid: u32) -> bool {
    let filter = format!("PID eq {pid}");
    match std::process::Command::new("tasklist")
        .args(["/FI", &filter, "/NH"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()),
        Err(_) => false,
    }
}

/// True se il monitor `--inq` avviato dalla dashboard è in esecuzione.
pub fn monitor_running() -> bool {
    let Ok(s) = std::fs::read_to_string(monitor_pid_path()) else {
        return false;
    };
    let Ok(pid) = s.trim().parse::<u32>() else {
        return false;
    };
    pid_alive(pid)
}

/// GET /api/events -> ultimi eventi del monitor `--inq` (letti da
/// `inq_events.jsonl` accanto all'eseguibile, al massimo 50, più recenti
/// per primi) + stato del monitor.
async fn events_json() -> axum::Json<serde_json::Value> {
    let path = crate::logging::exe_dir().join("inq_events.jsonl");
    let events: Vec<serde_json::Value> = match std::fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect(),
        Err(_) => Vec::new(),
    };
    let last: Vec<serde_json::Value> = events.into_iter().rev().take(50).collect();
    axum::Json(serde_json::json!({
        "events": last,
        "monitor_running": monitor_running(),
    }))
}

/// POST /api/events -> avvia il monitor `--inq` come processo separato
/// (stesso eseguibile, uscita ridiretta su `inq_monitor.log`, PID salvato
/// in `inq_monitor.pid`). Gli eventi finiscono in `inq_events.jsonl` che il
/// pannello legge: non serve più aprire un secondo terminale.
async fn events_start(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    if monitor_running() {
        return axum::Json(serde_json::json!({ "ok": true, "running": true, "already": true }));
    }
    let exe =
        std::env::current_exe().unwrap_or_else(|_| crate::logging::exe_dir().join("bluesniff.exe"));
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("--inq");
    let log_path = crate::logging::exe_dir().join("inq_monitor.log");
    if let Ok(f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        if let Ok(clone) = f.try_clone() {
            cmd.stdout(std::process::Stdio::from(f));
            cmd.stderr(std::process::Stdio::from(clone));
        }
    } else {
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: nessuna console
        // condivisa con la dashboard, così chiusa la finestra il monitor vive.
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id();
            let _ = std::fs::write(monitor_pid_path(), pid.to_string());
            if let Ok(mut m) = state.monitor_pid.write() {
                *m = Some(pid);
            }
            axum::Json(serde_json::json!({ "ok": true, "running": true, "pid": pid }))
        }
        Err(e) => axum::Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
    }
}

/// POST /api/events/stop -> ferma il monitor `--inq` avviato dalla dashboard.
async fn events_stop(State(_state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    if let Ok(s) = std::fs::read_to_string(monitor_pid_path()) {
        if let Ok(pid) = s.trim().parse::<u32>() {
            let p = pid.to_string();
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &p])
                .output();
        }
    }
    let _ = std::fs::remove_file(monitor_pid_path());
    axum::Json(serde_json::json!({ "ok": true, "stopped": true }))
}

/// POST /api/devices/rename -> rinomina un dispositivo (persistito in
/// `names.txt`, applicato ai dispositivi già in elenco). Nome vuoto = togli
/// il nome personalizzato e ripristina quello pubblicizzato.
#[derive(serde::Deserialize)]
struct RenameReq {
    mac: String,
    name: String,
}

async fn rename_device(
    State(state): State<DashboardState>,
    axum::Json(req): axum::Json<RenameReq>,
) -> axum::Json<serde_json::Value> {
    let mac_up = req.mac.trim().to_uppercase();
    let name = req.name.trim().to_string();
    {
        let mut map = state.names.write().unwrap_or_else(|p| p.into_inner());
        if name.is_empty() {
            map.remove(&mac_up);
        } else {
            map.insert(mac_up.clone(), name.clone());
        }
    }
    save_names(&state);
    if let Ok(mut devices) = state.devices.write() {
        for d in devices.iter_mut() {
            if d.mac.to_uppercase() == mac_up {
                d.name = name.clone();
                d.identified = !d.name.is_empty() || !d.vendor.is_empty();
            }
        }
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "mac": mac_up,
        "name": name,
    }))
}

/// Richiesta di follow/unfollow su `bt_known.txt`.
#[derive(serde::Deserialize)]
struct FollowReq {
    mac: String,
    /// Nome pubblicizzato: usato solo dal follow (per precompilare la seconda
    /// colonna). L'unfollow lo ignora, perche' non riscrive le altre colonne.
    #[serde(default)]
    name: String,
}

/// Richiesta delle quattro azioni su un singolo MAC: ignora, togli ignore,
/// "sono io", togli "sono io". Un solo tipo per tutti: le quattro operazioni
/// hanno la stessa forma, e quatro struct identici non aggiungono informazione.
#[derive(serde::Deserialize)]
struct MacReq {
    mac: String,
}

/// Query di `/api/devices`: solo `include_ignored` per ora.
#[derive(serde::Deserialize)]
struct DevicesQuery {
    /// `0` esclude gli ignorati dal corpo. Qualunque altro valore (o
    /// l'assenza) li include: il default deve essere quello che serve alla
    /// UI, e la UI vuole poterli mostrare nel filtro dedicato.
    #[serde(default)]
    include_ignored: Option<String>,
}

/// Risposta d'errore dei quattro endpoint: un solo formato, cosi' la UI
/// distingue "ok:false" da "ok:true" senza sapere quale rotta ha chiamato.
fn mac_error(msg: &str) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "ok": false, "error": msg }))
}

/// Query di `/api/report`: stessi nomi dei flag CLI, cosi' un link copiato
/// dalla barra degli indirizzi si riesce a scrivere identico su `--report`.
#[derive(serde::Deserialize)]
struct ReportQuery {
    /// RFC3339 (`2026-09-30T08:00:00Z`).
    from: Option<String>,
    to: Option<String>,
    anonymize: Option<String>,
    /// `0` esclude la tabella completa in appendice.
    appendix: Option<String>,
}

/// GET /api/report -> il report HTML come allegato.
///
/// Va in `spawn_blocking` perche' il lavoro e' tutto CPU-bound: parsing del CSV,
/// aggregazione, rendering di una pagina con 147 righe di appendice. Su un
/// file grande (una settimana, o piu' macchine che scrivono nella stessa
/// cartella) sono centinaia di millisecondi, e farli sul runtime avrebbero
/// bloccato **tutte** le altre rotte per quel tempo: la dashboard sembrerebbe
/// impazzita mentre scarica un report.
///
/// `Content-Disposition: attachment` perche' il pulsante e' "scarica", non
/// "apri": un utente che clicca "Report HTML" dalla dashboard vuole il file
/// da mandare via, e un file che si apre in una scheda nuova lo mette in
/// mezzo. Da CLI (`--report-open`) il file si apre, perche' li' la richiesta
/// e' esplicita.
async fn report_get(
    State(state): State<DashboardState>,
    axum::extract::Query(q): axum::extract::Query<ReportQuery>,
) -> Response {
    let parse_ts = |v: &Option<String>, who: &str| -> Result<Option<i64>, String> {
        match v {
            None => Ok(None),
            Some(s) if s.trim().is_empty() => Ok(None),
            Some(s) => crate::logging::parse_rfc3339_millis(s.trim())
                .map(Some)
                .ok_or_else(|| {
                    format!("{who} non e' un timestamp RFC3339: \"{s}\" (es. 2026-09-30T08:00:00Z)")
                }),
        }
    };
    let (from_ms, to_ms) = match (parse_ts(&q.from, "from"), parse_ts(&q.to, "to")) {
        (Ok(f), Ok(t)) => (f, t),
        (Err(e), _) | (_, Err(e)) => {
            // 400 e non un report sbagliato: un timestamp non parseabile
            // significa che l'utente (o un link rotto) ha chiesto qualcosa che
            // non esiste, e produrre "l'ultima settimana" senza dirlo sarebbe
            // peggio di un errore.
            return Response::builder()
                .status(400)
                .header("Content-Type", "text/plain; charset=utf-8")
                .body(axum::body::Body::from(e))
                .unwrap_or_default();
        }
    };
    let cfg = crate::report::ReportConfig {
        from_ms,
        to_ms,
        title: None,
        anonymize: q.anonymize.as_deref() == Some("1") || q.anonymize.as_deref() == Some("true"),
        full_appendix: q.appendix.as_deref() != Some("0"),
    };
    let src = crate::report::Sources {
        presenze: state
            .presenze
            .clone()
            .unwrap_or_else(|| crate::logging::exe_dir().join("presenze.csv")),
        raw_log_dir: crate::logging::exe_dir(),
        known: crate::known::path(),
        inq_events: crate::logging::exe_dir().join("inq_events.jsonl"),
    };
    let built = tokio::task::spawn_blocking(move || {
        let report = crate::report::build_from(&cfg, &src)?;
        let html = crate::report::render_html(&report);
        let stamp = crate::logging::rfc3339_millis(report.generated_ms)
            .get(0..16)
            .unwrap_or("")
            .replace(['-', ':'], "")
            .replace('T', "-");
        Ok::<(String, String), String>((html, format!("bluesniff-report-{stamp}.html")))
    })
    .await
    .map_err(|e| format!("generazione interrotta: {e}"))
    .and_then(|r| r);
    match built {
        Ok((html, filename)) => Response::builder()
            .header("Content-Type", "text/html; charset=utf-8")
            .header(
                "Content-Disposition",
                format!("attachment; filename=\"{filename}\""),
            )
            .header("Cache-Control", "no-store")
            .body(axum::body::Body::from(html))
            .unwrap_or_default(),
        Err(e) => Response::builder()
            .status(400)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(axum::body::Body::from(e))
            .unwrap_or_default(),
    }
}

/// POST /api/devices/ignore {mac} -> aggiunge a `ignore.txt`.
///
/// Risponde anche `was_watched`: se il dispositivo e' anche seguito, la UI lo
/// dice e propone di togliere il follow. **Ignorare non toglie il follow** di
/// sua initiative: "non voglio vederlo" e "voglio le notifiche" sono due
/// desideri che l'utente ha espresso separatamente, e togliere il secondo
/// senza che lo chieda sarebbe decidere al posto suo. Il pulsante che lo
/// toglie c'e', e chiede conferma.
async fn ignore_post(
    State(state): State<DashboardState>,
    axum::Json(req): axum::Json<MacReq>,
) -> axum::Json<serde_json::Value> {
    let path = crate::ignore::path();
    if let Err(e) = crate::ignore::ignore(&path, &req.mac) {
        return mac_error(&format!("scrittura ignore.txt fallita: {e}"));
    }
    let mac_up = req.mac.trim().to_uppercase();
    let mut was_watched = false;
    if let Ok(mut devices) = state.devices.write() {
        for d in devices.iter_mut() {
            if d.mac.to_uppercase() == mac_up {
                d.ignored = true;
                was_watched = d.watched;
            }
        }
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "ignored": true,
        "was_watched": was_watched,
        "path": path.display().to_string(),
    }))
}

/// POST /api/devices/unignore {mac} -> toglie il MAC da `ignore.txt`.
///
/// Non tocca `bt_known.txt`: se il dispositivo era anche seguito, continua a
/// esserlo. "Togli ignore" non significa "smetti di seguire".
async fn unignore_post(
    State(state): State<DashboardState>,
    axum::Json(req): axum::Json<MacReq>,
) -> axum::Json<serde_json::Value> {
    match crate::ignore::unignore(&crate::ignore::path(), &req.mac) {
        Ok(_) => {
            let mac_up = req.mac.trim().to_uppercase();
            if let Ok(mut devices) = state.devices.write() {
                for d in devices.iter_mut() {
                    if d.mac.to_uppercase() == mac_up {
                        d.ignored = false;
                    }
                }
            }
            axum::Json(serde_json::json!({ "ok": true, "ignored": false }))
        }
        Err(e) => mac_error(&format!("scrittura ignore.txt fallita: {e}")),
    }
}

/// GET /api/devices/ignored -> la lista per il pannello di pulizia.
///
/// Va letta dal file, non dallo stato live: un MAC ignorato e poi sparito
/// dalla tabella resta in `ignore.txt` (e va potuto togliere da li'), mentre
/// uno presente in `ignore.txt` ma mai visto in questa sessione non e' nel
/// vivo ma e' comunque da togliere.
async fn ignored_get() -> axum::Json<serde_json::Value> {
    let path = crate::ignore::path();
    let macs = crate::ignore::load(&path);
    axum::Json(serde_json::json!({
        "count": macs.len(),
        "macs": macs,
        "path": path.display().to_string(),
    }))
}

/// POST /api/devices/ignored/clear -> svuota `ignore.txt`, tiene i commenti.
async fn ignored_clear(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    match crate::ignore::unignore_all(&crate::ignore::path()) {
        Ok(n) => {
            if let Ok(mut devices) = state.devices.write() {
                for d in devices.iter_mut() {
                    d.ignored = false;
                }
            }
            axum::Json(serde_json::json!({ "ok": true, "removed": n }))
        }
        Err(e) => mac_error(&format!("scrittura ignore.txt fallita: {e}")),
    }
}

/// POST /api/devices/is-me {mac} -> dichiara questo dispositivo come proprio.
///
/// Uno solo alla volta: il file contiene un MAC e viene sovrascritto. Se
/// c'era gia' un "sono io", la risposta riporta il vecchio MAC cosi' la UI puo'
/// dire "prima era X, ora e' Y" invece di lasciare il dubbio.
async fn is_me_post(
    State(state): State<DashboardState>,
    axum::Json(req): axum::Json<MacReq>,
) -> axum::Json<serde_json::Value> {
    let path = crate::mine::path();
    let previous = crate::mine::get(&path);
    if let Err(e) = crate::mine::set(&path, &req.mac) {
        return mac_error(&format!("scrittura is_me.txt fallita: {e}"));
    }
    let want = crate::fsx::normalize_mac(&req.mac);
    if let Ok(mut devices) = state.devices.write() {
        for d in devices.iter_mut() {
            d.is_me = d.mac.to_uppercase() == want;
        }
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "is_me": want,
        "previous": previous,
        "path": path.display().to_string(),
    }))
}

/// POST /api/devices/is-me/clear -> nessun dispositivo e' "sono io".
async fn is_me_clear(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    match crate::mine::clear(&crate::mine::path()) {
        Ok(_) => {
            if let Ok(mut devices) = state.devices.write() {
                for d in devices.iter_mut() {
                    d.is_me = false;
                }
            }
            axum::Json(serde_json::json!({ "ok": true, "is_me": null }))
        }
        Err(e) => mac_error(&format!("scrittura is_me.txt fallita: {e}")),
    }
}

/// GET /api/known -> lista dei dispositivi seguiti, con il percorso del file.
///
/// Espone il path perche' la UI possa dire all'utente dove trovarlo quando
/// vuole aggiungere la colonna Persona a mano.
async fn known_get() -> axum::Json<serde_json::Value> {
    let path = crate::known::path();
    let list = crate::known::list(&path);
    let devices: Vec<serde_json::Value> = list
        .iter()
        .map(|k| serde_json::json!({ "mac": k.mac, "nome": k.nome, "persona": k.persona }))
        .collect();
    axum::Json(serde_json::json!({
        "path": path.display().to_string(),
        "count": devices.len(),
        "devices": devices,
    }))
}

/// POST /api/known/follow {mac, name?} -> aggiunge a `bt_known.txt` e marca il
/// dispositivo come seguito nella lista live.
///
/// Il riflesso in memoria serve a far comparire la stella subito: attendere la
/// prossima finestra BLE (5 s) per vedere la stella sarebbe sembrato un
/// pulsante rotto. Il loop di ascolto rilegge il file entro `ACTIVE_EVERY`
/// cicli, quindi il probe classic parte senza riavviare il processo.
async fn known_follow(
    State(state): State<DashboardState>,
    axum::Json(req): axum::Json<FollowReq>,
) -> axum::Json<serde_json::Value> {
    let path = crate::known::path();
    if let Err(e) = crate::known::follow(&path, &req.mac, &req.name) {
        return axum::Json(serde_json::json!({
            "ok": false,
            "error": format!("scrittura bt_known.txt fallita: {e}"),
        }));
    }
    let mac_up = req.mac.trim().to_uppercase();
    if let Ok(mut devices) = state.devices.write() {
        for d in devices.iter_mut() {
            if d.mac.to_uppercase() == mac_up {
                d.watched = true;
            }
        }
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "watched": true,
        "path": path.display().to_string(),
    }))
}

/// POST /api/known/unfollow {mac} -> toglie la riga da `bt_known.txt`.
async fn known_unfollow(
    State(state): State<DashboardState>,
    axum::Json(req): axum::Json<FollowReq>,
) -> axum::Json<serde_json::Value> {
    match crate::known::unfollow(&crate::known::path(), &req.mac) {
        Ok(_) => {
            let mac_up = req.mac.trim().to_uppercase();
            if let Ok(mut devices) = state.devices.write() {
                for d in devices.iter_mut() {
                    if d.mac.to_uppercase() == mac_up {
                        d.watched = false;
                    }
                }
            }
            axum::Json(serde_json::json!({ "ok": true, "watched": false }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "ok": false,
            "error": format!("scrittura bt_known.txt fallita: {e}"),
        })),
    }
}

/// POST /api/scan/retry -> riavvia subito una finestra BLE (5s) + una
/// inquiry classic, aggiorna lo stato e restituisce l'esito. Usato dal
/// pulsante "Riprova scansione" del pannello Radio quando la radio è muta.
async fn scan_retry(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    let seen = tokio::task::spawn_blocking(|| {
        crate::blewatcher::scan_window_blocking(std::time::Duration::from_secs(5), false)
    })
    .await
    .unwrap_or_default();
    update(&state, &seen, &[]);
    let found = tokio::task::spawn_blocking(|| crate::btclassic::inquiry(3))
        .await
        .unwrap_or_default();
    set_inquiry(&state, &found);
    axum::Json(serde_json::json!({
        "ok": true,
        "ble_unique": seen.len(),
        "classic_found": found.len(),
        "packets": crate::blewatcher::packets_received(),
    }))
}

/// POST /api/scan/pause -> mette in pausa la scansione BLE.
async fn scan_pause(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    state
        .paused
        .store(true, std::sync::atomic::Ordering::Relaxed);
    axum::Json(serde_json::json!({ "ok": true, "paused": true }))
}

/// POST /api/scan/resume -> riprende la scansione BLE.
/// POST /api/radio/reset -> spegne e riaccende la radio Bluetooth (WinRT).
/// Recupera uno scanner LE muto senza riavviare il PC. L'esito torna al
/// browser in `message`, già pronto da mostrare.
async fn radio_reset() -> axum::Json<serde_json::Value> {
    match crate::blewatcher::reset_radio(2).await {
        Ok(msg) => axum::Json(serde_json::json!({ "ok": true, "message": msg })),
        Err(e) => axum::Json(serde_json::json!({ "ok": false, "message": e })),
    }
}

/// POST /api/scan/resume -> riprende la scansione BLE.
async fn scan_resume(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    state
        .paused
        .store(false, std::sync::atomic::Ordering::Relaxed);
    axum::Json(serde_json::json!({ "ok": true, "paused": false }))
}

/// POST /api/scan/stop -> ferma il processo in modo pulito.
///
/// La dashboard non ha un riferimento diretto al flag di shutdown del loop di
/// ascolto: il canale che esiste gia' ed e' pensato per questo e' il file di
/// controllo, che il processo legge ogni secondo. Il ciclo dura dieci
/// secondi, quindi l'arresto avviene entro un ciclo: e' quello che garantisce
/// che `presenze.csv` venga flushato, cosa che `taskkill /F` non fa mai.
async fn scan_stop() -> axum::Json<serde_json::Value> {
    match crate::control::send_command(crate::control::Control::Stop) {
        Ok(()) => axum::Json(serde_json::json!({
            "ok": true,
            "message": "arresto in corso: il processo chiude e libera il PC",
        })),
        Err(e) => axum::Json(serde_json::json!({
            "ok": false,
            "error": format!("impossibile segnalare l'arresto: {e}"),
        })),
    }
}

/// POST /api/scan/status -> stato del processo, letto da `bluesniff.status`.
///
/// Lo stato vive nel processo (c'e' un solo scrittore, il loop di ascolto, e
/// puo' contare i cicli). Qui lo rileggiamo dal file che quello scrive: due
/// copie dello stesso stato divergerebbero alla prima esecuzione.
async fn scan_status() -> axum::Json<serde_json::Value> {
    let path = crate::control::status_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<serde_json::Value>(text.trim()) {
            Ok(v) => axum::Json(v),
            Err(e) => axum::Json(serde_json::json!({
                "ok": false,
                "error": format!("stato illeggibile: {e}"),
            })),
        },
        Err(e) => axum::Json(serde_json::json!({
            "ok": false,
            "error": format!("nessuno stato (serve --listen): {e}"),
        })),
    }
}

/// POST /api/scan/snapshot -> l'ultimo snapshot NDJSON dalla memoria del
/// processo, se c'e'. Il file su disco viene riletto solo come piano B: e'
/// quello che scrive il comando `snapshot` del canale file, e puo' essere di
/// qualche secondo indietro.
async fn scan_snapshot() -> axum::Json<serde_json::Value> {
    let path = crate::control::paths().snapshot();
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) {
            return axum::Json(v);
        }
    }
    // Nessuno snapshot su disco: si chiede al processo e si riprova una volta.
    // Il canale file risponde entro un secondo, e senza questo il pulsante
    // fallirebbe sempre alla prima pressione.
    let _ = crate::control::send_command(crate::control::Control::Snapshot);
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) {
                return axum::Json(v);
            }
        }
    }
    axum::Json(serde_json::json!({
        "ok": false,
        "error": "nessuno snapshot disponibile: serve --listen --json",
    }))
}

#[derive(serde::Deserialize)]
struct RawQuery {
    limit: Option<usize>,
    /// Testo cercato in MAC, nome, vendor ed esadecimale (case-insensitive).
    q: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

/// GET /api/raw?limit=200&q=&from=&to= -> stato del log raw (on/off,
/// contatori, file attivo) + i pacchetti che corrispondono alla ricerca
/// nell'intervallo. Il filtro gira lato server: senza questo, cliccando un
/// dispositivo dalle statistiche non si trovava nulla, perché la tabella
/// mostrava solo gli ultimi N pacchetti e non il device richiesto.
async fn raw_json(Query(q): Query<RawQuery>) -> axum::Json<serde_json::Value> {
    let limit = q.limit.unwrap_or(300).clamp(1, 2_000);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let from_ms = q
        .from
        .as_deref()
        .and_then(crate::logging::parse_rfc3339_millis)
        .unwrap_or(0);
    let to_ms = match q.to.as_deref() {
        None | Some("") | Some("now") => now_ms,
        Some(s) => crate::logging::parse_rfc3339_millis(s).unwrap_or(now_ms),
    };
    let (to_ms, from_ms) = if to_ms < from_ms {
        (from_ms, to_ms)
    } else {
        (to_ms, from_ms)
    };

    let lines = crate::rawlog::query(from_ms, to_ms, q.q.as_deref(), limit);
    let events: Vec<serde_json::Value> = lines
        .iter()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    axum::Json(serde_json::json!({
        "enabled": crate::rawlog::enabled(),
        "recorded": crate::rawlog::recorded(),
        "dropped": crate::rawlog::dropped(),
        "file": crate::rawlog::active_file_name(),
        "file_size": crate::rawlog::active_file_size(),
        "rotate_bytes": crate::rawlog::ROTATE_BYTES,
        "retention_days": crate::rawlog::RETENTION_DAYS,
        "events": events,
    }))
}

/// GET /api/raw/stats?from=&to= -> statistiche aggregate per dispositivo
/// nell'intervallo (pacchetti, RSSI, payload distinti, cadenza). La vista che
/// serve a chi studia un device: quanti pacchetti, con che segnale, con
/// quanti payload diversi, ogni quanti millisecondi.
async fn raw_stats(Query(q): Query<RawStatsQuery>) -> axum::Json<serde_json::Value> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let from_ms = q
        .from
        .as_deref()
        .and_then(crate::logging::parse_rfc3339_millis)
        .unwrap_or(0);
    let to_ms = match q.to.as_deref() {
        None | Some("") | Some("now") => now_ms,
        Some(s) => crate::logging::parse_rfc3339_millis(s).unwrap_or(now_ms),
    };
    let (to_ms, from_ms) = if to_ms < from_ms {
        (from_ms, to_ms)
    } else {
        (to_ms, from_ms)
    };
    axum::Json(serde_json::json!({
        "from": crate::logging::rfc3339_millis(from_ms),
        "to": crate::logging::rfc3339_millis(to_ms),
        "devices": crate::rawlog::stats_json(from_ms, to_ms),
    }))
}

#[derive(serde::Deserialize)]
struct RawStatsQuery {
    from: Option<String>,
    to: Option<String>,
}

/// GET /api/presence?silent_minutes=10&min_packets=3&from=&to=
/// -> stato di salute del radio + i dispositivi che non rivediamo da N
/// minuti, ciascuno con il motivo.
///
/// Il campo `reliable` e `radio.health` sono la parte importante: se il
/// canale LE e' muto o l'adapter e' assente, "il dispositivo e' sparito" non e'
/// un fatto ma un artefatto della nostra osservazione, e la risposta lo dice
/// esplicitamente invece di presentarlo come un allarme.
async fn presence_json(Query(q): Query<PresenceQuery>) -> axum::Json<serde_json::Value> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let from_ms = q
        .from
        .as_deref()
        .and_then(crate::logging::parse_rfc3339_millis)
        .unwrap_or(0);
    let to_ms = match q.to.as_deref() {
        None | Some("") | Some("now") => now_ms,
        Some(s) => crate::logging::parse_rfc3339_millis(s).unwrap_or(now_ms),
    };
    let (to_ms, from_ms) = if to_ms < from_ms {
        (from_ms, to_ms)
    } else {
        (to_ms, from_ms)
    };
    let cfg = crate::presence::PresenceConfig {
        min_packets: q.min_packets.unwrap_or(3).clamp(1, 10_000),
        silent_minutes: q.silent_minutes.unwrap_or(10).clamp(1, 10_000),
        ..Default::default()
    };
    let lines = crate::rawlog::iter_lines_in_range(from_ms, to_ms);
    let health = crate::radiostate::health(cfg.radio_stale_ms);
    let missing = crate::presence::missing(&lines, now_ms, &cfg);
    let observations = crate::presence::observe(&lines);
    let groups = crate::presence::seed_groups(&observations);
    let counts = crate::presence::seed_mac_counts(&observations);
    axum::Json(serde_json::json!({
        "from": crate::logging::rfc3339_millis(from_ms),
        "to": crate::logging::rfc3339_millis(to_ms),
        "now": crate::logging::rfc3339_millis(now_ms),
        "config": {
            "min_packets": cfg.min_packets,
            "silent_minutes": cfg.silent_minutes,
            "radio_stale_ms": cfg.radio_stale_ms,
        },
        "radio": crate::radiostate::snapshot(cfg.radio_stale_ms),
        "missing": crate::presence::missing_json(&missing, health, now_ms),
        // Badge per riga: sotto quanti indirizzi diversi e' comparso il blob
        // Continuity di questo MAC. Non fondiamo le righe, diamo il contesto.
        "seed_counts": counts
            .into_iter()
            .map(|(mac, info)| {
                (
                    mac,
                    serde_json::json!({ "seed": info.seed, "mac_count": info.mac_count }),
                )
            })
            .collect::<std::collections::HashMap<_, _>>(),
        "continuity_groups": groups.iter().map(|g| serde_json::json!({
            "seed": g.seed,
            "seed_short": &g.seed[..g.seed.len().min(12)],
            "macs": g.macs,
            "mac_count": g.macs.len(),
            "first_seen": crate::logging::rfc3339_millis(g.first_seen_ms),
            "last_seen": crate::logging::rfc3339_millis(g.last_seen_ms),
        })).collect::<Vec<_>>(),
    }))
}

#[derive(serde::Deserialize)]
struct PresenceQuery {
    from: Option<String>,
    to: Option<String>,
    /// Minuti di silenzio oltre i quali il dispositivo e' considerato sparito.
    silent_minutes: Option<i64>,
    /// Pacchetti minimi per considerare noto un dispositivo.
    min_packets: Option<usize>,
}

/// POST /api/raw/enable -> accende la registrazione raw a runtime.
async fn raw_enable() -> axum::Json<serde_json::Value> {
    crate::rawlog::set_enabled(true);
    axum::Json(serde_json::json!({ "ok": true, "enabled": true }))
}

/// POST /api/raw/disable -> spegne la registrazione raw a runtime (la
/// scansione BLE continua; solo il log si ferma).
async fn raw_disable() -> axum::Json<serde_json::Value> {
    crate::rawlog::set_enabled(false);
    axum::Json(serde_json::json!({ "ok": true, "enabled": false }))
}

#[derive(serde::Deserialize)]
struct RawExportQuery {
    /// RFC3339 con o senza millisecondi (UTC). Vuoto = epoch (inizio).
    from: Option<String>,
    /// RFC3339. Vuoto o "now" = adesso.
    to: Option<String>,
    /// "csv" (default) o "jsonl".
    format: Option<String>,
}

/// GET /api/raw/export?from=…&to=…&format=csv|jsonl -> file da scaricare con
/// gli eventi nell'intervallo richiesto. `to` vuoto significa "adesso".
async fn raw_export(Query(q): Query<RawExportQuery>) -> Response {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let from_ms = q
        .from
        .as_deref()
        .and_then(crate::logging::parse_rfc3339_millis)
        .unwrap_or(0);
    let to_ms = match q.to.as_deref() {
        None | Some("") | Some("now") => now_ms,
        Some(s) => crate::logging::parse_rfc3339_millis(s).unwrap_or(now_ms),
    };
    let (to_ms, from_ms) = if to_ms < from_ms {
        (from_ms, to_ms)
    } else {
        (to_ms, from_ms)
    };
    let format = match q.format.as_deref() {
        Some("jsonl") => crate::rawlog::ExportFormat::Jsonl,
        Some("pcapng") => crate::rawlog::ExportFormat::Pcapng,
        _ => crate::rawlog::ExportFormat::Csv,
    };
    let (mut body, truncated) = crate::rawlog::export(from_ms, to_ms, format);
    let stamp_a = crate::logging::rfc3339_millis(from_ms)
        .replace(['-', ':'], "")
        .replace(".000Z", "Z");
    let stamp_b = crate::logging::rfc3339_millis(to_ms)
        .replace(['-', ':'], "")
        .replace(".000Z", "Z");
    let (ext, content_type) = match format {
        crate::rawlog::ExportFormat::Csv => ("csv", "text/csv; charset=utf-8"),
        crate::rawlog::ExportFormat::Jsonl => ("jsonl", "application/x-ndjson; charset=utf-8"),
        crate::rawlog::ExportFormat::Pcapng => ("pcapng", "application/vnd.tcpdump.pcap"),
    };
    let filename = format!("bluesniff-raw-{stamp_a}-{stamp_b}.{ext}");
    if truncated {
        // Avviso in testata: il file è stato troncato al tetto di righe
        // (solo formati testuali: il pcapng è binario e non lo tocchiamo).
        let warn = format!(
            "# ATTENZIONE: export troncato a {} righe (aumento della finestra o filtri più stretti)\n",
            crate::rawlog::EXPORT_ROW_CAP
        );
        body.splice(0..0, warn.as_bytes().iter().copied());
    }
    let mut resp = Response::new(axum::body::Body::from(body));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(content_type),
    );
    if let Ok(v) =
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
    {
        resp.headers_mut()
            .insert(axum::http::header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// GET /api/ntfy -> impostazioni di notifica correnti.
async fn ntfy_get(State(state): State<DashboardState>) -> axum::Json<serde_json::Value> {
    let s = state.ntfy.read().map(|s| s.clone()).unwrap_or_default();
    axum::Json(serde_json::json!({
        "enabled": s.enabled,
        "topic": s.topic,
        "server": s.server,
        "arrival": s.notify_arrival,
        "departure": s.notify_departure,
    }))
}

/// GET /manifest.json — manifest PWA: quello che permette di installare la
/// dashboard dal telefono (Aggiungi a schermata Home).
///
/// Nota onesta: le PWA vietano l'installazione automatica senza HTTPS, e qui si
/// serve su `http://192.168.x.x:9000`. Il manifest serve comunque — iOS lo usa
/// per "Aggiungi a schermata Home" anche in chiaro, e su Android l'utente
/// installa dal menu. Nessun dato di scansione passa da qui.
async fn manifest_json() -> Response {
    let body = serde_json::json!({
    "name": "bluesniff",
    "short_name": "bluesniff",
    "description": "Scanner Bluetooth: chi e' vicino al tuo PC, e da quanto tempo",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0d0d0d",
    "theme_color": "#dc2626",
    "icons": [
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable" }
    ]
    })
    .to_string();
    Response::builder()
        .header("Content-Type", "application/manifest+json")
        .header("Cache-Control", "no-store")
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// GET /sw.js — service worker minimale.
///
/// Chrome Android lo pretende per offrire l'installazione, ma qui non deve
/// fare *niente*: i dispositivi cambiano ogni 5 secondi e una cache anche
/// minima mostrerebbe dati vecchi come se fossero freschi, che è il modo
/// migliore per far prendere una decisione sbagliata a qualcuno. Il file è
/// quindi vuoto di comportamento: si installa, non intercetta.
async fn service_worker() -> Response {
    let body = "// bluesniff: service worker vuoto di proposito.\n\
// I dati cambiano ogni 5 secondi: qualunque cache mostrerebbe uno stato\n\
// vecchio come se fosse attuale. Serve solo a rendere installabile la\n\
// dashboard come app su Android.\n\
self.addEventListener('install', () => self.skipWaiting());\n\
self.addEventListener('fetch', () => {});\n";
    Response::builder()
        .header("Content-Type", "application/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// GET /icon-192.png e /icon-512.png — icone incluse nel binario.
///
/// Sono dentro l'eseguibile (`include_bytes!`) e non in `target/`: un'icona
/// mancante farebbe fallire l'installazione, e l'utente non ha modo di
/// accorgersene. 1-4 KB l'uno, generati dal radar del progetto.
async fn icon_192() -> Response {
    icon_response(include_bytes!("assets/icon-192.png"))
}

async fn icon_512() -> Response {
    icon_response(include_bytes!("assets/icon-512.png"))
}

fn icon_response(bytes: &[u8]) -> Response {
    Response::builder()
        .header("Content-Type", "image/png")
        .header("Cache-Control", "public, max-age=86400")
        .body(axum::body::Body::from(bytes.to_vec()))
        .unwrap()
}

/// Corpo di `POST /api/ntfy/test`.
#[derive(serde::Deserialize)]
struct NtfyTestReq {
    topic: String,
    #[serde(default)]
    server: String,
}

/// POST /api/ntfy/test -> invia una notifica di prova e ritorna l'esito reale.
///
/// Non salva niente: il test e' un'anteprima, e l'utente puo' volere provare
/// un topic prima di decidere di adottarlo. Il salvataggio resta su
/// `POST /api/ntfy`.
///
/// La risposta segue la convenzione del progetto: 200 con `{ok: false, error}`
/// invece di un 4xx/5xx. Il client da' un solo significato a `ok`, e trattare
/// "topic sbagliato" come un errore di trasporto finirebbe per mostrargli
/// «errore rete», che non e' quello che e' successo.
async fn ntfy_test(axum::Json(req): axum::Json<NtfyTestReq>) -> axum::Json<serde_json::Value> {
    if let Err(e) = crate::alerts::validate_topic(&req.topic) {
        return axum::Json(serde_json::json!({ "ok": false, "error": e }));
    }
    let server = if req.server.trim().is_empty() {
        "https://ntfy.sh"
    } else {
        req.server.trim()
    };
    if let Err(e) = crate::alerts::validate_server(server) {
        return axum::Json(serde_json::json!({ "ok": false, "error": e }));
    }

    let topic = req.topic.trim();
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC".to_string());
    // Il messaggio non contiene MAC, nomi di dispositivi o dati di
    // `presenze.csv`: solo il fatto che e' un test e da quale stazione arriva,
    // cosi' chi riceve piu' notifiche sa quale delle sue macchine ha scritto.
    let msg = format!(
        "Test di bluesniff\nSe vedi questo messaggio sul telefono, le notifiche funzionano.\nStazione: {host}"
    );
    let url = format!("{}/{}", server.trim_end_matches('/'), topic);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "ok": false,
                "error": format!("Client HTTP non costruibile: {e}"),
            }))
        }
    };

    match client
        .post(&url)
        .header("Title", "bluesniff")
        .header("Tags", "test")
        .body(msg)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => axum::Json(serde_json::json!({
            "ok": true,
            "message": format!("Notifica inviata a \"{topic}\""),
            "topic": topic,
            "server": server,
        })),
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Il corpo di ntfy e' corto, ma un proxy puo' restituire una
            // pagina HTML di errore: 200 caratteri bastano a capire.
            let snippet: String = body.chars().take(200).collect();
            axum::Json(serde_json::json!({
                "ok": false,
                "error": format!("ntfy ha risposto {status}: {snippet}"),
            }))
        }
        Err(e) => {
            // I tre motivi hanno rimedi diversi, quindi si distinguono: un
            // timeout e' quasi sempre un firewall, una connessione rifiutata e'
            // un server niente affatto, un DNS fallito un nome sbagliato.
            let reason = if e.is_timeout() {
                "timeout dopo 5s".to_string()
            } else if e.is_connect() {
                format!("connessione fallita: {e}")
            } else {
                e.to_string()
            };
            axum::Json(serde_json::json!({
                "ok": false,
                "error": format!("Invio fallito: {reason}"),
            }))
        }
    }
}

/// POST /api/ntfy -> aggiorna le impostazioni di notifica e le persiste.
///
/// Valida topic e server prima di scrivere: un topic con uno spazio viene
/// accettato dal server di ntfy solo per rispondere 400 a ogni notifica, e
/// l'utente vedrebbe semplicemente che "non arriva niente" senza sapere il
/// motivo. Un campo vuoto non viene validato (le notifiche sono opzionali:
/// un utente che le disattiva deve poter salvare con il campo vuoto).
async fn ntfy_post(
    State(state): State<DashboardState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    if let Some(v) = body.get("topic").and_then(|v| v.as_str()) {
        let t = v.trim();
        if !t.is_empty() {
            if let Err(e) = crate::alerts::validate_topic(t) {
                return axum::Json(serde_json::json!({ "ok": false, "error": e }));
            }
        }
    }
    if let Some(v) = body.get("server").and_then(|v| v.as_str()) {
        let t = v.trim();
        if !t.is_empty() {
            if let Err(e) = crate::alerts::validate_server(t) {
                return axum::Json(serde_json::json!({ "ok": false, "error": e }));
            }
        }
    }
    let mut s = state.ntfy.write().unwrap_or_else(|p| p.into_inner());
    if let Some(v) = body.get("enabled").and_then(|v| v.as_bool()) {
        s.enabled = v;
    }
    if let Some(v) = body.get("topic").and_then(|v| v.as_str()) {
        s.topic = v.trim().to_string();
    }
    if let Some(v) = body.get("server").and_then(|v| v.as_str()) {
        let t = v.trim().to_string();
        if !t.is_empty() {
            s.server = t;
        }
    }
    if let Some(v) = body.get("arrival").and_then(|v| v.as_bool()) {
        s.notify_arrival = v;
    }
    if let Some(v) = body.get("departure").and_then(|v| v.as_bool()) {
        s.notify_departure = v;
    }
    if s.topic.trim().is_empty() {
        s.enabled = false;
    }
    s.save();
    axum::Json(serde_json::json!({ "ok": true }))
}

/// Converte un timestamp RFC3339 (UTC) in epoch secondi (best effort).
///
/// Delegata a `logging::parse_rfc3339_epoch`: un'unica implementazione
/// dell'aritmetica delle date. Qui si toglie solo la parte frazionaria dei
/// secondi, che il parser shared non gestisce.
fn rfc3339_epoch(s: &str) -> Option<i64> {
    let s = s.trim();
    let s = match s.split_once('.') {
        Some((head, _frac)) => head,
        None => s,
    };
    crate::logging::parse_rfc3339_epoch(s)
}

trait WithHeader {
    fn with_header(self, name: &'static str, value: &str) -> Response;
}
impl WithHeader for Response {
    fn with_header(mut self, name: &'static str, value: &str) -> Response {
        if let Ok(v) = value.parse() {
            self.headers_mut().insert(name, v);
        }
        self
    }
}

/// Pagina HTML della dashboard in stile bluehood: tema scuro, monospace,
/// topbar con brand e stato, sidebar con statistiche, filtri, radar e
/// notifiche, tabella ordinabile con ricerca e paginazione, modale di
/// dettaglio con storico RSSI e heatmap da presenze.csv. Tutto inline —
/// nessun file esterno da distribuire.
// Il delimitatore e' r## e non r# perche' nel markup ci sono sequenze come
// href="#" (i link "copia"), che chiuderebbero prematurely una raw string
// con un solo cancelletto.
const INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<!-- PWA: permettono di installare la dashboard dal telefono come app
     (Aggiungi a schermata Home). Non cambiano nulla di come funziona: senza
     manifest la pagina resta una pagina, e funziona esattamente come prima. -->
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#dc2626">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="bluesniff">
<link rel="apple-touch-icon" href="/icon-192.png">
<link rel="icon" href="/icon-192.png">
<title>BLUESNIFF // BT Reconnaissance</title>
<style>
:root {
--bg-primary: #0d0d0d;
--bg-secondary: #141414;
--bg-tertiary: #1a1a1a;
--bg-hover: #242424;
--bg-panel: #111111;
--text-primary: #e0e0e0;
--text-secondary: #888888;
--text-muted: #555555;
--accent-red: #dc2626;
--accent-orange: #ea580c;
--accent-amber: #d97706;
--accent-green: #16a34a;
--accent-blue: #2563eb;
--accent-cyan: #0891b2;
--border-color: #2a2a2a;
--border-active: #404040;
--font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', Consolas, monospace;
}
[data-theme="light"] {
--bg-primary: #f5f5f5;
--bg-secondary: #e8e8e8;
--bg-tertiary: #ffffff;
--bg-hover: #d8d8d8;
--bg-panel: #efefef;
--text-primary: #1a1a1a;
--text-secondary: #555555;
--text-muted: #888888;
--border-color: #cccccc;
--border-active: #999999;
}
[data-theme="light"] .type-phone { background: #dbeafe; color: #1d4ed8; }
[data-theme="light"] .type-laptop { background: #ccfbf1; color: #0f766e; }
[data-theme="light"] .type-audio { background: #f3e8ff; color: #7c3aed; }
[data-theme="light"] .type-watch { background: #dcfce7; color: #15803d; }
[data-theme="light"] .type-smart { background: #fef3c7; color: #b45309; }
[data-theme="light"] .type-vehicle { background: #fef9c3; color: #a16207; }
[data-theme="light"] .type-unknown { background: #e5e5e5; color: #555; }
[data-theme="light"] .modal-overlay.active { background: rgba(0, 0, 0, 0.5); }
* { margin: 0; padding: 0; box-sizing: border-box; }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--border-active); }
* { scrollbar-width: thin; scrollbar-color: var(--border-color) transparent; }
body {
font-family: var(--font-mono);
background: var(--bg-primary);
color: var(--text-primary);
min-height: 100vh;
font-size: 13px;
line-height: 1.5;
}
/* Top Bar */
.topbar {
background: var(--bg-secondary);
border-bottom: 1px solid var(--border-color);
padding: 0.5rem 1rem;
display: flex;
justify-content: space-between;
align-items: center;
position: sticky;
top: 0;
z-index: 100;
}
.topbar-left { display: flex; align-items: center; gap: 1.5rem; }
.brand { display: flex; align-items: center; gap: 0.5rem; text-decoration: none; color: inherit; }
.brand-icon { color: var(--accent-red); font-size: 1.1rem; }
.brand-text { font-weight: 700; font-size: 0.9rem; letter-spacing: 0.05em; }
.brand-text span { color: var(--accent-red); }
.topbar-right { display: flex; align-items: center; gap: 1.5rem; }
.status-indicator { display: flex; align-items: center; gap: 0.5rem; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; }
.status-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--accent-green); box-shadow: 0 0 6px var(--accent-green); animation: pulse 2s infinite; }
.status-dot.idle { background: var(--text-muted); box-shadow: none; animation: none; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.timestamp { font-size: 0.7rem; color: var(--text-muted); }
/* Barra "Collegato a" (URL copiabile) */
.share-bar { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; padding: 0.35rem 1rem; font-size: 0.7rem; background: var(--bg-panel); border-bottom: 1px solid var(--border-color); }
.share-label { color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.6rem; }
.share-url { font-family: var(--font-mono, monospace); color: var(--accent-cyan); cursor: pointer; padding: 0.1rem 0.35rem; border: 1px solid var(--border-color); border-radius: 3px; text-decoration: none; }
.share-url:hover { border-color: var(--border-active); background: var(--bg-tertiary); }
.share-tag { font-size: 0.55rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent-cyan); background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 3px; padding: 0.05rem 0.3rem; margin-right: 0.25rem; }
.share-copy { font-size: 0.6rem; padding: 0.2rem 0.5rem; }
.share-feedback { color: var(--accent-green); font-size: 0.65rem; }
/* Pulsante di condivisione in alto: sempre presente, anche da loopback,
   perche' il gallo e uovo della barra originale rendeva impossibile attivare
   la condivisione senza essere gia' entrati da un IP di rete. */
.share-toggle { display: flex; align-items: center; gap: 0.3rem; font-family: var(--font-mono, monospace); font-size: 0.68rem; padding: 0.25rem 0.55rem; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-tertiary); color: var(--text-muted); cursor: pointer; }
.share-toggle:hover { border-color: var(--border-active); color: var(--text-primary); }
.share-toggle.on { color: var(--accent-green); border-color: var(--accent-green); }
.share-toggle.busy { opacity: 0.6; cursor: wait; pointer-events: none; }
.share-pop { position: absolute; right: 1rem; top: 3.1rem; z-index: 60; width: 22rem; max-width: calc(100vw - 2rem); background: var(--bg-panel); border: 1px solid var(--border-active); border-radius: 6px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); padding: 0.75rem; font-size: 0.7rem; }
.share-pop-row { display: flex; justify-content: space-between; gap: 0.5rem; padding: 0.2rem 0; border-bottom: 1px solid var(--border-color); }
.share-pop-row:last-child { border-bottom: none; }
.share-pop-row span:first-child { color: var(--text-muted); }
.share-pop code { font-family: var(--font-mono, monospace); color: var(--accent-cyan); user-select: all; }
.share-pop-note { margin-top: 0.5rem; color: var(--text-muted); line-height: 1.4; }
.share-pop-ok { color: var(--accent-green); }
.share-pop-warn { color: var(--accent-amber); }
.share-modal-url { font-family: var(--font-mono, monospace); font-size: 0.8rem; color: var(--accent-cyan); background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 4px; padding: 0.5rem 0.6rem; word-break: break-all; user-select: all; }
/* Radar ingrandito */
#radar-big svg { width: min(88vw, 70vh); height: auto; display: block; margin: 0 auto; }
/* Finestra più grande per il radar ingrandito: niente scrollbar laterale. */
#radar-modal .modal { max-width: min(96vw, 1100px); max-height: 96vh; }
.radar-dot.hl circle:first-child { fill: var(--accent-amber); }
.radar-dot.hl .hl-ring { fill: none; stroke: var(--accent-amber); stroke-width: 1.5; animation: pulse 1.2s infinite; }
/* Main Layout */
.main { display: grid; grid-template-columns: 280px 1fr; min-height: calc(100vh - 45px); }
/* Sidebar */
.sidebar { background: var(--bg-panel); border-right: 1px solid var(--border-color); padding: 1rem; overflow-y: auto; }
.panel { margin-bottom: 1.5rem; }
.panel-header { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.15em; color: var(--text-muted); margin-bottom: 0.75rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border-color); }
.stat-grid { display: grid; gap: 0.5rem; }
.stat-item { background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 4px; padding: 0.75rem; display: flex; justify-content: space-between; align-items: center; }
.stat-item.stat-filter { cursor: pointer; transition: border-color 0.1s ease, background 0.1s ease; }
.stat-item.stat-filter:hover { background: var(--bg-hover); border-color: var(--border-active); }
.stat-item.stat-filter.active { background: var(--bg-tertiary); border-color: var(--accent-red); box-shadow: inset 0 0 0 1px var(--accent-red); }
.filter-chip { display: inline-block; cursor: pointer; padding: 0.1rem 0.4rem; border-radius: 8px; border: 1px solid var(--border-color); background: var(--bg-tertiary); user-select: none; transition: border-color 0.1s ease, background 0.1s ease; }
.filter-chip:hover { border-color: var(--accent-red); background: var(--bg-hover); }
.filter-chip .clear-x { color: var(--accent-red); font-weight: 700; margin-left: 0.3rem; }
.evt-link { color: var(--accent-cyan); cursor: pointer; text-decoration: underline; text-decoration-style: dotted; }
.stat-label { font-size: 0.7rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }
.stat-value { font-size: 1.25rem; font-weight: 700; }
.stat-value.red { color: var(--accent-red); }
.stat-value.amber { color: var(--accent-amber); }
.stat-value.green { color: var(--accent-green); }
.stat-value.blue { color: var(--accent-blue); }
/* Filters */
.filter-group { display: flex; flex-direction: column; gap: 0.25rem; }
.filter-btn { background: transparent; border: 1px solid transparent; color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.75rem; padding: 0.5rem 0.75rem; text-align: left; cursor: pointer; border-radius: 3px; transition: all 0.1s; display: flex; justify-content: space-between; }
.filter-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
.filter-btn.active { background: var(--bg-tertiary); border-color: var(--accent-red); color: var(--text-primary); }
.filter-count { color: var(--text-muted); font-size: 0.7rem; }
.filter-btn .filter-ico { margin-right: 0.35rem; }
/* Filtri eventi: 5 voci su un rigo che entrano nella colonna sinistra. */
.events-filter-group { display: flex; flex-wrap: nowrap; }
.events-filter-btn { flex: 1 1 0; min-width: 0; justify-content: center; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 0.53rem; padding: 0.22rem 0; }
.events-filter-btn.active { border-color: var(--accent-red); box-shadow: inset 0 0 0 1px var(--accent-red); }
/* Radar */
.radar-panel { background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 4px; padding: 0.5rem; }
.radar-panel svg { width: 100%; height: auto; display: block; }
.radar-outer { fill: none; stroke: var(--border-active); }
.radar-ring { fill: none; stroke: var(--border-color); stroke-dasharray: 2 3; }
.radar-sweep { stroke: var(--accent-red); stroke-width: 1; opacity: 0.5; }
.radar-trace { fill: none; stroke-width: 0.8; opacity: 0.55; }
.radar-trace.immediate { stroke: var(--accent-red); }
.radar-trace.near { stroke: var(--accent-amber); }
.radar-trace.far { stroke: var(--accent-blue); }
.radar-trace.remote { stroke: var(--text-muted); }
.radar-trace.hl { stroke-width: 1.6; opacity: 1; }
.radar-dot { cursor: pointer; }
.radar-dot circle { fill: var(--accent-red); animation: pulse 2s infinite; }
.radar-dot.stale circle { fill: var(--text-muted); animation: none; }
/* Marcatori di minaccia: viola = annuncio popup/phantom, rosso = CVE.
   Hanno la precedenza sul colore base e sullo stato stale. */
.radar-dot.phantom circle { fill: #a855f7; stroke: #c084fc; animation: pulse 2s infinite; }
.radar-dot.cve circle { fill: #ef4444; stroke: #f87171; animation: pulse 1.1s infinite; }
.radar-dot.phantom.cve circle { fill: #d946ef; stroke: #f87171; }
.radar-dot .conn-ring { fill: none; stroke: var(--accent-green); stroke-width: 0.8; stroke-dasharray: 2 1.5; }
.radar-dot text { font-size: 5.5px; fill: var(--text-secondary); pointer-events: none; }
.radar-empty { color: var(--text-muted); font-size: 0.7rem; text-align: center; padding: 1rem 0; }
/* Perdita di collegamento: la spazzata si ferma e la dashboard smette di
   fingersi viva. Senza questo, una UI ferma sembra ancora "scanning". */
.status-dot.off { background: var(--accent-red); box-shadow: 0 0 6px var(--accent-red); animation: none; }
.link-lost { position: fixed; left: 50%; transform: translateX(-50%); top: 0; z-index: 300; background: var(--accent-red); color: #fff; font-size: 0.72rem; font-weight: 600; padding: 0.35rem 1rem; border-radius: 0 0 5px 5px; box-shadow: 0 3px 12px rgba(0,0,0,0.4); display: flex; align-items: center; gap: 0.5rem; }
.link-lost-detail { font-weight: 400; opacity: 0.9; font-family: var(--font-mono, monospace); font-size: 0.65rem; }
/* L'avviso firewall sta in barra, non in un popover che l'utente può chiudere
   senza leggerlo: il sintomo ("non riesco a collegarmi") è diverso da quello
   visibile nel popover, quindi deve essere visibile senza interazione. */
.fw-warn { background: var(--accent-amber, #d97706); }
.radar-offline { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.35rem; background: rgba(0,0,0,0.55); color: var(--accent-red); font-size: 0.75rem; text-align: center; }
/* Il radar spento: pallini e tracce sbagliati, perche' i dati sono vecchi e
   mostrarli con il colore normale sarebbe mentire. */
.radar-frozen .radar-dot circle { animation: none; fill: var(--text-muted); }
.radar-frozen .radar-dot text { opacity: 0.35; }
.radar-frozen .radar-sweep { stroke: var(--text-muted); }
.pkt-chart { display: flex; align-items: flex-end; gap: 2px; height: 40px; margin-top: 0.4rem; }
.pkt-bar { flex: 1; background: var(--accent-amber); border-radius: 1px 1px 0 0; min-height: 2px; opacity: 0.8; transition: height 0.4s ease; }
.pkt-bar:hover { opacity: 1; }
/* Content Area */
.content { padding: 1rem; overflow-y: auto; }
/* Search Bar */
.search-bar { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
.search-input { flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 3px; padding: 0.6rem 0.75rem; color: var(--text-primary); font-family: var(--font-mono); font-size: 0.8rem; }
.search-input:focus { outline: none; border-color: var(--accent-red); }
.search-input::placeholder { color: var(--text-muted); }
.form-input { background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 3px; padding: 0.6rem 0.75rem; color: var(--text-primary); font-family: var(--font-mono); font-size: 0.8rem; width: 100%; }
.form-input:focus { outline: none; border-color: var(--accent-red); }
.kbd { display: inline-block; padding: 0.15rem 0.4rem; font-size: 0.65rem; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 2px; color: var(--text-muted); }
.btn { background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.7rem; padding: 0.6rem 1rem; cursor: pointer; border-radius: 3px; text-transform: uppercase; letter-spacing: 0.05em; transition: all 0.1s; }
.btn:hover { background: var(--bg-hover); color: var(--text-primary); border-color: var(--border-active); }
.btn-primary { background: var(--accent-red); border-color: var(--accent-red); color: white; }
.btn-primary:hover { background: #b91c1c; }
/* Pulsante ⭐ Segui nella scheda dispositivo. Tre stati visivi distinti:
   - non seguito: rosso pieno (btn-primary), invita al click
   - seguito: outline, invita a smettere (azione secondaria)
   - in corso: opaco, disabilitato
   La differenza di "peso visivo" fra i due stati attivi e' voluta: seguire e'
   cio' che l'utente vuole fare il 90% delle volte e deve attirare l'occhio;
   l'unfollow non deve competere per l'attenzione. */
.btn-follow { display: inline-flex; align-items: center; gap: 0.35rem; font-weight: 600; min-width: 9.5rem; justify-content: center; transition: all 0.12s ease; }
.btn-follow.followed { background: transparent; border-color: var(--accent-amber); color: var(--accent-amber); }
.btn-follow.followed:hover { background: rgba(217, 119, 6, 0.12); border-color: var(--accent-amber); }
.btn-follow.busy { opacity: 0.55; cursor: wait; pointer-events: none; }
/* Ignora: l'azione che nasconde è distruttiva per l'elenco, quindi il suo
   stato attivo è grigio e spento (niente colore che gridi "pericolo") e
   l'azione per riprenderlo è ambra, non rosso: ripristinare non è una
   riparazione. */
.btn-ignore { display: inline-flex; align-items: center; gap: 0.35rem; font-weight: 600; min-width: 9.5rem; justify-content: center; transition: all 0.12s ease; }
/* Ignorare nasconde un dispositivo: è l'azione che l'utente potrebbe
   rimpiangere, quindi rosso ma scuro — non il rosso pieno di .btn-primary,
   che è riservato al follow (l'unica azione che attiva qualcosa). */
.btn-ignore.off { background: #7f1d1d; border-color: #991b1b; color: #fecaca; }
.btn-ignore.off:hover { background: #991b1b; }
[data-theme="light"] .btn-ignore.off { background: #b91c1c; border-color: #991b1b; color: #fff; }
[data-theme="light"] .btn-ignore.off:hover { background: #991b1b; }
.btn-ignore.on { background: transparent; border-color: var(--text-muted); color: var(--text-muted); }
.btn-ignore.on:hover { background: rgba(136, 136, 136, 0.14); }
.btn-ignore.busy { opacity: 0.55; cursor: wait; pointer-events: none; }
/* "Sono io": verde, e quando è attivo il bottone non si ri-attiva ma diventa
   un'azione di revoca, perché il file tiene un solo MAC. */
.btn-ismine { display: inline-flex; align-items: center; gap: 0.35rem; font-weight: 600; min-width: 9.5rem; justify-content: center; transition: all 0.12s ease; }
.btn-ismine.on { background: transparent; border-color: var(--accent-green); color: var(--accent-green); }
.btn-ismine.on:hover { background: rgba(22, 163, 74, 0.12); }
.btn-ismine.busy { opacity: 0.55; cursor: wait; pointer-events: none; }
/* Un solo stile per i riscontri delle tre azioni della scheda (follow,
   ignore, is-me): prima era `.follow-feedback` e ora vale per tutte, cosi'
   aggiungere un'azione non significa inventare un'altra classe. */
.feedback { font-size: 0.7rem; font-weight: 600; transition: opacity 0.2s ease; }
.feedback.ok { color: var(--accent-green); }
.feedback.err { color: var(--accent-red); }
.feedback:empty { display: none; }
/* Badge in tabella: 🔇 e 👤. Lo stella del seguito esiste già. */
.badge-cell { font-size: 0.8rem; margin-left: 0.15rem; }
.badge-ignored { opacity: 0.75; }
.badge-me { color: var(--accent-green); }
.ignored-panel-list { max-height: 320px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.3rem; margin: 0.5rem 0; }
.ignored-row { display: flex; align-items: center; gap: 0.5rem; font-family: var(--font-mono); font-size: 0.72rem; padding: 0.3rem 0.4rem; background: var(--bg-tertiary); border-radius: 4px; }
.ignored-row .mac { flex: 1; }
/* Feedback accanto al pulsante. Lo stato e' dato da una classe, non da uno
   style inline: cosi' l'errore "rete giù" non richiede di toccare la stringa
   dell'HTML, e `:empty` evita che resti un'area vuota prima della risposta. */
/* Badge "persona" accanto all'etichetta: dice di chi e' il dispositivo
   seguito, un'informazione che arriva solo da bt_known.txt. */
.follow-persona { display: inline-flex; align-items: center; gap: 0.3rem; font-size: 0.7rem; color: var(--accent-amber); background: rgba(217, 119, 6, 0.10); border: 1px solid rgba(217, 119, 6, 0.35); border-radius: 3px; padding: 0.1rem 0.4rem; margin-left: 0.4rem; text-transform: none; letter-spacing: normal; vertical-align: middle; }
/* Legenda "Come leggere questa dashboard". Un termine per riga, con il
   termine in evidenza e la spiegazione sotto: è un testo da leggere, non
   una tabella da consultare, quindi niente righe alternate. */
.legend-item { padding: 0.55rem 0; border-bottom: 1px solid var(--border-color); }
.legend-item:last-of-type { border-bottom: none; }
.legend-term { font-weight: 600; color: var(--text-primary); margin-bottom: 0.15rem; }
.legend-sub { font-weight: 400; color: var(--text-muted); }
.legend-item b { color: var(--text-primary); }
/* Device Table */
.table-container { background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 4px; overflow: hidden; }
.table-header { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color); }
.table-title { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-secondary); }
.table-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
.device-table { width: 100%; border-collapse: collapse; }
.device-table th { text-align: left; padding: 0.6rem 0.75rem; font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); }
.device-table th.sortable { cursor: pointer; user-select: none; transition: color 0.1s ease, background 0.1s ease; }
.device-table th.sortable:hover { color: var(--text-primary); background: var(--bg-tertiary); }
.device-table th.sortable.active { color: var(--text-primary); background: var(--bg-tertiary); }
.sort-indicator { margin-left: 0.35rem; font-size: 0.6rem; opacity: 0.7; }
.device-table td { padding: 0.6rem 0.75rem; font-size: 0.8rem; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
.device-table tr { cursor: pointer; user-select: none; }
.device-table tr:hover { background: var(--bg-hover); }
.device-table tr:last-child td { border-bottom: none; }
.device-table tr.stale td { opacity: 0.45; }
/* Type badges */
.type-badge { display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.2rem 0.5rem; border-radius: 2px; font-size: 0.7rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.type-phone { background: #1e3a5f; color: #60a5fa; }
.type-laptop { background: #1a3a3a; color: #5eead4; }
.type-audio { background: #3a1e3a; color: #c084fc; }
.type-watch { background: #1e3a2e; color: #4ade80; }
.type-smart { background: #3a2e1e; color: #fbbf24; }
.type-vehicle { background: #3a3a1e; color: #facc15; }
.type-unknown { background: #2a2a2a; color: #888; }
.type-phantom { background: #4a1030; color: #f0a6ff; }
.mac-addr { font-size: 0.75rem; color: var(--text-secondary); letter-spacing: 0.02em; }
.vendor-name { color: var(--text-muted); font-size: 0.75rem; }
.device-name { color: var(--text-primary); }
.zone-pill { font-size: 0.65rem; padding: 0.1rem 0.4rem; border-radius: 8px; background: var(--bg-tertiary); color: var(--text-secondary); border: 1px solid var(--border-color); }
.zone-pill.immediate { background: var(--accent-red); color: #fff; border-color: var(--accent-red); }
.zone-pill.near { background: var(--accent-amber); color: #111; border-color: var(--accent-amber); }
.zone-pill.far { background: var(--accent-blue); color: #fff; border-color: var(--accent-blue); }
.zone-pill.remote { background: var(--bg-tertiary); color: var(--text-muted); }
.sighting-count { font-size: 0.8rem; color: var(--accent-amber); }
.last-seen { font-size: 0.75rem; color: var(--text-muted); }
.last-seen.recent { color: var(--accent-green); }
.watched-star { color: var(--accent-amber); margin-right: 0.25rem; }
/* Badge vulnerabilità note (CVE) */
.cve-badge { display: inline-flex; align-items: center; gap: 0.25rem; font-size: 0.62rem; font-weight: 700; color: #fff; background: var(--accent-red); border: 1px solid var(--accent-red); border-radius: 3px; padding: 0.1rem 0.35rem; margin-left: 0.4rem; cursor: help; letter-spacing: 0.02em; }
.cve-badge:hover { background: var(--accent-amber); border-color: var(--accent-amber); color: #111; }
.cve-section { margin-top: 1rem; border: 1px solid var(--accent-red); border-radius: 4px; padding: 0.6rem 0.7rem; background: var(--bg-tertiary); }
.cve-section-title { font-size: 0.7rem; font-weight: 700; color: var(--accent-red); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.4rem; }
.cve-item { font-size: 0.72rem; color: var(--text-secondary); padding: 0.25rem 0; border-bottom: 1px dashed var(--border-color); }
.cve-item:last-child { border-bottom: none; }
.cve-item .cve-id { color: var(--accent-red); font-weight: 700; font-family: var(--font-mono, monospace); }
/* Pagination */
.pagination-bar { display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; padding: 0.65rem 0.9rem; border-top: 1px solid var(--border-color); background: var(--bg-tertiary); flex-wrap: wrap; }
.pagination-left, .pagination-right { display: flex; align-items: center; gap: 0.45rem; }
.pagination-center { display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; justify-content: center; }
.page-numbers { display: flex; align-items: center; gap: 0.25rem; flex-wrap: wrap; }
.page-number-btn { min-width: 2rem; padding: 0.35rem 0.45rem; font-size: 0.7rem; line-height: 1; }
.page-number-btn.active { background: var(--accent-red); border-color: var(--accent-red); color: #fff; }
.page-ellipsis { color: var(--text-muted); font-size: 0.75rem; padding: 0 0.1rem; }
/* Modal */
.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.85); display: flex; align-items: center; justify-content: center; z-index: 1000; opacity: 0; pointer-events: none; transition: opacity 0.15s; }
.modal-overlay.active { opacity: 1; pointer-events: all; }
.modal { background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 4px; width: 90%; max-width: 700px; max-height: 85vh; overflow-y: auto; }
.modal-header { padding: 1rem; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; background: var(--bg-tertiary); }
.modal-title { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em; }
.modal-close { background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.25rem; line-height: 1; }
.modal-close:hover { color: var(--text-primary); }
.modal-body { padding: 1rem; }
.detail-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.75rem; margin-bottom: 1.5rem; }
.detail-item { background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 3px; padding: 0.75rem; }
.detail-item.full { grid-column: 1 / -1; }
.detail-label { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 0.35rem; }
.detail-value { font-size: 0.85rem; color: var(--text-primary); word-break: break-all; }
.detail-value.mono { font-family: var(--font-mono); }
.detail-value.highlight { color: var(--accent-amber); }
.chart-section { margin-top: 1rem; }
.chart-title { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 0.5rem; }
.rssi-chart { position: relative; height: 80px; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 3px; padding: 0.5rem; overflow: hidden; }
.rssi-chart svg { width: 100%; height: 100%; }
.rssi-line { fill: none; stroke: var(--accent-red); stroke-width: 1.5; }
/* Heatmaps */
.heatmap { background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 3px; padding: 0.75rem; font-size: 0.8rem; }
.heatmap-note { color: var(--text-muted); font-size: 0.7rem; padding: 0.25rem 0; }
.activity-grid { display: grid; gap: 3px; }
.activity-grid.hourly { grid-template-columns: repeat(24, 1fr); }
.activity-grid.daily { grid-template-columns: repeat(7, 1fr); }
.activity-cell { aspect-ratio: 1; border-radius: 2px; background: var(--bg-hover); cursor: pointer; transition: opacity 0.1s; }
.activity-cell:hover { opacity: 0.8; }
.activity-cell.l1 { background: rgba(220, 38, 38, 0.25); }
.activity-cell.l2 { background: rgba(220, 38, 38, 0.5); }
.activity-cell.l3 { background: rgba(220, 38, 38, 0.75); }
.activity-cell.l4 { background: var(--accent-red); }
.activity-labels { display: grid; gap: 3px; margin-top: 2px; font-size: 0.5rem; color: var(--text-muted); text-align: center; }
.activity-labels.hourly { grid-template-columns: repeat(24, 1fr); }
.activity-labels.daily { grid-template-columns: repeat(7, 1fr); }
/* ntfy form */
.ntfy-row { display: flex; align-items: center; gap: 0.5rem; margin: 0.5rem 0; font-size: 0.8rem; }
.ntfy-row input[type="checkbox"] { accent-color: var(--accent-red); width: 1rem; height: 1rem; }
/* Footer */
.footer { text-align: center; padding: 0.75rem; font-size: 0.65rem; color: var(--text-muted); border-top: 1px solid var(--border-color); background: var(--bg-secondary); }
.footer a { color: var(--accent-red); text-decoration: none; }
.footer a:hover { text-decoration: underline; }
.theme-toggle { background: transparent; border: 1px solid var(--border-color); color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.75rem; padding: 0.3rem 0.5rem; cursor: pointer; border-radius: 3px; transition: all 0.1s; }
.theme-toggle:hover { color: var(--text-primary); border-color: var(--border-active); }
/* Responsive */
@media (max-width: 900px) {
.main { grid-template-columns: 1fr; }
.sidebar { display: none; }
}

/* --- Vista da telefono --------------------------------------------------
   Sotto i 700px la tabella a 7 colonne diventa illeggibile, e i filtri
   vivono nella sidebar che e' gia' nascosta. Qui compaiono due pezzi nuovi:
   i chip dei filtri e la lista di card. La scelta del layout e' delegata al
   JS (`isMobile`), perche' una tabella HTML non si trasforma bene in card
   solo con CSS e il risultato sarebbe illeggibile anche per chi lo legge. */
.device-cards { display: none; flex-direction: column; gap: 0.5rem; }
.device-card {
background: var(--bg-panel);
border: 1px solid var(--border-color);
border-radius: 6px;
padding: 0.7rem 0.75rem;
cursor: pointer;
transition: border-color 0.1s ease;
}
.device-card:active { background: var(--bg-hover); border-color: var(--accent-red); }
.device-card.stale { opacity: 0.55; }
.card-header { display: flex; align-items: center; gap: 0.45rem; }
.card-category { font-size: 1.05rem; flex-shrink: 0; }
.card-name { font-weight: 600; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-star { flex-shrink: 0; font-size: 0.85rem; }
.card-mac { font-family: Consolas, monospace; font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.15rem; }
.card-meta { font-size: 0.7rem; color: var(--text-muted); margin-top: 0.1rem; }
.card-badges { display: flex; gap: 0.25rem; flex-wrap: wrap; margin-top: 0.35rem; }
.card-badge { font-size: 0.65rem; padding: 0.1rem 0.35rem; border-radius: 3px; background: var(--bg-tertiary); border: 1px solid var(--border-color); }
.card-badge.cve { background: #7f1d1d; border-color: #dc2626; color: #fecaca; }
.card-badge.phantom { background: #4a1030; border-color: #4a1030; color: #f0a6ff; }
.card-badge.ignored { background: #2a2a2a; color: var(--text-muted); }
.card-badge.me { background: #1e3a5f; border-color: #2563eb; color: #bfdbfe; }
.card-badge.static { background: #123a2c; border-color: #123a2c; color: #8fe8bd; }
.card-badge.rotating { background: #3a3010; border-color: #3a3010; color: #e8d49b; }
.card-footer {
display: flex; justify-content: space-between; align-items: center; gap: 0.4rem;
font-size: 0.7rem; color: var(--text-secondary);
margin-top: 0.45rem; padding-top: 0.4rem; border-top: 1px solid var(--border-color);
}
.card-rssi { font-family: Consolas, monospace; }
.card-sightings, .card-ago { color: var(--text-muted); }
.mobile-chips { display: none; margin-bottom: 0.5rem; }
.mobile-chips-scroll {
display: flex; gap: 0.35rem; overflow-x: auto; padding-bottom: 0.15rem;
scrollbar-width: none; -webkit-overflow-scrolling: touch;
}
.mobile-chips-scroll::-webkit-scrollbar { display: none; }
.mobile-chip {
flex-shrink: 0; padding: 0.4rem 0.7rem; border-radius: 16px;
border: 1px solid var(--border-color); background: var(--bg-tertiary);
color: var(--text-secondary); font-family: Consolas, monospace;
font-size: 0.72rem; white-space: nowrap; cursor: pointer;
}
.mobile-chip.active { background: var(--accent-red); border-color: var(--accent-red); color: #fff; }
.mobile-chip .chip-count { color: var(--text-muted); margin-left: 0.2rem; }
.mobile-chip.active .chip-count { color: rgba(255,255,255,0.85); }
.mobile-stats { display: none; gap: 0.4rem; margin-bottom: 0.4rem; font-size: 0.68rem; color: var(--text-muted); }
.mobile-stats span b { color: var(--text-primary); }

@media (max-width: 700px) {
/* I due layout si escludono a vicenda. Gli stili inline che il JS scrive
   sulle card hanno la precedenza, quindi qui si forza comunque la winner
   con !important: e' il punto in cui il resize deve ricostruire la lista. */
.device-cards { display: flex !important; }
.device-table { display: none !important; }
.mobile-chips, .mobile-stats { display: block; }
.mobile-stats { display: flex; }
.topbar { padding: 0.4rem 0.6rem; }
.brand-text { font-size: 0.8rem; }
/* L'orario e l'ultimo refresh stanno gia' nel footer e nel riquadro stato:
   rubarli e' l'unico modo di far stare i pulsanti in 375px. */
.topbar .timestamp { display: none; }
.share-toggle, .theme-toggle { padding: 0.35rem 0.5rem; font-size: 0.7rem; }
#share-toggle-label { display: none; }
.search-bar { flex-wrap: wrap; }
.search-bar .btn { font-size: 0.7rem; padding: 0.4rem 0.6rem; }
/* I numeri di pagina (1..7 con i puntini) non ci stanno: sul telefono
   servono solo "prec" e "succ", e il "pagina 3/12" resta sopra. */
#page-numbers { display: none; }
.table-actions { display: none; }
/* Il modale a schermo intero e' il comportamento atteso da un'app nativa;
   a meta' schermo con 7 campi non si legge niente. */
.modal { width: 100%; max-width: 100%; max-height: 100vh; margin: 0; border-radius: 0; }
.modal-overlay { align-items: stretch; }
#radar svg, .radar svg { width: 100%; height: auto; }
.radar-dot text { display: none; }
.radar-dot circle { r: 6; }
}
</style>
</head>
<body>
<div class="link-lost" id="link-lost" style="display: none;">⛔ Non piu' collegato al server <span class="link-lost-detail" id="link-lost-detail"></span></div>
<div class="link-lost fw-warn" id="fw-warn" style="display: none; top: 2.2rem;">🔥 Condivisione attiva ma il firewall non è aperto: <span class="link-lost-detail">serve amministratore, vedi il bottone Condividi</span></div>
<header class="topbar">
<div class="topbar-left">
<a href="/" class="brand">
<span class="brand-icon">◉</span>
<span class="brand-text">BLUE<span>SNIFF</span></span>
</a>
</div>
<div class="topbar-right">
<div class="status-indicator">
<div class="status-dot" id="status-dot"></div>
<span id="status-text">In attesa</span>
</div>
<div class="timestamp" id="last-update">--:--:--</div>
<button class="share-toggle" id="help-toggle" onclick="showLegendModal()" title="Cosa significa tutto questo?">❓</button>
<button class="share-toggle" id="share-toggle" onclick="shareOnClick()" title="Condividi la dashboard sulla rete locale">🌐 <span id="share-toggle-label">Condividi</span></button>
<button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" title="Tema chiaro/scuro">☀</button>
</div>
</header>
<div class="share-pop" id="share-pop" style="display: none;"></div>
<div class="share-bar" id="share-bar" style="display: none;">
<span class="share-label">🔗 Collegato a:</span>
<span id="share-urls"></span>
<button class="share-copy" id="share-intranet-btn" onclick="openShareModal()" title="Ottieni un link da condividere con chi è in rete">🔗 Condividi su intranet</button>
<span id="share-feedback" class="share-feedback"></span>
</div>
<div class="main">
<aside class="sidebar">
<div class="panel">
<div class="panel-header">Statistiche</div>
<div class="stat-grid">
<div class="stat-item stat-filter" data-filter="identified" title="Filtra: solo Identificati"><span class="stat-label">Identificati</span><span class="stat-value red" id="stat-identified">--</span></div>
<div class="stat-item stat-filter" data-filter="active" title="Filtra: solo Attivi ora"><span class="stat-label">Attivi ora</span><span class="stat-value green" id="stat-active">--</span></div>
<div class="stat-item stat-filter" data-filter="new" title="Filtra: solo Nuovi nell'ultima ora"><span class="stat-label">Nuovi (1h)</span><span class="stat-value amber" id="stat-new">--</span></div>
<div class="stat-item stat-filter" data-filter="randomized" title="Filtra: solo Randomizzati"><span class="stat-label">Randomizzati</span><span class="stat-value blue" id="stat-randomized">--</span></div>
</div>
</div>
<div class="panel">
<div class="panel-header">Radio</div>
<div id="radio-info" class="radar-empty">Caricamento...</div>
<button class="btn" onclick="openRawModal()" style="width: 100%; margin-top: 0.5rem;">📜 LOG RAW</button>
</div>
<div class="panel">
<div class="panel-header">Inquiry Classic</div>
<div id="inquiry-info" class="radar-empty">Caricamento...</div>
<button class="btn" id="inquiry-run" onclick="runInquiry()" style="width: 100%; margin-top: 0.5rem;">↻ Ripeti inquiry (~7s)</button>
</div>
<div class="panel">
<div class="panel-header">Ultimi eventi (monitor --inq)</div>
<div id="events-summary" class="radar-empty" style="display: none;"></div>
<button class="btn" id="monitor-btn" onclick="toggleMonitor()" style="width: 100%; justify-content: center; padding: 0.35rem; margin-bottom: 0.4rem;" title="Avvia/ferma il monitor --inq come processo separato">▶ Avvia monitor</button>
<div class="filter-group events-filter-group" id="events-filter-group" style="flex-direction: row; gap: 0.2rem; margin-bottom: 0.35rem;">
<button class="filter-btn events-filter-btn active" data-efilter="all" title="Mostra tutti gli eventi">Tutti</button>
<button class="filter-btn events-filter-btn" data-efilter="new" title="Solo nuovi dispositivi">Nuovi</button>
<button class="filter-btn events-filter-btn" data-efilter="packets" title="Solo pacchetti BLE">Pacchetti</button>
<button class="filter-btn events-filter-btn" data-efilter="gone" title="Solo dispositivi spariti">Spariti</button>
<button class="filter-btn events-filter-btn" data-efilter="spam" title="Solo avvisi spam BLE">Spam</button>
</div>
<div id="events-info" class="radar-empty">Caricamento...</div>
</div>
<div class="panel">
<div class="panel-header" style="display: flex; justify-content: space-between; align-items: center;"><span>RADAR</span><button class="btn" onclick="openRadarModal()" title="Ingrandisci il radar" style="padding: 0.1rem 0.4rem; font-size: 0.7rem;">⛶ Ingrandisci</button></div>
<div style="position: relative;"><div class="radar-panel" id="radar" onclick="radarSurfaceClick(event)" title="Clicca per ingrandire" style="cursor: pointer;"><div class="radar-empty">In attesa di dispositivi...</div></div><div class="radar-offline" id="radar-offline" style="display: none;"><div>⛔ Non piu' collegato al server</div><div style="color: var(--text-muted); font-size: 0.65rem;">ultimo dato: <span id="radar-offline-since">--:--:--</span></div></div></div>
<div style="display: flex; gap: 0.8rem; font-size: 0.7rem; color: var(--text-secondary); margin-top: 0.4rem; flex-wrap: wrap; align-items: center;"><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--accent-red);margin-right:0.3rem;box-shadow:0 0 4px var(--accent-red);"></span>attivo</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--text-muted);margin-right:0.3rem;"></span>assente ≥5′</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#a855f7;margin-right:0.3rem;box-shadow:0 0 4px #a855f7;"></span>👻 phantom</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#ef4444;margin-right:0.3rem;box-shadow:0 0 4px #ef4444;"></span>⚠ CVE</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#d946ef;margin-right:0.3rem;border:1.5px solid #f87171;box-shadow:0 0 4px #d946ef;"></span>phantom+CVE</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:11px;height:11px;border-radius:50%;background:transparent;margin-right:0.3rem;border:1.5px dashed var(--accent-green);"></span>🔗 connettibile</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:11px;height:11px;border-radius:50%;background:transparent;margin-right:0.3rem;border:1.5px solid var(--accent-amber);"></span>selezionato</span></div>
</div>
<div class="panel">
<div class="panel-header">Filtra</div>
<div class="filter-group" id="filter-group">
<button class="filter-btn active" data-filter="all">Tutti i dispositivi <span class="filter-count" id="count-all">--</span></button>
<button class="filter-btn" data-filter="active"><span class="filter-ico">🟢</span>Attivi ora <span class="filter-count" id="count-active">--</span></button>
<button class="filter-btn" data-filter="identified"><span class="filter-ico">🔵</span>Identificati <span class="filter-count" id="count-identified">--</span></button>
<button class="filter-btn" data-filter="unknown"><span class="filter-ico">⚪</span>Sconosciuti <span class="filter-count" id="count-unknown">--</span></button>
<button class="filter-btn" data-filter="randomized"><span class="filter-ico">🟠</span>Randomizzati <span class="filter-count" id="count-randomized">--</span></button>
<button class="filter-btn" data-filter="watched"><span class="filter-ico">★</span>Seguiti <span class="filter-count" id="count-watched">--</span></button>
<button class="filter-btn" data-filter="ignored"><span class="filter-ico">🔇</span>Ignorati <span class="filter-count" id="count-ignored">--</span></button>
<button class="filter-btn" data-filter="risk"><span class="filter-ico">⚠</span>Con rischi <span class="filter-count" id="count-risk">--</span></button>
<button class="filter-btn" data-filter="tracker"><span class="filter-ico">🏷</span>Tracker <span class="filter-count" id="count-tracker">--</span></button>
<button class="filter-btn" data-filter="static"><span class="filter-ico">📌</span>Statici <span class="filter-count" id="count-static">--</span></button>
<button class="filter-btn" data-filter="rotating"><span class="filter-ico">🔄</span>Rotanti <span class="filter-count" id="count-rotating">--</span></button>
<div id="watched-empty" style="display: none; padding: 0.5rem; font-size: 0.65rem; color: var(--text-muted); background: var(--bg-tertiary); border-radius: 4px; margin-top: 0.4rem; line-height: 1.5;">Nessun dispositivo seguito.<br>Clicca un dispositivo nella tabella e poi <b>⭐ Segui</b> nella scheda: verrà aggiunto a <code>bt_known.txt</code> e riceverai le notifiche quando arriva o parte.</div>
<div style="margin-top: 0.45rem;"><button class="btn" style="width: 100%; justify-content: center;" onclick="openIgnoredPanel()">🔇 Gestisci ignorati <span id="ignored-count-inline">0</span></button></div>
</div>
</div>
<div class="panel">
<div class="panel-header">Per classe</div>
<div class="filter-group" id="filter-group-class">
<button class="filter-btn" data-filter="phone"><span class="filter-ico">📱</span>Telefoni <span class="filter-count" id="count-phone">--</span></button>
<button class="filter-btn" data-filter="computer"><span class="filter-ico">💻</span>Computer <span class="filter-count" id="count-computer">--</span></button>
<button class="filter-btn" data-filter="audio"><span class="filter-ico">🎧</span>Audio <span class="filter-count" id="count-audio">--</span></button>
<button class="filter-btn" data-filter="wearable"><span class="filter-ico">⌚</span>Orologi <span class="filter-count" id="count-wearable">--</span></button>
<button class="filter-btn" data-filter="iot"><span class="filter-ico">📡</span>IoT <span class="filter-count" id="count-iot">--</span></button>
<button class="filter-btn" data-filter="vehicle"><span class="filter-ico">🚗</span>Veicoli <span class="filter-count" id="count-vehicle">--</span></button>
<button class="filter-btn" data-filter="phantom"><span class="filter-ico">👻</span>Phantom <span class="filter-count" id="count-phantom">--</span></button>
<button class="filter-btn" data-filter="other"><span class="filter-ico">❔</span>Altri <span class="filter-count" id="count-other">--</span></button>
</div>
</div>
<div class="panel">
<div class="panel-header">Display</div>
<button class="filter-btn" id="view-toggle" onclick="toggleViewMode()" style="width: 100%; justify-content: center;">☰ Vista compatta</button>
<button class="filter-btn" id="screenshot-toggle" onclick="toggleScreenshotMode()" style="width: 100%; justify-content: center; margin-top: 0.5rem;">📷 Screenshot Mode</button>
<button class="filter-btn" onclick="openNtfy()" style="width: 100%; justify-content: center; margin-top: 0.5rem;">🔔 Notifiche ntfy</button>
</div>
</aside>
<main class="content">
<div class="search-bar">
<input type="text" class="search-input" id="search" placeholder="Cerca per MAC, vendor o nome...">
<button class="btn" id="export-btn" onclick="exportCsv()">Export CSV</button>
<button class="btn" id="report-btn" onclick="downloadReport()" title="Scarica un report HTML autonomo di tutto il periodo registrato: si apre in qualsiasi browser, si stampa, e si può mandare via email">📄 Report HTML</button>
<button class="btn" id="export-sec-btn" onclick="exportSecurity()">🛡 Report sicurezza</button>
</div>
<!-- Lista card: il layout alternativo a quello della tabella. Nascosta su
     desktop via CSS e riempita dal JS solo quando serve, cosi' sul PC non
     esiste un secondo DOM da mantenere sincronizzato. -->
<div class="device-cards" id="device-cards"></div>
<div class="table-container">
<!-- Visto solo sotto i 700px: la sidebar coi filtri e' gia' nascosta li, e
     senza chip non ci sarebbe modo di filtrare. I conteggi arrivano dagli
     stessi elementi della sidebar, quindi restano allineati per costruzione. -->
<div class="mobile-stats" id="mobile-stats"></div>
<div class="mobile-chips" id="mobile-chips">
<div class="mobile-chips-scroll" id="mobile-chips-scroll"></div>
</div>
<div class="table-header">
<span class="table-title">Dispositivi <span id="visible-count" style="color: var(--text-muted);"></span> <span id="filter-indicator" class="filter-chip" style="color: var(--accent-amber); font-size: 0.7rem; display: none;"></span></span>
<div class="table-actions">
<span style="font-size: 0.7rem; color: var(--text-muted);">Tutto <span class="kbd">1</span> <span class="kbd">2</span> Seguiti · <span class="kbd">3</span> Telefoni · <span class="kbd">4</span> Computer · <span class="kbd">5</span> Audio · <span class="kbd">n</span> ntfy</span>
</div>
</div>
<table class="device-table">
<thead>
<tr>
<th class="sortable" data-sort="class">Classe<span class="sort-indicator"></span></th>
<th class="sortable" data-sort="mac">Indirizzo<span class="sort-indicator"></span></th>
<th class="sortable" data-sort="vendor">Vendor<span class="sort-indicator"></span></th>
<th class="sortable" data-sort="name">Nome<span class="sort-indicator"></span></th>
<th class="sortable" data-sort="rssi">RSSI<span class="sort-indicator"></span></th>
<th class="sortable" data-sort="sightings">Avvistamenti<span class="sort-indicator"></span></th>
<th class="sortable" data-sort="last_seen">Ultimo contatto<span class="sort-indicator"></span></th>
</tr>
</thead>
<tbody id="device-list">
<tr><td colspan="7" style="text-align: center; padding: 2rem; color: var(--text-muted);">In attesa di dati...</td></tr>
</tbody>
</table>
<div class="pagination-bar">
<div class="pagination-left">
<span id="page-info" style="font-size: 0.7rem; color: var(--text-muted);">Pagina --/--</span>
</div>
<div class="pagination-center">
<button class="btn" id="prev-page-btn" onclick="changePage(-1)">Prec</button>
<div class="page-numbers" id="page-numbers"></div>
<button class="btn" id="next-page-btn" onclick="changePage(1)">Succ</button>
</div>
<div class="pagination-right">
<span style="font-size: 0.7rem; color: var(--text-muted);">Righe/pagina</span>
<select class="form-input" id="page-size-select" onchange="changePageSize(this.value)" style="min-width: 4.5rem; padding: 0.4rem 0.5rem; font-size: 0.7rem;">
<option value="25">25</option>
<option value="50" selected>50</option>
<option value="100">100</option>
</select>
</div>
</div>
</div>
</main>
</div>
<footer class="footer">
BLUESNIFF // Framework di ricognizione Bluetooth // <span class="kbd">?</span> Scorciatoie
</footer>
<!-- Modale dettaglio -->
<div class="modal-overlay" id="raw-modal">
<div class="modal" style="max-width: min(96vw, 1200px); max-height: 94vh;">
<div class="modal-header">
<span class="modal-title">📜 LOG RAW — annunci BLE per pacchetto</span>
<button class="modal-close" onclick="closeRawModal()">&times;</button>
</div>
<div class="modal-body">
<div style="display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: flex-end; margin-bottom: 0.8rem;">
<div>
<div style="font-size: 0.65rem; color: var(--text-muted); margin-bottom: 0.2rem;">DA (UTC)</div>
<input type="datetime-local" id="raw-from" step="1" style="background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 4px; padding: 0.35rem; font-size: 0.75rem;">
</div>
<div>
<div style="font-size: 0.65rem; color: var(--text-muted); margin-bottom: 0.2rem;">A (UTC, vuoto = adesso)</div>
<input type="datetime-local" id="raw-to" step="1" style="background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 4px; padding: 0.35rem; font-size: 0.75rem;">
</div>
<div>
<div style="font-size: 0.65rem; color: var(--text-muted); margin-bottom: 0.2rem;">FORMATO</div>
<select id="raw-format" style="background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 4px; padding: 0.35rem; font-size: 0.75rem;">
<option value="csv">CSV</option>
<option value="jsonl">JSONL</option>
<option value="pcapng">PCAPNG (Wireshark)</option>
</select>
</div>
<button class="btn" onclick="rawExport()" style="margin-bottom: 0.1rem;">💾 Esporta intervallo</button>
<button class="btn" onclick="rawRefresh(true)" style="margin-bottom: 0.1rem;">⟳ Aggiorna</button>
<button class="btn" id="raw-toggle-btn" onclick="rawToggle()" style="margin-bottom: 0.1rem;">⏸ Disattiva log</button>
</div>
<div id="raw-status" style="font-size: 0.65rem; color: var(--text-muted); margin-bottom: 0.5rem;"></div>
<div id="raw-radio" style="font-size: 0.68rem; margin-bottom: 0.6rem; padding: 0.4rem 0.5rem; border-radius: 4px; border: 1px solid var(--border-color); font-family: var(--font-mono, monospace); color: var(--text-secondary);">Stato radio: caricamento…</div>
<div id="raw-clients" style="font-size: 0.68rem; margin-bottom: 0.6rem; padding: 0.4rem 0.5rem; border-radius: 4px; border: 1px solid var(--border-color); font-family: var(--font-mono, monospace); color: var(--text-secondary);">Client collegati: caricamento…</div>
<div id="raw-presence-panel" style="margin-bottom: 0.7rem;">
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
<span style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary);">Spariti</span>
<span style="font-size: 0.6rem; color: var(--text-muted);">dispositivi non più visti · si tacita se il radio non sta guardando</span>
</div>
<div id="raw-presence" style="font-size: 0.68rem; font-family: var(--font-mono, monospace); color: var(--text-secondary);">Caricamento…</div>
</div>
<div id="raw-seed-panel" style="margin-bottom: 0.7rem;">
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
<span style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary);">Stesso valore Continuity</span>
<span style="font-size: 0.6rem; color: var(--text-muted);">lo stesso blob Apple sotto indirizzi diversi — correlazione, non identità</span>
</div>
<div id="raw-seeds" style="font-size: 0.68rem; font-family: var(--font-mono, monospace); color: var(--text-secondary);"></div>
</div>
<div id="raw-stats-panel" style="margin-bottom: 0.7rem;">
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
<span style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary);">Per dispositivo</span>
<span style="font-size: 0.6rem; color: var(--text-muted);">clicca un dispositivo per filtrare i pacchetti · la cadenza è la firma del protocollo</span>
</div>
<div id="raw-stats" style="font-size: 0.68rem; font-family: var(--font-mono, monospace); color: var(--text-secondary);">Caricamento…</div>
</div>
<input type="text" id="raw-filter" placeholder="Cerca per MAC, nome, vendor o hex…" oninput="rawDebouncedRefresh()" style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 4px; padding: 0.4rem; font-size: 0.75rem; margin-bottom: 0.5rem;">
<div style="max-height: 55vh; overflow: auto; border: 1px solid var(--border-color); border-radius: 4px;">
<table style="width: 100%; border-collapse: collapse; font-size: 0.68rem; font-family: var(--font-mono, monospace);">
<thead style="position: sticky; top: 0; background: var(--bg-tertiary);">
<tr>
<th style="text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border-color); white-space: nowrap;">ORA (UTC)</th>
<th style="text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border-color);">MAC</th>
<th style="text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border-color);">TIPO</th>
<th style="text-align: right; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border-color);">RSSI</th>
<th style="text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border-color);">HEX</th>
<th style="text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border-color);">DECODIFICA</th>
</tr>
</thead>
<tbody id="raw-tbody"></tbody>
</table>
</div>
<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.4rem;">L'hex è ciò che Windows ha consegnato al watcher (record AD [len][type][data]); se il controller filtra dei payload, qui non compaiono. Aggiornamento automatico ogni 3 s mentre il modale è aperto.</div>
</div>
</div>
</div>

<div class="modal-overlay" id="device-modal">
<div class="modal">
<div class="modal-header">
<span class="modal-title">Scheda dispositivo</span>
<button class="modal-close" onclick="closeModal()">&times;</button>
</div>
<div class="modal-body" id="modal-content"></div>
</div>
</div>
<!-- Modale notifiche -->
<div class="modal-overlay" id="ntfy-modal">
<div class="modal" style="max-width: 520px;">
<div class="modal-header">
<span class="modal-title">Notifiche ntfy</span>
<button class="modal-close" onclick="closeNtfyModal()">&times;</button>
</div>
<div class="modal-body">
<p style="font-size: 0.75rem; color: var(--text-secondary); margin: 0 0 1rem; line-height: 1.5;">
Le notifiche ti avvisano sul telefono quando un dispositivo che <b>segui</b>
(arrivo o partenza). Usano <b>ntfy</b>: un servizio gratuito e senza account.
Se non sai cos'e', il riquadro in fondo spiega tutto in cinque righe.
</p>
<div class="ntfy-row"><input type="checkbox" id="ntfy-enabled"><label for="ntfy-enabled">Notifiche abilitate</label></div>
<div class="detail-label" style="margin-top: 0.75rem;">Topic (il nome del canale su ntfy)</div>
<input type="text" class="form-input" id="ntfy-topic" placeholder="es. mario-rossi-ufficio">
<div id="ntfy-topic-error" style="font-size: 0.65rem; color: var(--accent-red); margin-top: 0.2rem; display: none;"></div>
<div class="detail-label" style="margin-top: 0.75rem;">Server</div>
<input type="text" class="form-input" id="ntfy-server" placeholder="https://ntfy.sh">
<div id="ntfy-server-error" style="font-size: 0.65rem; color: var(--accent-red); margin-top: 0.2rem; display: none;"></div>
<div class="ntfy-row" style="margin-top: 0.75rem;"><input type="checkbox" id="ntfy-arrival"><label for="ntfy-arrival">Avviso di arrivo (il dispositivo torna)</label></div>
<div class="ntfy-row"><input type="checkbox" id="ntfy-departure"><label for="ntfy-departure">Avviso di partenza (scompare per circa 3 minuti)</label></div>
<div style="margin-top: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center;">
<button class="btn btn-primary" onclick="saveNtfy()">Salva</button>
<button class="btn" id="ntfy-test-btn" onclick="testNtfy()">📤 Invia notifica di test</button>
<span id="ntfy-status" style="font-size: 0.75rem; color: var(--accent-green); margin-left: 0.25rem;"></span>
</div>
<details style="margin-top: 1rem; font-size: 0.7rem; color: var(--text-secondary);">
<summary style="cursor: pointer; color: var(--accent-blue); font-weight: 600;">❓ Come funziona ntfy (30 secondi di lettura)</summary>
<ol style="margin-top: 0.5rem; padding-left: 1.2rem; line-height: 1.6;">
<li>Installa l'app <b>ntfy</b> sul telefono: <a href="https://ntfy.sh" target="_blank" rel="noopener">ntfy.sh</a> (Android, iOS o F-Droid).</li>
<li>Scegli un <b>topic</b>: un nome univoco, tipo <code>mario-rossi-ufficio</code>.<br>
<em style="color: var(--accent-amber);">Chi conosce il topic puo' leggere le tue notifiche: scegline uno non indovinabile.</em></li>
<li>Nell'app ntfy, iscriviti al topic (tap «+», inserisci il nome).</li>
<li>Qui sopra scrivi lo stesso topic e premi <b>Salva</b>.</li>
<li>Premi <b>📤 Invia notifica di test</b>: se arriva sul telefono, sei pronto.</li>
</ol>
<p style="color: var(--text-muted); font-size: 0.65rem; margin-top: 0.5rem;">
ntfy e' gratuito, open source e senza account. Puoi anche ospitarlo sul tuo
server: in quel caso cambia solo il campo «Server». Le impostazioni vengono
salvate in ntfy.txt / ntfy_settings.txt accanto all'eseguibile.
</p>
</details>
</div>
</div>
</div>
<!-- Modale scorciatoie -->
<div class="modal-overlay" id="legend-modal">
<div class="modal" style="max-width: 680px;">
<div class="modal-header">
<span class="modal-title">❓ Come leggere questa dashboard</span>
<button class="modal-close" onclick="closeLegendModal()">&times;</button>
</div>
<div class="modal-body" style="padding: 1rem 1.2rem 1.2rem 1.2rem; font-size: 0.78rem; line-height: 1.6; color: var(--text-secondary);">
<p style="margin: 0 0 0.8rem 0; color: var(--text-muted);">bluesniff ascolta gli annunci BLE e interroga i telefoni che segui. Non decodifica comunicazioni, non rompe la randomizzazione dei MAC, non sa dove sei. Qui sotto c'è il vocabolario: quasi tutti i termini strani vengono da come funziona il Bluetooth, non da un difetto.</p>

<div class="legend-item">
<div class="legend-term">🔄 Rotanti — <span class="legend-sub">"N MAC condividono lo stesso fingerprint"</span></div>
<div>Un solo dispositivo fisico che cambia indirizzo. I telefoni moderni ruotano il MAC BLE ogni ~15 minuti per privacy; se un annuncio porta sempre lo stesso payload, <b>quel</b> payload è la sua firma. Bluesniff raggruppa i MAC con la stessa firma e ne conta uno solo. Quindi "🔄 3 MAC" vuol dire <b>un dispositivo visto sotto tre indirizzi</b>, non tre intrusi.</div>
</div>

<div class="legend-item">
<div class="legend-term">🟠 Randomizzati</div>
<div>Il secondo bit del MAC è attivo: è un indirizzo che il dispositivo si è dato da solo invece di quello che gli ha assegnato il produttore. Quasi tutti i telefoni lo fanno, per questo. È una buona notizia, non un sospetto.</div>
</div>

<div class="legend-item">
<div class="legend-term">👻 Phantom</div>
<div>Un tipo di annuncio che Apple, Samsung e Google usano per cose legittime: "Continuity popup", trovare il mio AirTag, Swift Pair, Fast Pair. Bluesniff lo riconosce dalla struttura dell'annuncio. <b>Non è una condanna</b>: essere phantom significa solo "c'è dentro un protocollo proprietario". È però anche la firma che gli spoof BLE imitano, quindi il badge serve a farti notare un caso sospetto, non a dichiararlo.</div>
</div>

<div class="legend-item">
<div class="legend-term">🏷 Tracker</div>
<div>Un sottoinsieme dei phantom: AirTag, SmartTag, Tile, Chipolo, Pebblebee, Find My. Sono dispositivi progettati per essere trovati, quindi li cerchiamo per capire chi li porta. Vederne uno non significa che qualcuno ti sta seguendo: sono comuni in casa, in auto, al lavoro.</div>
</div>

<div class="legend-item">
<div class="legend-term">⚠ Con rischi</div>
<div>Il dispositivo (modello, vendor) combacia una vulnerabilità nota che riguarda come si annuncia in Bluetooth. Esempio: WhisperPair, che permette a chiunque nelle vicinanze di accoppiare il dispositivo al proprio telefono senza conferma. È un avviso sul <b>dispositivo</b>, non su chi ce l'ha.</div>
</div>

<div class="legend-item">
<div class="legend-term">📌 Statici</div>
<div>RSSI che non si muove (varianza quasi nulla su almeno 5 campioni). Quasi sempre è un dispositivo fisso e vicino: antenna, Wi-Fi, TV, un tracker appoggiato a casa. È rumore di fondo, quindi lo escludiamo dai segnali utili.</div>
</div>

<div class="legend-item">
<div class="legend-term">⚫ "Assente da 5′" <span class="legend-sub">sul radar</span></div>
<div>Non è un allarme. Significa solo che da cinque minuti non lo vediamo annunciare. I telefoni smettono di annunciarsi per risparmiare batteria: uno spento, uno in tasca, uno in un'altra stanza dà esattamente questo. Un vero allarme è un'altra cosa: nasce dal <b>probe attivo</b> sui dispositivi che segui, e arriva con una notifica ntfy.</div>
</div>

<div class="legend-item">
<div class="legend-term">📡 Radar — distanza e angolo</div>
<div>La distanza dal centro indica quanto sia <b>vicino a voi</b> (RSSI). L'angolo <b>non è una direzione fisica</b>: è una posizione stabile per ogni dispositivo, scelta solo per non far sovrapporre i puntini. Per la direzione vera servirebbe un'antenna direzionale. La stima in metri è un modello (path-loss a due punti, con attenuazione ambiente), quindi ha un errore di qualche metro: è un ordine di grandezza, non una misura.</div>
</div>

<div class="legend-item">
<div class="legend-term">📐 φ (phi)</div>
<div>Il coefficiente di correlazione di Pearson fra due serie booleane: misura quanto due dispositivi appaiono e spariscono <b>insieme</b>. Vale +1 se sempre insieme, −1 se mai insieme, ~0 se indipendenti. Serve a <code>--track</code> (seguire un MAC nel tempo) e a distinguere "è un dispositivo" da "c'è un altro telefono a casa". Non compaiono nella tabella perché sarebbe rumore per la maggior parte degli utenti.</div>
</div>

<div class="legend-item">
<div class="legend-term">🔗 Connettibili</div>
<div>Il dispositivo si annuncia come <i>general discoverable</i>: accetta nuove connessioni. È un'informazione utile (molti dispositivi lo sono solo quando non hannonessuno connesso) e anche un piccolo avviso di privacy.</div>
</div>

<div class="legend-item">
<div class="legend-term">⭐ Seguiti</div>
<div>Dispositivi che hai scelto tu. Vengono cercati attivamente ogni 60 secondi con un <i>page</i> Bluetooth Classic — funziona anche a schermo spento, perché non richiede pairing — e su di loro scattano le notifiche. È l'unica lista che bluesniff non deduce, ma decide con te.</div>
</div>

<div style="margin-top: 1rem; padding-top: 0.7rem; border-top: 1px solid var(--border-color); font-size: 0.7rem; color: var(--text-muted);">
Cosa <b>non</b> facciamo: non apriamo canali, non deautenticiamo, non leggiamo traffico di altri, non indoviniamo il MAC reale dietro un indirizzo randomizzato. <code>bluesniff --doctor</code> se qualcosa non torna.
</div>
</div>
</div>
</div>

<div class="modal-overlay" id="ignored-modal">
<div class="modal" style="max-width: 520px;">
<div class="modal-header">
<span class="modal-title">🔇 Dispositivi ignorati</span>
<button class="modal-close" onclick="closeIgnoredPanel()">&times;</button>
</div>
<div class="modal-body" style="padding: 1rem;">
<div style="font-size: 0.7rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 0.5rem;">Sono in <code>ignore.txt</code>, uno per riga, e non compaiono più in nessun filtro tranne “Ignorati”. Togliendone uno torna in tabella. <b>L’ignore è per MAC</b>: un dispositivo che cambia indirizzo (telefono con MAC randomizzato, AirTag) va ignorato di nuovo a ogni rotazione.</div>
<div id="ignored-list" class="ignored-panel-list"><div class="detail-value" style="color: var(--text-muted);">Caricamento…</div></div>
<div style="display: flex; gap: 0.5rem; justify-content: flex-end;">
<button class="btn" id="unignore-all-btn" onclick="unignoreAll()">Svuota tutto</button>
<button class="btn btn-primary" onclick="closeIgnoredPanel()">Chiudi</button>
</div>
<div id="ignored-feedback" class="feedback" style="margin-top: 0.4rem;"></div>
</div>
</div>
</div>

<div class="modal-overlay" id="shortcuts-modal">
<div class="modal" style="max-width: 420px;">
<div class="modal-header">
<span class="modal-title">Scorciatoie da tastiera</span>
<button class="modal-close" onclick="closeShortcutsModal()">&times;</button>
</div>
<div class="modal-body" style="padding: 1rem;">
<div style="display: grid; gap: 0.5rem;">
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">/</span><span style="color: var(--text-secondary);">Cerca</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">r</span><span style="color: var(--text-secondary);">Aggiorna</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">c</span><span style="color: var(--text-secondary);">Vista compatta</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">n</span><span style="color: var(--text-secondary);">Notifiche ntfy</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">Esc</span><span style="color: var(--text-secondary);">Chiudi modale</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">1</span><span style="color: var(--text-secondary);">Tutti i dispositivi</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">2</span><span style="color: var(--text-secondary);">Solo seguiti</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">3</span><span style="color: var(--text-secondary);">Telefoni</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid var(--border-color);"><span class="kbd">4</span><span style="color: var(--text-secondary);">Computer</span></div>
<div style="display: flex; justify-content: space-between; padding: 0.4rem 0;"><span class="kbd">5</span><span style="color: var(--text-secondary);">Audio</span></div>
</div>
</div>
</div>
</div>
<!-- Modale radar ingrandito -->
<div class="modal-overlay" id="radar-modal">
<div class="modal" style="max-width: min(96vw, 1100px); max-height: 96vh;">
<div class="modal-header">
<span class="modal-title">RADAR — ingrandito</span>
<button class="modal-close" onclick="closeRadarModal()">&times;</button>
</div>
<div class="modal-body">
<div id="radar-big-info" style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.5rem;"></div>
<div class="radar-panel" id="radar-big"><div class="radar-empty">In attesa di dispositivi...</div></div>
<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.4rem;"><b>L'angolo non indica una direzione fisica</b>: è solo una posizione stabile, scelta una volta per ogni dispositivo, che serve a non far sovrapporre i puntini. La distanza dal centro indica invece quanto sia vicino a voi (RSSI). · clicca un punto per la scheda · la linea chiara traccia lo storico del movimento (colore = zona)</div>
<div style="display: flex; gap: 0.8rem; font-size: 0.7rem; color: var(--text-secondary); margin-top: 0.4rem; flex-wrap: wrap; align-items: center;"><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--accent-red);margin-right:0.3rem;box-shadow:0 0 4px var(--accent-red);"></span>attivo</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--text-muted);margin-right:0.3rem;"></span>assente ≥5′</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#a855f7;margin-right:0.3rem;box-shadow:0 0 4px #a855f7;"></span>👻 phantom</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#ef4444;margin-right:0.3rem;box-shadow:0 0 4px #ef4444;"></span>⚠ CVE</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#d946ef;margin-right:0.3rem;border:1.5px solid #f87171;box-shadow:0 0 4px #d946ef;"></span>phantom+CVE</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:11px;height:11px;border-radius:50%;background:transparent;margin-right:0.3rem;border:1.5px dashed var(--accent-green);"></span>🔗 connettibile</span><span style="display:inline-flex;align-items:center;"><span style="display:inline-block;width:11px;height:11px;border-radius:50%;background:transparent;margin-right:0.3rem;border:1.5px solid var(--accent-amber);"></span>selezionato</span></div>
</div>
</div>
</div>
<!-- Modale condivisione intranet -->
<div class="modal-overlay" id="share-modal">
<div class="modal" style="max-width: 480px;">
<div class="modal-header">
<span class="modal-title">Condividi su intranet</span>
<button class="modal-close" onclick="closeShareModal()">&times;</button>
</div>
<div class="modal-body">
<div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.5rem;">Chiunque sulla rete può aprire questo indirizzo e vedere la dashboard:</div>
<div class="share-modal-url" id="share-modal-url"></div>
<div style="margin-top: 0.75rem; display: flex; gap: 0.5rem; align-items: center;">
<button class="btn btn-primary" onclick="copyShareModalUrl()">📋 Copia</button>
<span id="share-modal-feedback" class="share-feedback"></span>
</div>
<div id="share-modal-note" style="font-size: 0.65rem; color: var(--text-muted); margin-top: 0.75rem;"></div>
</div>
</div>
</div>
</div>
<script>
function applyTheme(theme) {
document.documentElement.setAttribute('data-theme', theme);
const btn = document.getElementById('theme-toggle');
if (btn) btn.textContent = theme === 'light' ? '☽' : '☀';
}
function toggleTheme() {
const current = document.documentElement.getAttribute('data-theme') || 'dark';
const next = current === 'dark' ? 'light' : 'dark';
localStorage.setItem('bluesniff_theme', next);
applyTheme(next);
}
applyTheme(localStorage.getItem('bluesniff_theme') || 'dark');

let allDevices = [];
let currentFilter = 'all';
let compactView = localStorage.getItem('bluesniff_compact_view') === 'true';
let screenshotMode = localStorage.getItem('bluesniff_screenshot_mode') === 'true';
// `?screenshot=1` accende la modalita' da sola: serve a generare le
// immagini della documentazione in modo riproducibile.
const shotParam = new URLSearchParams(location.search).get('screenshot');
if (shotParam === '1') {
screenshotMode = true;
try { localStorage.setItem('bluesniff_screenshot_mode', 'true'); } catch (e) { /* privata */ }
}
let searchTerm = '';
let sortState = { column: 'last_seen', direction: 'desc' };
let pagination = { page: 1, pageSize: 50, totalPages: 1, totalMatching: 0 };
// Sotto i 700px la tabella a 7 colonne non si legge: si passa alle card. E'
// una soglia e non uno stile, perche' la decisione la prende il JS che
// costruisce il markup — una tabella non si trasforma in card con il solo
// CSS senza diventare codice che nessuno riesce a mantenere.
// Il pageSize segue: 50 righe su un telefono sono 50 schermate di scroll.
const mobileMql = window.matchMedia('(max-width: 700px)');
let isMobile = mobileMql.matches;

const TYPE_META = {
phone:  { cls: 'type-phone',   ico: '📱', label: 'Telefono' },
computer:{ cls: 'type-laptop',  ico: '💻', label: 'Computer' },
audio:  { cls: 'type-audio',   ico: '🎧', label: 'Audio' },
wearable:{ cls: 'type-watch',   ico: '⌚', label: 'Orologio' },
iot:    { cls: 'type-smart',   ico: '📡', label: 'IoT' },
vehicle:{ cls: 'type-vehicle', ico: '🚗', label: 'Veicolo' },
phantom:{ cls: 'type-phantom', ico: '👻', label: 'Phantom' },
other:  { cls: 'type-unknown', ico: '❔', label: 'Altro' }
};
const ZONE_CLS = { immediate: 'immediate', near: 'near', far: 'far', remote: 'remote' };

function typeMeta(cat) { return TYPE_META[cat] || TYPE_META.other; }
function escapeHtml(s) {
const div = document.createElement('div');
div.textContent = s == null ? '' : String(s);
return div.innerHTML;
}
function obfuscateMAC(mac) {
if (!screenshotMode || !mac) return mac;
const parts = mac.split(':');
if (parts.length === 6) return parts[0] + ':' + parts[1] + ':XX:XX:XX:XX';
return mac;
}
function obfuscateName(name) {
if (!screenshotMode || !name) return name;
if (name.length <= 2) return '**';
return name.substring(0, 2) + '*'.repeat(Math.min(name.length - 2, 8));
}
// Maschera l'indirizzo IP locale: 192.168.1.28:9000 -> 192.168.x.x:9000.
// Non e' un MAC, ma e' il dato che identifica la *posizione* del computer
// piu' di qualunque altro. Chi e' sulla stessa rete puo' provare a
// raggiungerlo, e in un screenshot finito su un repository pubblico resta
// per sempre.
function obfuscateUrl(url) {
if (!screenshotMode || !url) return url;
return url.replace(/(\d+\.\d+)\.\d+\.\d+(:\d+)?/, '$1.x.x$2');
}
function fmtAgo(ts) {
if (!ts) return '—';
const diff = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
if (diff < 10) return 'adesso';
if (diff < 60) return Math.floor(diff) + 's fa';
if (diff < 3600) return Math.floor(diff / 60) + 'min fa';
if (diff < 86400) return Math.floor(diff / 3600) + 'h fa';
return Math.floor(diff / 86400) + 'g fa';
}
function fmtFull(ts) {
if (!ts) return '—';
return new Date(ts).toLocaleString('it-IT');
}

function updateViewToggle() {
const btn = document.getElementById('view-toggle');
if (btn) btn.innerHTML = compactView ? '◫ Vista dettagliata' : '☰ Vista compatta';
}
function updateScreenshotToggle() {
const btn = document.getElementById('screenshot-toggle');
if (btn) {
btn.innerHTML = screenshotMode ? '📷 Screenshot Mode ON' : '📷 Screenshot Mode';
btn.style.background = screenshotMode ? 'var(--accent-red)' : '';
btn.style.color = screenshotMode ? 'white' : '';
}
}
function toggleViewMode() {
compactView = !compactView;
localStorage.setItem('bluesniff_compact_view', compactView);
updateViewToggle();
render();
}
function toggleScreenshotMode() {
screenshotMode = !screenshotMode;
localStorage.setItem('bluesniff_screenshot_mode', screenshotMode);
updateScreenshotToggle();
render();
}

function setFilter(filter) {
currentFilter = filter;
pagination.page = 1;
document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === filter));
document.querySelectorAll('.stat-item.stat-filter').forEach(s => s.classList.toggle('active', s.dataset.filter === filter));
document.querySelectorAll('.mobile-chip').forEach(c => c.classList.toggle('active', c.dataset.filter === filter));
render();
}

// --- Stato del collegamento con il server ---------------------------------
// Un singolo fetch fallito non significa "server spento": puo' essere una
// richiesta lenta o un'innocua interruzione. Dichiarare la disconnessione al
// primo errore farebbe lampeggiare il banner a ogni scatto lento. Due
// fallimenti consecutivi sono invece un fatto: il server non risponde.
let serverOnline = true;
let failStreak = 0;
let lastGoodAt = null;

function setConnection(ok) {
if (ok) {
failStreak = 0;
if (!serverOnline) {
serverOnline = true;
document.getElementById('link-lost').style.display = 'none';
document.getElementById('radar-offline').style.display = 'none';
// I pallini riprendono il colore vero solo dopo un aggiornamento riuscito,
// non subito: potremmo avere ancora i dati precedenti in memoria.
document.querySelectorAll('.radar-panel').forEach(p => p.classList.remove('radar-frozen'));
document.getElementById('status-dot').classList.remove('off');
}
return;
}
failStreak++;
// Rientriamo subito se gia' siamo offline (niente da ripetere) o se non
// abbiamo ancora due fallimenti consecutivi. La condizione va scritta cosi':
// "torniamo se NON siamo online", non "se siamo online".
if (!serverOnline || failStreak < 2) return;
serverOnline = false;
if (lastGoodAt) {
document.getElementById('link-lost-detail').textContent = 'ultimo dato: ' + lastGoodAt.toLocaleTimeString('it-IT');
document.getElementById('radar-offline-since').textContent = lastGoodAt.toLocaleTimeString('it-IT');
}
document.getElementById('link-lost').style.display = 'flex';
document.getElementById('radar-offline').style.display = 'flex';
// Il radar resta con i dati dell'ultimo aggiornamento riuscito, ma dichiarato
// vecchio: preferibile a una spazzata che continua a girare come se fosse
// una lettura dal vivo.
document.querySelectorAll('.radar-panel').forEach(p => p.classList.add('radar-frozen'));
document.getElementById('status-dot').classList.add('off');
document.getElementById('status-text').textContent = 'Non collegato';
}

async function refresh() {
try {
const res = await fetch('/api/devices');
if (!res.ok) throw new Error('HTTP ' + res.status);
const data = await res.json();
lastGoodAt = new Date();
setConnection(true);
allDevices = data.devices || [];
updateStats(data.counts || {});
updateCounts(data.counts || {});
render();
renderRadar();
refreshRadio();
refreshInquiry();
refreshEvents();
refreshInfo();
shareRefresh();
checkDeepLink();
const now = new Date().toLocaleTimeString('it-IT');
document.getElementById('last-update').textContent = now;
const dot = document.getElementById('status-dot');
const txt = document.getElementById('status-text');
const hasActive = (data.counts || {}).active > 0;
dot.classList.toggle('idle', !hasActive);
dot.classList.remove('off');
txt.textContent = hasActive ? 'Scanning' : 'In attesa';
} catch (e) {
setConnection(false);
console.error('Errore aggiornamento:', e);
}
}

// Barra "Collegato a": URL raggiungibili del listener, copiabili.
let shareUrls = [];
function pickPrimaryUrl(urls) {
const host = window.location.hostname;
const match = urls.find(x => x.url.includes(host));
if (match) return match.url;
return (urls.find(x => !x.url.includes('localhost')) || urls[0] || {}).url || '';
}
function copyText(text, feedbackId) {
const done = function () {
const fb = document.getElementById(feedbackId || 'share-feedback');
if (fb) { fb.textContent = '✓ copiato!'; setTimeout(function () { fb.textContent = ''; }, 1500); }
};
if (navigator.clipboard && navigator.clipboard.writeText) {
navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text); done(); });
} else { fallbackCopy(text); done(); }
}
function fallbackCopy(text) {
const ta = document.createElement('textarea');
ta.value = text;
ta.style.position = 'fixed';
ta.style.opacity = '0';
document.body.appendChild(ta);
ta.select();
try { document.execCommand('copy'); } catch (e) {}
document.body.removeChild(ta);
}
function copyShareUrl() { copyText(shareTargetUrl(), 'share-feedback'); }
// Copia presa da un data-copy: evita di costruire codice con apici dentro
// apici, che e' fragile e una volta rotto fallisce in silenzio.
function shareCopyFrom(ev) {
ev.preventDefault();
const el = ev.currentTarget;
copyText(el.getAttribute('data-copy') || '', 'share-pop-fb');
return false;
}
function shareTargetUrl() {
const host = window.location.hostname;
const remote = host !== 'localhost' && host !== '127.0.0.1';
if (remote) {
// Chi si collega da remoto non ha una LAN locale: condivide il link del
// server BT che sta già usando (il suo IP/tailnet).
return window.location.origin + window.location.pathname;
}
// Utente locale: condividi il primo URL non-localhost (intranet/tailnet).
const lan = shareUrls.find(function (x) { return !x.url.includes('localhost') && !x.url.includes('127.0.0.1'); });
if (lan) return lan.url;
return window.location.origin + window.location.pathname;
}
function openShareModal() {
const url = shareTargetUrl();
document.getElementById('share-modal-url').textContent = url;
document.getElementById('share-modal-feedback').textContent = '';
const remote = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';
document.getElementById('share-modal-note').textContent = remote
? 'Sei collegato da remoto: non puoi creare un link LAN locale, quindi condividi questo link del server BT. Chi lo apre vedrà la dashboard dal tuo stesso indirizzo (VPN/tailnet consentita).'
: 'Suggerimento: invia questo link a chi è sulla stessa rete. Il PC deve restare acceso e la porta 9000 aperta nel firewall di Windows.';
document.getElementById('share-modal').classList.add('active');
}
function closeShareModal() { document.getElementById('share-modal').classList.remove('active'); }

// --- Condivisione in rete -------------------------------------------------
// Un solo bottone in alto, sempre presente. Fa tre cose in una: espone la
// dashboard, apre la porta nel firewall e si ricorda al prossimo avvio.
// Non puo' fare di piu' da solo: aprire il firewall richiede diritti di
// amministratore, e quando mancano lo diciamo mostrando il comando esatto
// invece di far credere che sia andato tutto bene.
let shareState = null;
function shareBtn() { return document.getElementById('share-toggle'); }
function shareLabel() { return document.getElementById('share-toggle-label'); }

function shareRender() {
const st = shareState;
if (!st) return;
const on = !!st.active;
shareBtn().classList.toggle('on', on);
shareLabel().textContent = on ? (st.first_address ? st.first_address + ':' + st.port : 'Condivisa') : 'Condividi';
const rows = [];
if (on && st.addresses && st.addresses.length) {
st.addresses.forEach(function (a) {
const url = 'http://' + a + ':' + st.port;
rows.push(['Indirizzo', '<code>' + url + '</code> <a href="#" data-copy="' + url + '" onclick="return shareCopyFrom(event)">copia</a>']);
});
} else if (on) {
rows.push(['Indirizzo', '<span style="color:var(--text-muted)">nessuna rete locale attiva</span>']);
}
rows.push(['mDNS', st.mdns ? '<span class="share-pop-ok">annunciato come _blusniff._tcp</span>' : '<span class="share-pop-warn">non attivo</span>']);
const fw = st.firewall || {};
// Banner in barra: la condivisione risulta attiva ma il firewall la blocca.
var fwWarn = document.getElementById('fw-warn');
if (fwWarn) {
var blocked = on && (fw.state === 'needs_admin' || fw.state === 'error');
fwWarn.style.display = blocked ? 'flex' : 'none';
}
if (fw.state === 'created' || fw.state === 'open') {
rows.push(['Firewall', '<span class="share-pop-ok">porta ' + st.port + ' aperta</span>']);
} else if (fw.state === 'needs_admin') {
rows.push(['Firewall', '<span class="share-pop-warn">serve amministratore</span>']);
} else if (fw.state === 'error') {
rows.push(['Firewall', '<span class="share-pop-warn">errore</span>']);
} else {
rows.push(['Firewall', '<span class="share-pop-warn">porta non aperta</span>']);
}
let note = '';
if (fw.state === 'needs_admin' || fw.state === 'error') {
note = 'Per aprire la porta, esegui come amministratore:<br><code style="word-break:break-all">' + (fw.command || '') + '</code><br><br>Nel frattempo la dashboard resta raggiungibile da questa macchina.';
} else if (!on) {
note = 'La dashboard ascolta solo su questa macchina. Accendila per renderla raggiungibile dagli altri dispositivi sulla rete.';
}
document.getElementById('share-pop').innerHTML = rows.map(function (r) {
return '<div class="share-pop-row"><span>' + r[0] + '</span><span>' + r[1] + '</span></div>';
}).join('') + '<div class="share-pop-note" id="share-pop-fb">' + note + '</div>' +
'<div class="share-pop-note" style="margin-top:0.4rem"><a href="#" onclick="shareToggle(); return false;" style="color:var(--accent-cyan)">' +
(on ? 'spegCondivisione' : 'accendi Condivisione') + '</a> &middot; <a href="#" onclick="sharePopClose(); return false;">chiudi</a></div>';
}

function sharePopClose() { document.getElementById('share-pop').style.display = 'none'; }
// Il bottone ha due comportamenti, non uno: da spento ACCENDE (e la pagina si
// ricarica perche' il server cambia bind), da acceso MOSTRA i dettagli. Se il
// click spegnesse direttamente, un utente che cerca solo l'indirizzo da
// copiare chiuderebbe per sbaglio la condivisione.
function shareOnClick() {
if (shareState && shareState.active) {
const pop = document.getElementById('share-pop');
pop.style.display = pop.style.display === 'none' ? 'block' : 'none';
} else {
shareToggle();
}
}
async function shareRefresh() {
try {
const r = await fetch('/api/share');
shareState = await r.json();
shareState.addresses = (shareState.addresses || []);
shareState.first_address = shareState.addresses[0] || '';
shareRender();
} catch (e) { /* la dashboard si sta riavviando: la richiesta puo' fallire */ }
}
async function shareToggle() {
const on = shareState && shareState.active;
const btn = shareBtn();
// Doppio click durante un riavvio: il server potrebbe ricevere due POST e
// fermare due volte, colpendo il sender del server appena avviato. Il lato
// server scarta comunque la richiesta ridondante, ma qui non la mandiamo
// neanche: il bottone resta disabilitato fino al reload.
if (btn.classList.contains('busy')) return;
btn.classList.add('busy');
btn.setAttribute('aria-busy', 'true');
shareLabel().textContent = on ? 'spegnendo...' : 'accendendo...';
try {
const r = await fetch('/api/share', {
method: 'POST', headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ on: !on })
});
const res = await r.json();
// Il server si riavvia per cambiare bind: la connessione muore subito dopo la
// risposta. Ricarichiamo la pagina, altrimenti la UI mostrerebbe uno stato
// vecchio su una pagina che ha smesso di essere servita.
if (res.ok) {
setTimeout(function () { window.location.reload(); }, 900);
return;
}
shareBtn().classList.remove('busy');
shareLabel().textContent = on ? 'Condivisa' : 'Condividi';
document.getElementById('share-pop').style.display = 'block';
document.getElementById('share-pop').innerHTML = '<div class="share-pop-row"><span class="share-pop-warn">' + (res.error || 'errore') + '</span></div>';
} catch (e) {
setTimeout(function () { window.location.reload(); }, 900);
}
}
function copyShareModalUrl() { copyText(document.getElementById('share-modal-url').textContent, 'share-modal-feedback'); }
async function refreshInfo() {
try {
const res = await fetch('/api/info');
const d = await res.json();
shareUrls = d.urls || [];
const bar = document.getElementById('share-bar');
if (!bar) return;
if (shareUrls.length === 0) { bar.style.display = 'none'; return; }
bar.style.display = '';
// Nella barra mostriamo solo gli URL condivisibili (niente localhost).
const chips = shareUrls.filter(function (x) { return !x.url.includes('localhost') && !x.url.includes('127.0.0.1'); }).map(function (x) {
const tag = x.label !== 'intranet'
? ' <span class="share-tag">' + x.label + '</span>' : '';
return '<a class="share-url" href="' + x.url + '" target="_blank" title="Copia negli appunti">' + obfuscateUrl(x.url) + '</a>' + tag;
});
document.getElementById('share-urls').innerHTML = chips.join(' ');
document.querySelectorAll('#share-urls .share-url').forEach(function (a) {
a.addEventListener('click', function (e) {
e.preventDefault();
copyText(a.getAttribute('href'), 'share-feedback');
});
});
const btn = document.getElementById('share-intranet-btn');
if (btn) btn.style.display = (chips.length || window.location.hostname !== 'localhost') ? '' : 'none';
} catch (e) {
console.error('Errore info:', e);
}
}

function updateStats(c) {
document.getElementById('stat-identified').textContent = c.identified || 0;
document.getElementById('stat-active').textContent = c.active || 0;
document.getElementById('stat-new').textContent = c.new_past_hour || 0;
document.getElementById('stat-randomized').textContent = c.randomized || 0;
}

function updateCounts(c) {
const classes = c.classes || {};
const map = {
all: c.total || 0, active: c.active || 0, identified: c.identified || 0,
unknown: c.unknown || 0, randomized: c.randomized || 0, watched: c.watched || 0,
ignored: c.ignored || 0,
phone: classes.phone || 0, computer: classes.computer || 0, audio: classes.audio || 0,
wearable: classes.wearable || 0, iot: classes.iot || 0, vehicle: classes.vehicle || 0,
phantom: classes.phantom || 0,
risk: c.risky || 0,
tracker: c.tracker || 0,
static: c.static || 0,
rotating: c.rotating || 0,
other: classes.other || 0
};
Object.keys(map).forEach(k => {
const el = document.getElementById('count-' + k);
if (el) el.textContent = map[k];
});
// Il filtro "Seguiti" a zero e' una domanda, non uno stato: senza questo
// suggerimento l'utente non sa che quel filtro esiste e cosa fare per
// accenderlo. Compare solo quando il filtro resterebbe altrimenti muto.
const we = document.getElementById('watched-empty');
if (we) we.style.display = (map.watched || 0) === 0 ? 'block' : 'none';
// Il numero accanto al bottone "Gestisci ignorati" e' l'unico posto dove la
// sidebar mostra gli ignorati quando il filtro non e' attivo: se l'utente
// ignora qualcosa e cambia filtro, deve poter capire che c'e' roba nascosta
// senza doverlo scoprire ricordando che l'ha fatto.
const ic = document.getElementById('ignored-count-inline');
if (ic) ic.textContent = map.ignored || 0;
}

function matchesFilter(d) {
// Gli ignorati sono visibili solo nel loro filtro. In tutti gli altri sono
// nascosti: e' quello che l'utente ha chiesto ("non lo voglio piu'"), e il
// filtro "Ignorati" e' l'unico posto dove li ritrova, anche per toglierli.
if (currentFilter === 'ignored') return !!d.ignored;
if (d.ignored) return false;
switch (currentFilter) {
case 'active': return d.active;
case 'identified': return d.identified;
case 'unknown': return !d.identified;
case 'randomized': return d.randomized;
case 'new': return (Date.now() - new Date(d.first_seen).getTime()) < 3600000 && d.first_seen;
case 'watched': return d.watched;
case 'risk': return !!(d.risky);
case 'tracker': return !!(d.tracker);
case 'static': return !!(d.static_dev);
case 'rotating': return !!(d.rotating);
default:
if (currentFilter === 'all') return true;
return d.category === currentFilter;
}
}

function getSortValue(d, column) {
switch (column) {
case 'class': return (d.category || '').toLowerCase();
case 'mac': return (d.mac || '').toLowerCase();
case 'vendor': return (d.vendor || '').toLowerCase();
case 'name': return (d.name || '').toLowerCase();
case 'rssi': return Number.isFinite(d.rssi) ? d.rssi : -9999;
case 'sightings': return d.sightings || 0;
case 'last_seen': return new Date(d.last_seen).getTime() || 0;
default: return 0;
}
}

function filtered() {
let list = allDevices.filter(matchesFilter);
const term = searchTerm.toLowerCase();
if (term) {
list = list.filter(d =>
[d.mac, d.vendor, d.name, d.category].join(' ').toLowerCase().includes(term));
}
const dir = sortState.direction === 'asc' ? 1 : -1;
list.sort((a, b) => {
// Il dispositivo personale sta in cima a ogni vista, in ordine crescente o
// decrescente che sia: e' il punto di riferimento dell'utente, quindi cercarlo
// ogni volta tra 200 righe non ha senso. Non e' un criterio di ordinamento che
// compete con gli altri, e' un rango: vale sempre, e dentro ogni rango
// l'ordinamento scelto dall'utente continua a valere.
if (!!a.is_me !== !!b.is_me) return a.is_me ? -1 : 1;
const av = getSortValue(a, sortState.column);
const bv = getSortValue(b, sortState.column);
if (av < bv) return -1 * dir;
if (av > bv) return 1 * dir;
return 0;
});
return list;
}

function setSort(column) {
if (sortState.column === column) {
sortState.direction = sortState.direction === 'asc' ? 'desc' : 'asc';
} else {
sortState.column = column;
sortState.direction = 'asc';
}
document.querySelectorAll('.device-table th.sortable').forEach(th => {
const active = th.dataset.sort === sortState.column;
th.classList.toggle('active', active);
const ind = th.querySelector('.sort-indicator');
if (ind) ind.textContent = active ? (sortState.direction === 'asc' ? '▲' : '▼') : '';
});
pagination.page = 1;
render();
}

// Etichette amichevoli per le famiglie di annunci phantom/tracker (badge
// tabella, scheda dispositivo e tooltip radar).
const PHANTOM_LABELS = { 'apple-popup': 'Apple Continuity popup', 'apple-findmy': 'Apple Find My (AirTag)', 'swift-pair': 'Swift Pair', 'samsung-easysetup': 'Samsung EasySetup', 'samsung-smarttag': 'Samsung SmartTag', 'samsung-fmm': 'Samsung Find My', 'chipolo': 'Chipolo tracker', 'pebblebee': 'Pebblebee tracker', 'google-findmy': 'Google Find My tag', 'fast-pair': 'Fast Pair', 'tile': 'Tile tracker' };
// Famiglie che rappresentano tracker di localizzazione (non spoof popup).
const TRACKER_FAMILIES = ['apple-findmy', 'samsung-smarttag', 'samsung-fmm', 'chipolo', 'pebblebee', 'google-findmy', 'tile'];
function phantomLabel(p) { return PHANTOM_LABELS[p] || p; }

function render() {
const list = filtered();
pagination.totalMatching = list.length;
pagination.totalPages = Math.max(1, Math.ceil(list.length / pagination.pageSize));
if (pagination.page > pagination.totalPages) pagination.page = pagination.totalPages;
const start = (pagination.page - 1) * pagination.pageSize;
const page = list.slice(start, start + pagination.pageSize);

document.getElementById('visible-count').textContent = ': ' + list.length + ' dispositivi';
const filterNames = { all: '', active: '(Filtro Attivi)', new: '(Filtro Nuovi 1h)', identified: '(Filtro Identificati)', unknown: '(Filtro Sconosciuti)', randomized: '(Filtro Randomizzati)', watched: '(Filtro Seguiti)', ignored: '(Filtro Ignorati)', risk: '(Filtro Con rischi)', tracker: '(Filtro Tracker)', phone: '(Filtro Telefoni)', computer: '(Filtro Computer)', audio: '(Filtro Audio)', wearable: '(Filtro Orologi)', iot: '(Filtro IoT)', vehicle: '(Filtro Veicoli)', phantom: '(Filtro Phantom)', other: '(Filtro Altro)' };
// Nomi amichevoli per le famiglie di annunci phantom (badge tabella/scheda).
const fi = document.getElementById('filter-indicator');
if (fi) {
if (currentFilter === 'all') {
fi.style.display = 'none';
fi.textContent = '';
fi.onclick = null;
} else {
fi.style.display = '';
fi.innerHTML = filterNames[currentFilter] + ' <span class="clear-x" aria-hidden="true">✕</span>';
fi.title = '✕ Cancella Filtro (mostra tutti i dispositivi)';
fi.onclick = function () { setFilter('all'); };
}
}
// Da qui in poi il layout si biforca: stessa pagina di dati, due modi di
// mostrarne i contenuti. Non si prova a condividere il markup fra i due —
// sono layout diversi con priorità diverse, e una tabella non si astrae in
// una card senza diventare una terza via che nessuno aggiorna.
if (isMobile) renderMobile(page); else renderDesktop(page);
renderPagination();
renderMobileChips();
}

// Vista desktop: la tabella a 7 colonne, com'era.
function renderDesktop(page) {
const tbody = document.getElementById('device-list');
if (page.length === 0) {
tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 2rem; color: var(--text-muted);">Nessun dispositivo trovato</td></tr>';
} else {
tbody.innerHTML = page.map(d => {
const meta = typeMeta(d.category);
const star = d.watched ? '<span class="watched-star">★</span>' : '';
// 🔇 e 👤 accanto alla stella: sono le tre scelte che l'utente ha fatto, e
// devono essere leggibili nella tabella senza aprire la scheda. In un device
// ignorato sono l'unico posto dove si vedono (gli altri filtri lo nascondono).
const igBadge = d.ignored ? '<span class="badge-cell badge-ignored" title="Ignorato: nascosto dai filtri (ignore.txt). Le notifiche, se seguito, continuano.">🔇</span>' : '';
const meBadge = d.is_me ? '<span class="badge-cell badge-me" title="Il tuo dispositivo (is_me.txt)">👤</span>' : '';
const mac = obfuscateMAC(d.mac);
// Nome reale risolto dal Model ID Fast Pair quando l'annuncio non
// pubblicizza un nome (model_names.txt dal dataset Bluetooth-LE-Spam).
const fallback = d.model_name ? escapeHtml(obfuscateName(d.model_name)) : '<span style="color: var(--text-muted);">&lt;senza nome&gt;</span>';
const name = d.name ? escapeHtml(obfuscateName(d.name)) : fallback;
const cveBadges = (d.cves || []).map(c => '<span class="cve-badge" title="' + escapeHtml(c.model + ' — ' + c.cve + ': ' + c.description) + '">⚠ ' + escapeHtml(c.cve) + '</span>').join('');
const phBadge = d.phantom ? '<span class="cve-badge" style="background:#4a1030;border-color:#4a1030;color:#f0a6ff;" title="' + (TRACKER_FAMILIES.includes(d.phantom) ? 'Tracker BLE riconosciuto: ' : 'Annuncio popup/phantom (possibile spoof BLE): ') + escapeHtml(phantomLabel(d.phantom)) + '">👻 ' + escapeHtml(phantomLabel(d.phantom)) + '</span>' : '';
const fpBadge = (d.static_dev ? '<span class="cve-badge" style="background:#123a2c;border-color:#123a2c;color:#8fe8bd;" title="📌 Falso positivo ambientale: RSSI quasi immobile (varianza < 4.0 su almeno 5 campioni) — dispositivo fisso (Smart-Tag dietro il muro, PC, TV...)">📌 statico</span>' : '') + (d.rotating ? '<span class="cve-badge" style="background:#3a3010;border-color:#3a3010;color:#e8d49b;" title="🔄 ' + (d.rotating_n || 0) + ' MAC condividono lo stesso fingerprint BLE — un solo dispositivo fisico che cambia indirizzo">🔄 ' + (d.rotating_n || 0) + ' MAC</span>' : '');
const nameWithCve = name + star + meBadge + igBadge + phBadge + fpBadge + cveBadges;
const vendor = d.vendor ? escapeHtml(d.vendor) : '—';
const zone = ZONE_CLS[d.zone] ? '<span class="zone-pill ' + ZONE_CLS[d.zone] + '">' + d.zone + '</span>' : '—';
const rssi = Number.isFinite(d.rssi) ? d.rssi + ' dBm' : '—';
const stale = (Date.now() - new Date(d.last_seen).getTime()) > 300000 ? ' stale' : '';
const lastCls = (Date.now() - new Date(d.last_seen).getTime()) < 60000 ? 'recent' : '';
const onclick = 'showDevice(\'' + d.mac + '\')';
if (compactView) {
return '<tr class="' + stale + '" onclick="' + onclick + '">' +
'<td><span class="type-badge ' + meta.cls + '" style="font-size: 0.65rem; padding: 0.15rem 0.4rem;">' + star + meta.ico + '</span></td>' +
'<td colspan="3" style="font-size: 0.75rem;"><span class="mac-addr">' + mac + '</span> ' + nameWithCve + '</td>' +
'<td style="font-size: 0.75rem;">' + rssi + '</td>' +
'<td style="font-size: 0.75rem;">' + d.sightings + '</td>' +
'<td class="' + lastCls + '" style="font-size: 0.75rem;">' + fmtAgo(d.last_seen) + '</td></tr>';
}
return '<tr class="' + stale + '" onclick="' + onclick + '">' +
'<td><span class="type-badge ' + meta.cls + '">' + star + meta.ico + ' ' + meta.label + '</span></td>' +
'<td class="mac-addr">' + mac + '</td>' +
'<td class="vendor-name">' + vendor + '</td>' +
'<td class="device-name">' + nameWithCve + '</td>' +
'<td>' + rssi + ' ' + zone + '</td>' +
'<td class="sighting-count">' + d.sightings + '</td>' +
'<td class="last-seen ' + lastCls + '" title="' + fmtFull(d.last_seen) + '">' + fmtAgo(d.last_seen) + '</td></tr>';
}).join('');
}
}

// Vista telefono: una card per dispositivo. L'ordine dentro la card e' quello
// che serve a colpo d'occhio — prima chi e' (icona + nome), poi l'indirizzo,
// poi vendor e classe, poi i badge che segnalano qualcosa (CVE, phantom,
// ignorato, rotazione), e in fondo i numeri. Ogni badge ripete in `title`
// l'informazione estesa che nella tabella sta scritta per esteso: la card
// puo' mostrare "⚠" dove la tabella scriveva l'identificativo della CVE,
// quindi il dettaglio non puo' sparire, solo spostarsi nel tooltip.
function renderMobile(page) {
const box = document.getElementById('device-cards');
if (page.length === 0) {
box.innerHTML = '<div style="text-align: center; padding: 2rem 1rem; color: var(--text-muted);">Nessun dispositivo trovato</div>';
return;
}
box.innerHTML = page.map(d => {
const meta = typeMeta(d.category);
const star = d.watched ? '<span class="card-star">★</span>' : '';
const mac = obfuscateMAC(d.mac);
const fallback = d.model_name ? escapeHtml(obfuscateName(d.model_name)) : '<span style="color: var(--text-muted);">&lt;senza nome&gt;</span>';
const name = d.name ? escapeHtml(obfuscateName(d.name)) : fallback;
const badges = [];
if (d.is_me) badges.push('<span class="card-badge me" title="Il tuo dispositivo (is_me.txt)">👤</span>');
if (d.ignored) badges.push('<span class="card-badge ignored" title="Ignorato: nascosto dai filtri (ignore.txt)">🔇</span>');
if (d.static_dev) badges.push('<span class="card-badge static" title="Falso positivo ambientale: RSSI quasi immobile — dispositivo fisso">📌</span>');
if (d.rotating) badges.push('<span class="card-badge rotating" title="' + (d.rotating_n || 0) + ' MAC con lo stesso fingerprint: un solo dispositivo che cambia indirizzo">🔄 ' + (d.rotating_n || 0) + '</span>');
if (d.phantom) badges.push('<span class="card-badge phantom" title="' + (TRACKER_FAMILIES.includes(d.phantom) ? 'Tracker BLE riconosciuto: ' : 'Annuncio popup/phantom (possibile spoof BLE): ') + escapeHtml(phantomLabel(d.phantom)) + '">👻</span>');
for (const c of (d.cves || [])) badges.push('<span class="card-badge cve" title="' + escapeHtml(c.model + ' — ' + c.cve + ': ' + c.description) + '">⚠</span>');
const vendor = d.vendor ? escapeHtml(d.vendor) : '—';
const zone = ZONE_CLS[d.zone] ? ' · ' + d.zone : '';
const rssi = Number.isFinite(d.rssi) ? d.rssi + ' dBm' : '—';
const stale = (Date.now() - new Date(d.last_seen).getTime()) > 300000 ? ' stale' : '';
return '<div class="device-card' + stale + '" onclick="showDevice(\'' + d.mac + '\')">' +
'<div class="card-header"><span class="card-category">' + meta.ico + '</span>' +
'<span class="card-name">' + name + '</span>' + star + '</div>' +
'<div class="card-mac">' + mac + '</div>' +
'<div class="card-meta">' + vendor + ' · ' + meta.label + '</div>' +
(badges.length ? '<div class="card-badges">' + badges.join('') + '</div>' : '') +
'<div class="card-footer"><span class="card-rssi">📶 ' + rssi + zone + '</span>' +
'<span class="card-sightings">' + d.sightings + ' volte</span>' +
'<span class="card-ago" title="' + fmtFull(d.last_seen) + '">' + fmtAgo(d.last_seen) + '</span></div></div>'
}).join('');
}

// Chip dei filtri per il telefono. Le etichette sono le stesse della sidebar e
// i conteggi vengono letti dagli stessi elementi che aggiorna la sidebar: due
// copie di "quanti attivi ci sono" divergerebbero alla prima esecuzione.
function renderMobileChips() {
const scroll = document.getElementById('mobile-chips-scroll');
if (!scroll) return;
const defs = [
['all', 'Tutti', ''], ['active', 'Attivi', '🟢'], ['watched', 'Seguiti', '★'],
['risk', 'Con rischi', '⚠'], ['tracker', 'Tracker', '🏷'], ['randomized', 'Randomizzati', '🟠'],
['phone', 'Telefoni', '📱'], ['computer', 'Computer', '💻'], ['audio', 'Audio', '🎧'],
['wearable', 'Orologi', '⌚'], ['iot', 'IoT', '📡'], ['vehicle', 'Veicoli', '🚗'],
['phantom', 'Phantom', '👻'], ['ignored', 'Ignorati', '🔇'], ['other', 'Altri', '❔']
];
scroll.innerHTML = defs.map(([id, label, ico]) => {
const n = document.getElementById('count-' + id);
const num = n ? n.textContent : '';
return '<button class="mobile-chip' + (currentFilter === id ? ' active' : '') + '" data-filter="' + id +
'" onclick="setFilter(\'' + id + '\')">' + (ico ? ico + ' ' : '') + label +
(num ? ' <span class="chip-count">' + escapeHtml(num) + '</span>' : '') + '</button>';
}).join('');
// I quattro numeri che in sidebar sono card cliccabili: sul telefono diventano
// una riga sola sopra i chip (stesso dato, due espressioni diverse).
const stats = document.getElementById('mobile-stats');
if (stats) {
const get = id => { const e = document.getElementById('stat-' + id); return e ? e.textContent : '—'; };
stats.innerHTML = '<span>🔵 Identificati <b>' + get('identified') + '</b></span>' +
'<span>🟢 Attivi <b>' + get('active') + '</b></span>' +
'<span>🟠 Nuovi <b>' + get('new') + '</b></span>';
}
}

// Ruotare il telefono (o allargare la finestra) cambia il layout. Il CSS da
// solo non basta: la lista e' gia' costruita con il markup sbagliato, quindi
// al cambio di soglia va ricostruita. Si torna sempre a pagina 1 perche' un
// numero di pagina calcolato su 50 righe non ha senso su 20.
mobileMql.addEventListener('change', e => {
isMobile = e.matches;
pagination.pageSize = isMobile ? 20 : 50;
pagination.page = 1;
render();
});

function renderPagination() {
const info = document.getElementById('page-info');
info.textContent = 'Pagina ' + pagination.page + '/' + pagination.totalPages;
document.getElementById('prev-page-btn').disabled = pagination.page <= 1;
document.getElementById('next-page-btn').disabled = pagination.page >= pagination.totalPages;
const container = document.getElementById('page-numbers');
const total = pagination.totalPages;
const cur = pagination.page;
let tokens;
if (total <= 7) {
tokens = Array.from({ length: total }, (_, i) => i + 1);
} else {
tokens = [1];
let s = Math.max(2, cur - 1), e = Math.min(total - 1, cur + 1);
if (cur <= 3) { s = 2; e = 4; } else if (cur >= total - 2) { s = total - 3; e = total - 1; }
if (s > 2) tokens.push('...');
for (let p = s; p <= e; p++) tokens.push(p);
if (e < total - 1) tokens.push('...');
tokens.push(total);
}
container.innerHTML = tokens.map(t => {
if (t === '...') return '<span class="page-ellipsis">…</span>';
return '<button class="btn page-number-btn' + (t === cur ? ' active' : '') + '" onclick="goToPage(' + t + ')">' + t + '</button>';
}).join('');
}
function goToPage(p) {
const t = Math.max(1, Math.min(p, pagination.totalPages));
if (t !== pagination.page) { pagination.page = t; render(); }
}
function changePage(delta) { goToPage(pagination.page + delta); }
function changePageSize(v) {
pagination.pageSize = Number.parseInt(v, 10) || 50;
pagination.page = 1;
render();
}

function sparklineSvg(history) {
if (!history || history.length < 2) return '<div style="padding: 0.5rem; color: var(--text-muted); font-size: 0.75rem;">Dati RSSI insufficienti (servono almeno 2 campioni).</div>';
const w = 620, h = 60, pad = 4;
const min = Math.min.apply(null, history), max = Math.max.apply(null, history);
const range = (max - min) || 1;
const pts = history.map((v, i) => {
const x = pad + (i / (history.length - 1)) * (w - 2 * pad);
const y = pad + (1 - (v - min) / range) * (h - 2 * pad);
return x.toFixed(1) + ',' + y.toFixed(1);
}).join(' ');
return '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
'<polyline class="rssi-line" points="' + pts + '"></polyline></svg>' +
'<div style="display: flex; justify-content: space-between; font-size: 0.6rem; color: var(--text-muted); margin-top: 0.25rem;">' +
'<span>min ' + min + ' dBm</span><span>max ' + max + ' dBm</span><span>' + history.length + ' campioni</span></div>';
}

function periodLabel(h) {
if (h >= 5 && h < 12) return 'mattina';
if (h >= 12 && h < 18) return 'pomeriggio';
if (h >= 18) return 'sera';
return 'notte';
}

function renderHeatmapGrid(counts, cls, labels) {
const max = Math.max.apply(null, counts);
const cells = counts.map(c => {
const lvl = max > 0 ? (c === 0 ? 0 : Math.max(1, Math.round((c / max) * 4))) : 0;
return '<div class="activity-cell l' + lvl + '" title="' + c + '"></div>';
}).join('');
return '<div class="activity-grid ' + cls + '">' + cells + '</div>' +
'<div class="activity-labels ' + cls + '">' + labels + '</div>';
}

async function loadHeatmap(mac) {
const h1 = document.getElementById('heatmap-hourly');
const h7 = document.getElementById('heatmap-daily');
if (!h1 || !h7) return;
try {
const res = await fetch('/api/heatmap?mac=' + encodeURIComponent(mac));
const data = await res.json();
if (!data.available) {
h1.innerHTML = '<div class="heatmap-note">presenze.csv non disponibile (avvia con --listen per generarlo).</div>';
h7.innerHTML = '';
return;
}
const hours = data.hours || [];
const days = data.days || [];
const total = data.total || 0;
const peakIdx = hours.indexOf(Math.max.apply(null, hours));
if (total === 0) {
h1.innerHTML = '<div class="heatmap-note">Nessun avvistamento per questo MAC in presenze.csv.</div>';
h7.innerHTML = '';
return;
}
const hourLabels = Array.from({ length: 24 }, (_, h) => h % 3 === 0 ? h : '');
h1.innerHTML = '<div class="heatmap-note">' + total + ' avvistamenti · picco: ' + periodLabel(peakIdx) + ' (h' + peakIdx + ', ' + hours[peakIdx] + ')' + '</div>' +
renderHeatmapGrid(hours, 'hourly', hourLabels);
h7.innerHTML = '<div class="heatmap-note">Per giorno della settimana (L=Lunedì)</div>' +
renderHeatmapGrid(days, 'daily', ['L', 'M', 'M', 'G', 'V', 'S', 'D']);
} catch (e) {
h1.innerHTML = '<div class="heatmap-note">Errore heatmap: ' + escapeHtml(e.message) + '</div>';
h7.innerHTML = '';
}
}

function showDevice(mac) {
const d = allDevices.find(x => x.mac === mac);
if (!d) return;
showDeviceData(d);
}
// I tre blocchi di azione della scheda: "Segui", "Ignora", "Sono io".
//
// Sono tre operazioni su tre file diversi e con tre effetti diversi, quindi
// restano separate anche se il peso visivo è lo stesso. Ognuna spiega nella
// riga piccola cosa sta per succedere: sono le tre azioni che scrivono su
// disco e l'utente deve poter tornare indietro sapendo cosa ha scritto.
//
// L'ordine segue "prima il più innocuo": ignorare e dichiarare il proprio
// telefono non attivano nessuna sorveglianza, il follow sì (notifiche
// periodiche verso ntfy). Quello che costa di più sta in fondo.
function actionsBlock(d) {
return followBlock(d) + ignoreBlock(d) + isMeBlock(d);
}

// Blocco "Segui" della scheda dispositivo.
//
// Il peso visivo segue l'azione: da non seguito a seguito il click e' quello
// che l'utente vuole fare (pulsante rosso pieno, il default di .btn); una
// volta seguito, l'unfollow e' un'azione secondaria e non deve competere per
// l'attenzione (outline ambra). Il badge della persona compare solo se
// l'utente l'ha compilata in bt_known.txt: e' un dato suo, non lo inventiamo.
function followBlock(d) {
const personaBadge = d.persona
? '<span class="follow-persona" title="Persona associata in bt_known.txt">👤 ' + escapeHtml(d.persona) + '</span>'
: '';
const explanation = d.watched
? 'Seguito: il probe BT Classic lo cerca ogni 60 s e le notifiche ntfy scattano quando arriva o parte.'
: 'Non seguito. Aggiungendolo a bt_known.txt viene cercato attivamente e ricevi le notifiche quando arriva o parte.';
let html = '<div class="detail-item" style="grid-column: 1 / -1;">' +
'<div class="detail-label">⭐ Segui questo dispositivo' + personaBadge + '</div>' +
'<div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">' +
'<span style="font-size: 0.7rem; color: var(--text-muted); flex: 1; min-width: 14rem;">' + escapeHtml(explanation) + '</span>' +
'<button class="btn btn-follow ' + (d.watched ? 'followed' : 'btn-primary') + '" id="follow-btn" onclick="toggleFollow(\'' + d.mac + '\')">' +
(d.watched ? '✖ Smetti di seguire' : '⭐ Segui') +
'</button>' +
'<span id="follow-feedback" class="feedback"></span>' +
'</div>';
if (d.watched) {
html += '<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.25rem;">La riga è in <code>bt_known.txt</code> accanto all&#39;eseguibile: lì puoi correggere il nome e aggiungere la <b>Persona</b> (di chi è), che compare come badge in questa scheda. Le notifiche usano il nome. Vale anche ai prossimi avvii, oppure con <code>bluesniff --edit-known</code>.</div>';
} else if (!d.name) {
html += '<div style="font-size: 0.6rem; color: var(--accent-amber); margin-top: 0.25rem;">⚠ Questo dispositivo non ha un nome pubblicizzato: in bt_known.txt comparirà come MAC e le notifiche useranno il MAC come nome. Rinominalo col campo qui sopra prima di seguirlo.</div>';
}
// Il MAC di bt_known.txt e' un MAC Classic: il probe usa RFCOMM/AF_BTH, che
// non funziona su un indirizzo BLE randomizzato. Non tentiamo di convertire
// BLE -> Classic (e' impossibile: l'indirizzo vero non e' in nessun annuncio),
// quindi diciamo il fatto e lasciamo scegliere. Senza questo avviso l'utente
// clicca "Segui", vede la stella e non arriva mai nessuna notifica: sembrerebbe
// un guasto, mentre e' la differenza fra due tecnologie diverse.
if (!d.watched && d.randomized) {
html += '<div style="font-size: 0.6rem; color: var(--accent-amber); margin-top: 0.25rem;">⚠ MAC randomizzato: questo indirizzo è BLE e cambia nel tempo, quindi il probe BT Classic non lo raggiungerà e <b>non arriveranno notifiche di presenza</b>. Puoi comunque seguirlo (la stella resta e la riga è in bt_known.txt). Se è il tuo telefono, il MAC Classic è un altro: cercalo con <code>bluesniff --learn</code>, che elenca i dispositivi già associati a Windows.</div>';
}
return html + '</div>';
}

// Blocco "Ignora": nasconde il dispositivo dalla tabella.
//
// L'ignora e' l'azione che l'utente usera di piu' (un AirTag del vicino, un
// vecchio wearable): deve essere immediata e reversibile, e la riga piccola
// dice la cosa che non e' ovvia, cioe' che NON tocca le notifiche.
function ignoreBlock(d) {
const explanation = d.ignored
? 'Ignorato: sparito dalla tabella, ma le notifiche (se è seguito) continuano. Toglilo per rivederlo.'
: 'Nasconde dalla tabella e dai conteggi. Non influisce sulle notifiche: sono una scelta separata.';
let html = '<div class="detail-item" style="grid-column: 1 / -1;">' +
'<div class="detail-label">🔇 Ignora questo dispositivo</div>' +
'<div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">' +
'<span style="font-size: 0.7rem; color: var(--text-muted); flex: 1; min-width: 14rem;">' + escapeHtml(explanation) + '</span>' +
'<button class="btn btn-ignore ' + (d.ignored ? 'on' : 'off') + '" id="ignore-btn" onclick="toggleIgnore(\'' + d.mac + '\', ' + (d.watched ? 'true' : 'false') + ')">' +
(d.ignored ? '↩ Non ignorare' : '🔇 Ignora') +
'</button>' +
'<span id="ignore-feedback" class="feedback"></span>' +
'</div>';
if (!d.ignored) {
html += '<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.25rem;">Va in <code>ignore.txt</code> accanto all&#39;eseguibile, per sempre e anche ai prossimi avvii. È per <b>MAC</b>: se il dispositivo ruota l’indirizzo, va ignorato di nuovo. La lista si gestisce da “Gestisci ignorati” nella barra laterale.</div>';
}
return html + '</div>';
}

// Blocco "Sono io": dichiara il dispositivo personale.
//
// Non silenzia le notifiche di proposito: un utente a cui smettono le
// notifiche senza spiegazione cerca il bug. Se vuole silenziare il proprio
// telefono, lo ignora: è lì che il significato è chiaro.
function isMeBlock(d) {
const explanation = d.is_me
? 'È il tuo dispositivo. Resta in cima alla tabella e conoscerai i tuoi spostamenti dai correlati.'
: 'Il MAC che porti con te. Bluesniff lo mette in cima alla tabella: distingue "sono arrivato" da "è arrivato qualcun\'altro".';
let html = '<div class="detail-item" style="grid-column: 1 / -1;">' +
'<div class="detail-label">👤 Sono io</div>' +
'<div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">' +
'<span style="font-size: 0.7rem; color: var(--text-muted); flex: 1; min-width: 14rem;">' + escapeHtml(explanation) + '</span>' +
'<button class="btn btn-ismine ' + (d.is_me ? 'on' : '') + '" id="isme-btn" onclick="toggleIsMe(\'' + d.mac + '\')">' +
(d.is_me ? '↩ Non è il mio' : '👤 Sono io') +
'</button>' +
'<span id="isme-feedback" class="feedback"></span>' +
'</div>';
html += '<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.25rem;">Va in <code>is_me.txt</code>, <b>un solo MAC</b> per volta: sceglierne un altro sostituisce questo. Non cambia le notifiche.</div>';
return html + '</div>';
}

function showDeviceData(d) {
const meta = typeMeta(d.category);
const zonePill = ZONE_CLS[d.zone] ? '<span class="zone-pill ' + ZONE_CLS[d.zone] + '">' + d.zone + '</span>' : '—';
const rssiNow = Number.isFinite(d.rssi) ? d.rssi + ' dBm' : '—';
document.getElementById('modal-content').innerHTML =
'<div class="detail-grid">' +
'<div class="detail-item"><div class="detail-label">Nome</div><div class="detail-value">' + escapeHtml(obfuscateName(d.name) || '(senza nome)') + '</div></div>' +
'<div class="detail-item" style="grid-column: 1 / -1;"><div class="detail-label">✏️ Rinomina dispositivo</div>' +
'<div style="display: flex; gap: 0.35rem; align-items: center;">' +
'<input class="form-input" id="rename-input" value="' + escapeHtml(d.name || '') + '" placeholder="Nome personalizzato (vuoto = ripristina)" style="flex: 1; min-width: 0;">' +
'<button class="btn btn-primary" onclick="saveRename(\'' + d.mac + '\')" style="white-space: nowrap;">Salva</button>' +
'<span id="rename-feedback" style="font-size: 0.7rem; color: var(--accent-green);"></span>' +
'</div>' +
'<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.25rem;">Il nome viene salvato in names.txt accanto all&#39;eseguibile e vince su quello pubblicizzato (vale anche ai prossimi avvii).</div>' +
'</div>' +
actionsBlock(d) +
'<div class="detail-item"><div class="detail-label">Classe</div><div class="detail-value highlight"><span class="type-badge ' + meta.cls + '">' + meta.ico + ' ' + meta.label + '</span></div></div>' +
'<div class="detail-item"><div class="detail-label">Indirizzo MAC</div><div class="detail-value mono">' + obfuscateMAC(d.mac) + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Vendor</div><div class="detail-value">' + escapeHtml(d.vendor || '—') + '</div></div>' +
'<div class="detail-item"><div class="detail-label">RSSI attuale</div><div class="detail-value">' + rssiNow + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Distanza stimata</div><div class="detail-value">' + (Number.isFinite(d.distance_m) ? '~' + d.distance_m.toFixed(1) + ' m' : '—') + (d.tx_power != null ? ' <span style="color: var(--text-muted); font-size: 0.65rem;">(tx ' + d.tx_power + ' dBm' + (d.tx_ibeacon ? ' · iBeacon' : '') + ')</span>' : '') + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Connettibile</div><div class="detail-value">' + (d.connectable == null ? '—' : d.connectable ? '<span style="color: var(--accent-green);">Sì 🔗</span>' : '<span style="color: var(--text-muted);">No 📡</span>') + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Zona di prossimità</div><div class="detail-value">' + zonePill + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Randomizzato</div><div class="detail-value">' + (d.randomized ? 'Sì' : 'No') + '</div></div>' +
(d.static_dev ? '<div class="detail-item" style="grid-column: 1 / -1;"><div class="detail-label">📌 Falso positivo ambientale</div><div class="detail-value">RSSI quasi immobile (varianza < 4.0 su almeno 5 campioni) — dispositivo fisso, escluso come segnale ambientale. <span style="font-size:0.65rem;color:var(--text-muted);">Filtro sidebar “Statici”</span></div></div>' : '') +
(d.rotating ? '<div class="detail-item" style="grid-column: 1 / -1;"><div class="detail-label">🔄 MAC rotante</div><div class="detail-value">' + (d.rotating_n || 0) + ' MAC condividono lo stesso fingerprint BLE — un solo dispositivo fisico che cambia indirizzo (es. Smart-Tag o telefono con MAC randomizzato)</div></div>' : '') +
'<div class="detail-item" style="grid-column: 1 / -1;"><div class="detail-label">Model ID Fast Pair</div><div class="detail-value mono">' + (d.model_id != null ? d.model_id : '—') + (d.model_name ? ' <span style="color: var(--text-secondary);">≈ ' + escapeHtml(d.model_name) + '</span>' : '') + '</div></div>' +
(d.phantom ? '<div class="detail-item" style="grid-column: 1 / -1;"><div class="detail-label">' + (TRACKER_FAMILIES.includes(d.phantom) ? '🏷 Tracker BLE' : '⚠ Annuncio popup/phantom') + '</div><div class="detail-value"><span class="type-badge type-phantom">👻 ' + escapeHtml(phantomLabel(d.phantom)) + '</span> <span style="font-size: 0.65rem; color: var(--text-muted);">' + (TRACKER_FAMILIES.includes(d.phantom) ? 'famiglia di localizzazione riconosciuta dalla firma BLE' : 'possibile spoof BLE — non un verdetto') + '</span></div></div>' : '') +
((d.cves && d.cves.length) ? '<div class="detail-item" style="grid-column: 1 / -1;"><div class="cve-section"><div class="cve-section-title">⚠ Vulnerabilità note</div>' + d.cves.map(c => '<div class="cve-item"><span class="cve-id">' + escapeHtml(c.cve) + '</span> — ' + escapeHtml(c.vendor + ' ' + c.model) + ' · ' + escapeHtml(c.description) + '</div>').join('') + '</div></div>' : '') +
'<div class="detail-item"><div class="detail-label">Seguito</div><div class="detail-value">' + (d.watched ? 'Sì ★' : 'No') + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Primo avvistamento</div><div class="detail-value">' + fmtFull(d.first_seen) + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Ultimo avvistamento</div><div class="detail-value">' + fmtFull(d.last_seen) + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Avvistamenti</div><div class="detail-value highlight">' + d.sightings + '</div></div>' +
'<div class="detail-item"><div class="detail-label">Stato</div><div class="detail-value">' + (d.active ? '<span style="color: var(--accent-green);">attivo ora</span>' : fmtAgo(d.last_seen)) + '</div></div>' +
'</div>' +
'<div class="chart-section"><div class="chart-title">Storico RSSI (sessione live)</div><div class="rssi-chart">' + sparklineSvg(d.rssi_history) + '</div></div>' +
'<div class="chart-section"><div class="chart-title">Heatmap attività — da presenze.csv</div>' +
'<div class="heatmap" id="heatmap-hourly"><div class="heatmap-note">Caricamento...</div></div>' +
'<div class="heatmap" id="heatmap-daily" style="margin-top: 0.5rem;"></div></div>' +
'<div style="margin-top: 1rem; font-size: 0.65rem; color: var(--text-muted);">Dati live accumulati da quando è partito bluesniff; heatmap e storico storico da presenze.csv.</div>' +
'<div style="margin-top: 1rem; display: flex; gap: 0.5rem; align-items: center;">' +
'<button class="btn" onclick="shareDevice(\'' + d.mac + '\')" title="Copia un link che apre questa scheda">🔗 Condividi link</button>' +
'<span id="share-dev-feedback" style="font-size: 0.7rem; color: var(--accent-green);"></span>' +
'</div>' +
'<div style="margin-top: 0.8rem; border-top: 1px solid var(--border-color); padding-top: 0.6rem;">' +
'<div class="detail-label" style="margin-bottom: 0.35rem;">🔍 Sonde di identificazione (semi-attive, sola lettura)</div>' +
'<div style="display: flex; gap: 0.4rem; flex-wrap: wrap; margin-bottom: 0.45rem;">' +
'<button class="btn" id="btn-probe-gatt" onclick="runProbe(\'gatt\',\'' + d.mac + '\')" title="Connette al dispositivo e legge i servizi GATT (con Device Information per il modello)">🔌 Sonda GATT</button>' +
'<button class="btn" id="btn-probe-sdp" onclick="runProbe(\'sdp\',\'' + d.mac + '\')" title="SDP classico (stile bluing): elenca i servizi BR/EDR — serve radio classic + device raggiungibile">📞 Sonda SDP (classic)</button>' +
'</div>' +
'<div id="probe-result" style="font-size: 0.7rem; max-height: 230px; overflow-y: auto;"></div>' +
'</div>';
document.getElementById('device-modal').classList.add('active');
loadHeatmap(d.mac);
showStoredProbe(d.mac);
}
async function showStoredProbe(mac) {
// Quando si riapre una scheda già sondata, ripropone l\'ultimo risultato.
try {
const res = await fetch('/api/probe?mac=' + encodeURIComponent(mac) + '&kind=gatt');
const d = await res.json();
if (d.result) renderProbe('gatt', d.result);
} catch (e) { /* silenzioso: la sonda la fa l\'utente */ }
}
async function runProbe(kind, mac) {
const btn = document.getElementById('btn-probe-' + kind);
const out = document.getElementById('probe-result');
if (!btn || !out) return;
const old = btn.textContent;
btn.disabled = true;
btn.textContent = '⏳ in corso (max ~12s)';
out.innerHTML = '<div style="color: var(--text-muted);">' + (kind === 'gatt' ? '🔌' : '📞') + ' sonda ' + (kind === 'gatt' ? 'GATT' : 'SDP') + ' in corso...</div>';
try {
const res = await fetch('/api/probe', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ mac: mac, kind: kind })
});
const d = await res.json();
if (d.result) renderProbe(kind, d.result);
else out.innerHTML = '<div class="radar-empty">nessun risultato dalla sonda</div>';
} catch (e) {
out.innerHTML = '<div style="color: var(--accent-red);">errore rete: ' + escapeHtml(String(e)) + '</div>';
}
btn.disabled = false;
btn.textContent = old;
}
function renderProbe(kind, p) {
const out = document.getElementById('probe-result');
if (!out || !p) return;
out.innerHTML = kind === 'gatt' ? renderGatt(p) : renderSdp(p);
}
function renderGatt(p) {
let h = '';
if (p.error) {
return '<div style="color: var(--accent-amber);">⚠ ' + escapeHtml(p.error) + '</div>';
}
h += '<div style="margin-bottom: 0.3rem;">📛 ' + (p.device_name ? escapeHtml(p.device_name) : '(senza nome dall\'annuncio)') + '</div>';
if (p.ident) h += '<div style="margin-bottom: 0.3rem;">🏷️ <b>≈ ' + escapeHtml(p.ident) + '</b></div>';
(p.cves || []).forEach(c => {
h += '<div style="color: var(--accent-red); margin-bottom: 0.15rem;">⚠ <b>' + escapeHtml(c.cve) + '</b> — ' + escapeHtml(c.vendor + ' ' + c.model) + '</div>';
});
if (!p.services || p.services.length === 0) {
return h + '<div class="radar-empty">nessun servizio esposto (device spesso vuoto se non abbinato)</div>';
}
h += p.services.map(s =>
'<div style="padding: 0.25rem 0; border-bottom: 1px solid var(--border-color);">' +
'<b>' + escapeHtml(s.name) + '</b> <span class="mac-addr">' + escapeHtml(s.uuid) + '</span>' +
(s.chars || []).map(c =>
'<div style="padding-left: 0.8rem; font-size: 0.62rem; color: var(--text-secondary);">• ' + escapeHtml(c.name) + ' [' + escapeHtml(c.props || '') + '] ' +
(c.value ? '= <b style="color: var(--text-primary);">' + escapeHtml(c.value) + '</b>' : '') +
'<span class="mac-addr">' + escapeHtml(c.uuid) + '</span></div>'
).join('') + '</div>'
).join('');
return h;
}
function renderSdp(p) {
if (p.error) {
return '<div style="color: var(--accent-amber);">⚠ ' + escapeHtml(p.error) + '</div>';
}
let h = '';
if (p.risks && p.risks.length > 0) {
h += '<div style="margin-bottom: 0.4rem;">' + p.risks.map(r =>
'<div style="border: 1px solid var(--accent-amber); border-left: 3px solid var(--accent-amber); border-radius: 6px; padding: 0.3rem 0.5rem; margin-bottom: 0.25rem; font-size: 0.68rem;">' +
'<b style="color: var(--accent-amber);">⚠ ' + escapeHtml(r.title) + '</b><br>' +
'<span style="color: var(--text-muted);">' + escapeHtml(r.note) + '</span>' +
'</div>'
).join('') + '</div>';
}
if (!p.services || p.services.length === 0) {
return h + '<div class="radar-empty">nessun servizio SDP trovato (device non in page-scan?)</div>';
}
h += p.services.map(s =>
'<div style="padding: 0.25rem 0; border-bottom: 1px solid var(--border-color);">' +
'<span style="color: var(--accent-green);">▸</span> <b>' + escapeHtml(s.class_name) + '</b> ' +
'<span class="mac-addr">0x' + ('0000' + (s.uuid || 0).toString(16)).slice(-4).toUpperCase() + '</span>' +
(s.protocol ? ' <span style="color: var(--text-muted);">(' + escapeHtml(s.protocol) + ')</span>' : '') +
(s.service_name ? ' — <i>' + escapeHtml(s.service_name) + '</i>' : '') +
'</div>'
).join('');
return h;
}
function shareDevice(mac) {
copyText(location.origin + location.pathname + '?mac=' + encodeURIComponent(mac), 'share-dev-feedback');
}
// Segui / smetti di seguire: scrive in bt_known.txt via API.
//
// Lo stato del feedback e' dato da una classe (`ok` / `err`), non da uno style
// inline: cosi' non si tocca la stringa dell'HTML per cambiare colore, e
// `:empty` evita che resti un buco prima della risposta.
// Ridisegna la scheda dopo un'azione, usando il device vivo se c'e', e
// ricostruendolo se non c'e'.
//
// Il secondo caso non e' un dettaglio: la scheda si apre anche da un link
// condiviso (`?device=MAC`) o dalla ricerca, dove il dispositivo puo' non
// essere nella lista, e puo' sparire mentre la scheda e' aperta. Senza questo
// fallback `showDeviceData(undefined)` solleva, il `catch` del toggle scrive
// "errore rete" e l'utente vede un errore di rete dopo che il file e' stato
// scritto correttamente: il peggior messaggio possibile, perche' e' falso e
// porta a ritentare.
//
// Il fallback dichiara i campi che i blocchi di azione leggono; il resto
// (RSSI, storico) resta vuoto, ed e' corretto: non lo conosciamo.
function redrawDevice(mac, patch) {
const live = allDevices.find(x => x.mac === mac);
if (live) Object.assign(live, patch);
const d = live || Object.assign({ mac: mac, name: '', vendor: '', rssi: null, zone: '-', category: 'other', randomized: false, identified: false, watched: false, ignored: false, is_me: false, persona: '', active: false, sightings: 0, first_seen: new Date().toISOString(), last_seen: new Date().toISOString(), rssi_history: [] }, patch);
showDeviceData(d);
return d;
}

async function toggleFollow(mac) {
const btn = document.getElementById('follow-btn');
const fb = document.getElementById('follow-feedback');
if (!btn || !fb) return;
const d = allDevices.find(x => x.mac === mac);
const isFollowed = !!(d && d.watched);
const url = isFollowed ? '/api/known/unfollow' : '/api/known/follow';
const body = isFollowed ? { mac: mac } : { mac: mac, name: (d && d.name) || '' };
btn.classList.add('busy');
const oldLabel = btn.textContent;
btn.textContent = 'in corso…';
fb.textContent = '';
fb.className = 'feedback';
function fail(msg) {
fb.textContent = msg;
fb.className = 'feedback err';
btn.classList.remove('busy');
btn.textContent = oldLabel;
}
try {
const res = await fetch(url, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify(body)
});
const r = await res.json();
if (!r.ok) { fail('errore: ' + (r.error || '')); return; }
// La scheda si ridisegna col pulsante invertito: se l'utente deve aspettare,
// un doppio click sembra un no-op e sembra un bug.
redrawDevice(mac, { watched: !!r.watched });
const fb2 = document.getElementById('follow-feedback');
if (fb2) {
fb2.textContent = r.watched ? '✓ aggiunto' : '✓ rimosso';
fb2.className = 'feedback ok';
}
// La tabella ha il contatore e il filtro "Seguiti": ricarichiamo la lista.
refresh();
} catch (e) { fail('errore rete'); }
}

// Ignora / togli ignore.
//
// `wasWatched` arriva dalla scheda, non dal server: serve per la conferma
// quando l'utente ignora un dispositivo che sta anche seguendo. La domanda
// ("vuoi togliere anche il follow?") non e' una formality: senza, uno
// schiaccia "Ignora" su un telefono che segue e si ritrova senza notifiche,
// cioe' senza sapere di averle perse.
async function toggleIgnore(mac, wasWatched) {
const btn = document.getElementById('ignore-btn');
const fb = document.getElementById('ignore-feedback');
if (!btn || !fb) return;
const d = allDevices.find(x => x.mac === mac);
const isIgnored = !!(d && d.ignored);
if (!isIgnored && wasWatched) {
const go = confirm('Questo dispositivo è anche seguito.\n\nIgnorarlo lo nasconde dalla tabella, ma le notifiche di arrivo/partenza continueranno.\n\nVuoi togliere anche il follow (niente più notifiche)?');
if (go) { await unfollowQuiet(mac); }
}
const url = isIgnored ? '/api/devices/unignore' : '/api/devices/ignore';
btn.classList.add('busy');
const oldLabel = btn.textContent;
btn.textContent = 'in corso…';
fb.textContent = '';
fb.className = 'feedback';
function fail(msg) { fb.textContent = msg; fb.className = 'feedback err'; btn.classList.remove('busy'); btn.textContent = oldLabel; }
try {
const res = await fetch(url, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ mac: mac })
});
const r = await res.json();
if (!r.ok) { fail('errore: ' + (r.error || '')); return; }
redrawDevice(mac, { ignored: !!r.ignored });
const fb2 = document.getElementById('ignore-feedback');
if (fb2) { fb2.textContent = r.ignored ? '✓ ignorato' : '✓ ripristinato'; fb2.className = 'feedback ok'; }
refresh();
} catch (e) { fail('errore rete'); }
}

// Unfollow senza feedback: lo usa la conferma dell'ignore, che ha gia' la
// sua riga di riscontro. Riusa l'endpoint esistente invece di duplicarlo.
async function unfollowQuiet(mac) {
try {
await fetch('/api/known/unfollow', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ mac: mac })
});
allDevices.forEach(x => { if (x.mac === mac) x.watched = false; });
} catch (e) { /* la tabella si riallinea al prossimo refresh */ }
}

// "Sono io": imposta o revoca. Il server tiene un solo MAC, quindi impostare
// un secondo dispositivo sostituisce il primo: la risposta lo dice, e lo
// mostriamo, perche' un utente che vede sparire il badge dal primo telefono
// senza spiegazione penserebbe a un bug.
async function toggleIsMe(mac) {
const btn = document.getElementById('isme-btn');
const fb = document.getElementById('isme-feedback');
if (!btn || !fb) return;
const d = allDevices.find(x => x.mac === mac);
const isMe = !!(d && d.is_me);
const url = isMe ? '/api/devices/is-me/clear' : '/api/devices/is-me';
const body = isMe ? {} : { mac: mac };
btn.classList.add('busy');
const oldLabel = btn.textContent;
btn.textContent = 'in corso…';
fb.textContent = '';
fb.className = 'feedback';
function fail(msg) { fb.textContent = msg; fb.className = 'feedback err'; btn.classList.remove('busy'); btn.textContent = oldLabel; }
try {
const res = await fetch(url, {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify(body)
});
const r = await res.json();
if (!r.ok) { fail('errore: ' + (r.error || '')); return; }
// Qualunque altro dispositivo perde il badge: il file ne contiene uno solo.
allDevices.forEach(x => { x.is_me = (x.mac === mac) && !isMe; });
redrawDevice(mac, { is_me: !isMe });
const fb2 = document.getElementById('isme-feedback');
if (fb2) {
let msg = isMe ? '✓ tolto' : '✓ impostato';
if (r.previous && r.previous !== mac) msg += ' (prima era ' + r.previous + ')';
fb2.textContent = msg;
fb2.className = 'feedback ok';
}
refresh();
} catch (e) { fail('errore rete'); }
}

// Pannello "Gestisci ignorati".
//
// Legge la lista dal file, non dallo stato live: un MAC ignorato che non e'
// piu' annunciato non e' piu' in tabella ma e' ancora in `ignore.txt`, ed e'
// esattamente il tipo di riga che l'utente dimentica e non trova piu'. Il
// pulsante "Svuota tutto" ha una conferma con il numero dentro ("Rimuovere 47
// dispositivi?"), perche' con un numero annegato nella domanda nessuno
// preme "Sì" e il bottone resta inutile.
async function openIgnoredPanel() {
document.getElementById('ignored-modal').classList.add('active');
const box = document.getElementById('ignored-list');
const fb = document.getElementById('ignored-feedback');
box.innerHTML = '<div class="detail-value" style="color: var(--text-muted);">Caricamento…</div>';
fb.textContent = ''; fb.className = 'feedback';
try {
const res = await fetch('/api/devices/ignored');
const r = await res.json();
renderIgnoredList(r);
} catch (e) { box.innerHTML = '<div class="detail-value" style="color: var(--accent-red);">errore di rete</div>'; }
}
function renderIgnoredList(r) {
const box = document.getElementById('ignored-list');
const macs = r.macs || [];
document.getElementById('ignored-count-inline').textContent = r.count;
const all = document.getElementById('unignore-all-btn');
if (all) { all.textContent = macs.length ? ('Svuota tutto (' + macs.length + ')') : 'Svuota tutto'; all.disabled = !macs.length; }
if (!macs.length) { box.innerHTML = '<div class="detail-value" style="color: var(--text-muted);">Nessun dispositivo ignorato.</div>'; return; }
const nomi = {};
allDevices.forEach(d => { if (d.ignored && d.name) nomi[d.mac] = d.name; });
box.innerHTML = macs.map(m =>
'<div class="ignored-row"><span class="mac">' + escapeHtml(m) + '</span>' +
'<span style="color: var(--text-muted);">' + escapeHtml(nomi[m] || '') + '</span>' +
'<button class="btn" onclick="unignoreOne(\'' + m + '\')">Rimuovi</button></div>'
).join('');
}
function closeIgnoredPanel() { document.getElementById('ignored-modal').classList.remove('active'); }
async function unignoreOne(mac) {
const fb = document.getElementById('ignored-feedback');
try {
const res = await fetch('/api/devices/unignore', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ mac: mac })
});
const r = await res.json();
if (!r.ok) { fb.textContent = 'errore: ' + (r.error || ''); fb.className = 'feedback err'; return; }
const d = allDevices.find(x => x.mac === mac);
if (d) d.ignored = false;
fb.textContent = '✓ ripristinato ' + mac; fb.className = 'feedback ok';
const again = await (await fetch('/api/devices/ignored')).json();
renderIgnoredList(again);
refresh();
} catch (e) { fb.textContent = 'errore rete'; fb.className = 'feedback err'; }
}
async function unignoreAll() {
const fb = document.getElementById('ignored-feedback');
try {
const cur = await (await fetch('/api/devices/ignored')).json();
if (!confirm(cur.count ? ('Rimuovere ' + cur.count + ' dispositivi ignorati?\n\nI commenti in ignore.txt restano.') : 'Non c\'è niente da rimuovere.')) return;
const res = await fetch('/api/devices/ignored/clear', { method: 'POST' });
const r = await res.json();
if (!r.ok) { fb.textContent = 'errore: ' + (r.error || ''); fb.className = 'feedback err'; return; }
allDevices.forEach(d => { d.ignored = false; });
fb.textContent = '✓ rimossi ' + r.removed; fb.className = 'feedback ok';
renderIgnoredList({ count: 0, macs: [] });
refresh();
} catch (e) { fb.textContent = 'errore rete'; fb.className = 'feedback err'; }
}

async function saveRename(mac) {
const inp = document.getElementById('rename-input');
const fb = document.getElementById('rename-feedback');
if (!inp || !fb) return;
inp.disabled = true;
try {
const res = await fetch('/api/devices/rename', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ mac: mac, name: inp.value })
});
const d = await res.json();
if (d.ok) {
fb.textContent = '✓ salvato';
setTimeout(function () { fb.textContent = ''; inp.disabled = false; }, 1500);
const dev = allDevices.find(x => x.mac === mac);
if (dev) dev.name = d.name;
refresh();
} else {
fb.textContent = 'errore: ' + (d.error || '');
inp.disabled = false;
}
} catch (e) {
fb.textContent = 'errore rete';
inp.disabled = false;
}
}
// Deep link ?mac=...: apre direttamente la scheda del dispositivo quando
// compare in elenco (riprovato a ogni refresh finché non viene visto).
let pendingMac = null;
function checkDeepLink() {
let m = pendingMac || new URLSearchParams(location.search).get('mac');
if (!m) return;
const dev = allDevices.find(x => x.mac.toUpperCase() === m.toUpperCase());
if (dev) { pendingMac = null; showDevice(dev.mac); }
else { pendingMac = m; }
}
function closeModal() { document.getElementById('device-modal').classList.remove('active'); }

// ---------------------------------------------------------------------------
// LOG RAW: ultimi pacchetti BLE con hex e decodifica, export per intervallo.
// ---------------------------------------------------------------------------
let rawEvents = [];
let rawTimer = null;
let rawStatus = null;
let rawStats = null;

function openRawModal() {
document.getElementById('raw-modal').classList.add('active');
// Deep link: #raw-mac=AA:BB:... apre il log già filtrato su un dispositivo.
const m = (location.hash.match(/raw-mac=([0-9A-Fa-f:]+)/) || [])[1];
if (m) document.getElementById('raw-filter').value = m;
rawRefresh(true);
// Live refresh mentre il modale è aperto.
if (rawTimer) clearInterval(rawTimer);
rawTimer = setInterval(() => rawRefresh(false), 3000);
}

function closeRawModal() {
document.getElementById('raw-modal').classList.remove('active');
if (rawTimer) { clearInterval(rawTimer); rawTimer = null; }
}

// Converte il valore di un <input datetime-local> (ora locale del browser) in
// RFC3339 UTC: il backend lavora solo in UTC.
function rawLocalToUtc(v) {
if (!v) return '';
const d = new Date(v);
if (isNaN(d.getTime())) return '';
return d.toISOString().replace('.000Z', 'Z');
}

async function rawRefresh(reset) {
try {
// Il filtro e la finestra vanno al server: cosi' un device vecchio, che non
// e' fra gli ultimi N pacchetti, si trova lo stesso.
const p = new URLSearchParams();
p.set('limit', '300');
const q = (document.getElementById('raw-filter').value || '').trim();
if (q) p.set('q', q);
const from = document.getElementById('raw-from').value;
const to = document.getElementById('raw-to').value;
if (from) p.set('from', new Date(from).toISOString().replace('.000Z', 'Z'));
if (to) p.set('to', new Date(to).toISOString().replace('.000Z', 'Z'));
const res = await fetch('/api/raw?' + p.toString());
const d = await res.json();
rawEvents = d.events || [];
rawStatus = d;
rawRender();
rawRenderStatus();
rawRenderToggle(d.enabled);
rawRefreshStats();
rawRefreshPresence();
} catch (e) {
console.error('Errore raw log:', e);
}
}

// Statistiche per dispositivo sull'intervallo indicato nei campi da/a, cosi'
// lo studio e' coerente con l'export: se cambio la finestra, ricalcola tutto.
async function rawRefreshStats() {
const from = document.getElementById('raw-from').value;
const to = document.getElementById('raw-to').value;
const p = new URLSearchParams();
if (from) p.set('from', new Date(from).toISOString().replace('.000Z', 'Z'));
if (to) p.set('to', new Date(to).toISOString().replace('.000Z', 'Z'));
try {
const res = await fetch('/api/raw/stats?' + p.toString());
const d = await res.json();
rawStats = d.devices || [];
rawRenderStats();
} catch (e) {
console.error('Errore statistiche raw:', e);
}
}

function rawRenderStats() {
const el = document.getElementById('raw-stats');
if (!el) return;
if (!rawStats || rawStats.length === 0) {
el.innerHTML = '<span style="color: var(--text-muted);">Nessun pacchetto nell\'intervallo scelto</span>';
return;
}
const fmt = ms => (ms == null ? '—' : (ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : ms + 'ms'));
el.innerHTML = '<table style="width: 100%; border-collapse: collapse;">'
+ '<tr style="text-align: left; color: var(--text-muted); font-size: 0.62rem;">'
+ '<th style="padding: 0.15rem 0.4rem;">MAC</th><th style="padding: 0.15rem 0.4rem;">NOME/HINT</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">PKT</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">RSSI min/avg/max</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">CADENZA med/p95</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">PAYLOAD</th></tr>'
+ rawStats.slice(0, 40).map(d => {
const who = d.name || d.hint || d.vendor || '<senza nome>';
// Badge del blob Continuity: sotto quanti indirizzi diversi e' comparso lo
// stesso valore Apple per questo MAC. Non fondiamo le righe, diamo il contesto.
const sc = rawPresence && rawPresence.seed_counts ? rawPresence.seed_counts[d.mac] : null;
const badge = sc && sc.mac_count > 1
? ' <span title="lo stesso valore Apple Continuity visto sotto ' + sc.mac_count + ' indirizzi diversi" style="color: var(--accent-amber); cursor: help;">↻' + sc.mac_count + '</span>'
: '';
return '<tr style="cursor: pointer; border-top: 1px solid var(--border-color);" '
+ 'onclick="rawFilterMac(\'' + d.mac + '\')" title="clicca per filtrare i pacchetti">'
+ '<td style="padding: 0.15rem 0.4rem; color: var(--accent-cyan);">' + escapeHtml(d.mac) + badge + '</td>'
+ '<td style="padding: 0.15rem 0.4rem;">' + escapeHtml(who) + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + d.packets + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + d.rssi_min + ' / ' + d.rssi_avg + ' / ' + d.rssi_max + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + fmt(d.interval_median_ms) + ' / ' + fmt(d.interval_p95_ms) + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + d.distinct_payloads + '</td>'
+ '</tr>';
}).join('')
+ '</table>';
}

// ---------------------------------------------------------------------------
// Presenza e stato radio.
// ---------------------------------------------------------------------------
let rawPresence = null;

async function rawRefreshPresence() {
const el = document.getElementById('raw-presence');
const radioEl = document.getElementById('raw-radio');
if (!el) return;
const p = new URLSearchParams();
const from = document.getElementById('raw-from').value;
const to = document.getElementById('raw-to').value;
if (from) p.set('from', new Date(from).toISOString().replace('.000Z', 'Z'));
if (to) p.set('to', new Date(to).toISOString().replace('.000Z', 'Z'));
try {
const res = await fetch('/api/presence?' + p.toString());
const d = await res.json();
rawPresence = d;
rawRenderRadio(d.radio);
rawRenderPresence(d);
rawRenderSeeds(d);
rawRenderStats(); // i badge ↻N dipendono dai dati di presenza
rawRefreshClients();
} catch (e) {
el.innerHTML = '<span style="color: var(--accent-amber);">Analisi di presenza non disponibile</span>';
}
}

// Client HTTP che hanno contattato la dashboard. Utile solo quando e'
// esposta in rete locale: di default ascolta su 127.0.0.1 e l'elenco ha una
// voce sola.
async function rawRefreshClients() {
const el = document.getElementById('raw-clients');
if (!el) return;
try {
const d = await (await fetch('/api/clients')).json();
if (!d.unique_ips) {
el.innerHTML = 'Client collegati: <b>nessuno</b>';
return;
}
const rows = (d.clients || []).map(c => '<tr style="border-top: 1px solid var(--border-color);">'
+ '<td style="padding: 0.15rem 0.4rem; color: var(--accent-cyan);">' + escapeHtml(c.ip) + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + c.requests + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + c.idle_seconds + ' s fa</td>'
+ '<td style="padding: 0.15rem 0.4rem; color: var(--text-muted);">' + escapeHtml(c.last_path) + '</td>'
+ '</tr>').join('');
el.innerHTML = 'Client collegati: <b>' + d.unique_ips + '</b> IP distinti · ' + d.total_requests + ' richieste'
+ '<table style="width: 100%; border-collapse: collapse; margin-top: 0.3rem;">'
+ '<tr style="text-align: left; color: var(--text-muted); font-size: 0.62rem;">'
+ '<th style="padding: 0.15rem 0.4rem;">IP</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">RICHIESTE</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">ULTIMA</th>'
+ '<th style="padding: 0.15rem 0.4rem;">ULTIMA PAGINA</th></tr>'
+ rows + '</table>'
+ '<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.25rem;">'
+ 'Solo indirizzi IP: non registriamo richieste, header o contenuti. Un IP può corrispondere a più clienti reali (NAT, proxy): sono stime, non identità.</div>';
} catch (e) { /* la dashboard resta utilizzabile anche senza questo pannello */ }
}

function rawRenderRadio(r) {
const el = document.getElementById('raw-radio');
if (!el || !r) return;
const color = r.reliable ? 'var(--accent-green)' : 'var(--accent-amber)';
const since = r.since_last_ble_ms == null ? 'mai' : Math.round(r.since_last_ble_ms / 1000) + ' s fa';
// Il colore e' deliberatamente forte: se il radio non sta guardando, ogni
// altra riga della pagina e' da prendere con le pinze.
el.style.borderColor = color;
el.innerHTML = 'Radio: <b style="color: ' + color + '">' + escapeHtml(r.health_it) + '</b>'
+ ' · adapter ' + (r.adapter_opened ? 'aperto' : 'non aperto')
+ ' · pacchetti BLE ' + r.ble_packets
+ ' · ultimo ' + since
+ (r.mute_events > 0 ? ' · <span style="color: var(--accent-amber);">' + r.mute_events + ' interruzioni</span>' : '')
+ (r.reliable ? '' : '<br><span style="color: var(--accent-amber);">⚠ l\'osservazione non è affidabile: ciò che manca può essere il radio, non i dispositivi</span>');
}

function rawRenderPresence(d) {
const el = document.getElementById('raw-presence');
if (!el) return;
const rows = d.missing || [];
if (rows.length === 0) {
el.innerHTML = '<span style="color: var(--text-muted);">Nessun dispositivo noto è silenzioso (soglia ' + d.config.silent_minutes + ' min, minimo ' + d.config.min_packets + ' pacchetti)</span>';
return;
}
el.innerHTML = '<table style="width: 100%; border-collapse: collapse;">'
+ '<tr style="text-align: left; color: var(--text-muted); font-size: 0.62rem;">'
+ '<th style="padding: 0.15rem 0.4rem;">MAC</th><th style="padding: 0.15rem 0.4rem;">CHI</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">PKT</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">ULTIMO VISTO</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">RSSI</th></tr>'
+ rows.slice(0, 20).map(r => {
const who = r.name || r.hint || r.vendor || '—';
const rel = r.reliable ? '' : ' style="color: var(--text-muted);"';
return '<tr style="cursor: pointer; border-top: 1px solid var(--border-color);" onclick="rawFilterMac(\'' + r.mac + '\')" title="' + escapeHtml(r.reason) + '">'
+ '<td style="padding: 0.15rem 0.4rem; color: var(--accent-cyan);">' + escapeHtml(r.mac) + '</td>'
+ '<td style="padding: 0.15rem 0.4rem;">' + escapeHtml(who) + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + r.packets + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;"' + rel + '>' + r.silent_minutes + ' min fa · ' + escapeHtml(r.last_seen) + '</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + r.rssi_avg + '</td>'
+ '</tr>';
}).join('')
+ '</table>'
+ '<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.25rem;">'
+ 'Un silenzio non è una prova: il dispositivo può essere andato via, spento, o aver cambiato MAC. Passa il mouse per il motivo. Non conosciamo il numero di dispositivi presenti.</div>';
}

function rawRenderSeeds(d) {
const el = document.getElementById('raw-seeds');
if (!el) return;
const groups = d.continuity_groups || [];
if (groups.length === 0) {
el.innerHTML = '<span style="color: var(--text-muted);">Nessun valore Apple Continuity ripetuto su indirizzi diversi</span>';
return;
}
el.innerHTML = '<table style="width: 100%; border-collapse: collapse;">'
+ '<tr style="text-align: left; color: var(--text-muted); font-size: 0.62rem;">'
+ '<th style="padding: 0.15rem 0.4rem;">VALORE</th>'
+ '<th style="padding: 0.15rem 0.4rem; text-align: right;">INDIRIZZI</th>'
+ '<th style="padding: 0.15rem 0.4rem;">MAC</th></tr>'
+ groups.slice(0, 12).map(g => '<tr style="border-top: 1px solid var(--border-color);">'
+ '<td style="padding: 0.15rem 0.4rem; color: var(--accent-amber);">' + escapeHtml(g.seed_short) + '…</td>'
+ '<td style="padding: 0.15rem 0.4rem; text-align: right;">' + g.mac_count + '</td>'
+ '<td style="padding: 0.15rem 0.4rem;">' + g.macs.slice(0, 6).map(escapeHtml).join(', ') + (g.macs.length > 6 ? ' …' : '') + '</td>'
+ '</tr>').join('')
+ '</table>'
+ '<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.25rem;">'
+ 'Apple deriva questo valore per dispositivo e lo tiene costante. Che compaia sotto più indirizzi è un indizio forte, ma non una prova d\'identità: i dispositivi restano righe separate.</div>';
}

// Filtra i pacchetti su un MAC e lo mette nel link: chi studia un tracker puo'
// salvare e riaprire la vista gia' pronta.
// Ricerca manuale: niente diRefresh a ogni tasto (sarebbe una richiesta per
// carattere), ma entro mezzo secondo si aggiorna.
let rawDebounce = null;
function rawDebouncedRefresh() {
if (rawDebounce) clearTimeout(rawDebounce);
rawDebounce = setTimeout(() => rawRefresh(false), 400);
}

function rawFilterMac(mac) {
document.getElementById('raw-filter').value = mac;
history.replaceState(null, '', '#raw-mac=' + mac);
rawRefresh(false);
}

function rawRenderStatus() {
if (!rawStatus) return;
const el = document.getElementById('raw-status');
const mb = (rawStatus.file_size / (1024 * 1024)).toFixed(1);
const capMb = (rawStatus.rotate_bytes / (1024 * 1024)).toFixed(0);
el.innerHTML = 'Registrazione <b>' + (rawStatus.enabled ? 'ATTIVA' : 'DISATTIVATA') + '</b> · registrati <b>' + rawStatus.recorded + '</b> pacchetti' + (rawStatus.dropped > 0 ? ' · <span style=\'color: var(--accent-amber);\'>scartati ' + rawStatus.dropped + ' (coda piena)</span>' : '') + ' · file <b>' + escapeHtml(rawStatus.file) + '</b> (' + mb + ' MB / rotazione a ' + capMb + ' MB, retention ' + rawStatus.retention_days + ' giorni) · mostrati gli ultimi ' + rawEvents.length;
}

function rawRenderToggle(enabled) {
const btn = document.getElementById('raw-toggle-btn');
btn.textContent = enabled ? '⏸ Disattiva log' : '▶ Riattiva log';
btn.style.background = enabled ? '' : 'var(--accent-green)';
}

async function rawToggle() {
const d = rawStatus || {};
const action = d.enabled ? 'disable' : 'enable';
try {
await fetch('/api/raw/' + action, { method: 'POST' });
await rawRefresh(false);
} catch (e) {
console.error('Errore toggle raw log:', e);
}
}

function rawExport() {
const from = rawLocalToUtc(document.getElementById('raw-from').value);
const to = rawLocalToUtc(document.getElementById('raw-to').value);
const format = document.getElementById('raw-format').value;
const params = new URLSearchParams();
if (from) params.set('from', from);
if (to) params.set('to', to);
params.set('format', format);
// Navigazione diretta: il server risponde con Content-Disposition
// attachment, quindi il browser scarica senza cambiare pagina.
window.location.href = '/api/raw/export?' + params.toString();
}

function rawRender() {
const tbody = document.getElementById('raw-tbody');
const filter = (document.getElementById('raw-filter').value || '').trim();
// Il server ha gia' filtrato: non rifiltriamo qui, senn\u00f2 il filtro
// ripartirebbe dal sottoinsieme gi\u00e0 filtrato e taglierebbe i pacchetti.
const rows = rawEvents;
// I pi\u00f9 recenti in cima (il server restituisce in ordine cronologico).
const sorted = rows.slice().reverse();
const rowsHtml = sorted.slice(0, 500).map(ev => {
const ts = (ev.ts || '').replace('T', ' ').replace('Z', '');
const decode = (ev.decode || []).join('<br>');
const hexGrouped = (ev.hex || '').replace(/(.{16})/g, '$1 ');
const advCls = ev.scan_response ? 'color: var(--accent-cyan);' : '';
return '<tr>' +
'<td style="padding: 0.25rem 0.5rem; white-space: nowrap; color: var(--text-secondary);">' + escapeHtml(ts) + '</td>' +
'<td style="padding: 0.25rem 0.5rem; white-space: nowrap;">' + escapeHtml(ev.mac || '') + (ev.name ? '<div style="color: var(--text-secondary); font-size: 0.62rem;">' + escapeHtml(ev.name) + '</div>' : '') + '</td>' +
'<td style="padding: 0.25rem 0.5rem; white-space: nowrap; ' + advCls + '">' + escapeHtml(ev.adv_type || '') + (ev.scan_response ? ' ↩' : '') + (ev.addr_type === 'random' ? ' <span style=\'color: var(--accent-blue);\'>R</span>' : '') + '</td>' +
'<td style="padding: 0.25rem 0.5rem; text-align: right; white-space: nowrap;">' + (ev.rssi != null ? ev.rssi : '') + '</td>' +
'<td style="padding: 0.25rem 0.5rem; word-break: break-all; max-width: 340px; color: var(--accent-amber);">' + (ev.hex ? escapeHtml(hexGrouped.trim()) : '<span style="color: var(--text-muted);">— nessun AD</span>') + '</td>' +
'<td style="padding: 0.25rem 0.5rem; word-break: break-word; max-width: 380px; color: var(--text-secondary);">' + (decode || '<span style="color: var(--text-muted);">—</span>') + '</td>' +
'</tr>';
}).join('');

// Se il filtro non trova nulla, non dire "nessun pacchetto": puo' essere che
// il device sia semplicemente piu' vecchio della coda mostrata. Le
// statistiche sanno quanti pacchetti ha nel file, quindi usiamele per essere
// onesti invece di lasciare un vuoto che sembra un errore.
let empty = '<tr><td colspan="6" style="padding: 1rem; text-align: center; color: var(--text-muted);">';
if (!rowsHtml && filter && rawStats) {
const mac = filter.trim().toUpperCase();
const known = rawStats.find(d => d.mac.toUpperCase() === mac);
if (known) {
empty += escapeHtml(known.mac) + ' ha ' + known.packets + ' pacchetti registrati, ma non nella finestra scelta (da/ad): allarga l\u2019intervallo o usa Esporta';
} else {
empty += 'Nessun pacchetto registrato per questo filtro';
}
empty += '</td></tr>';
} else if (!rowsHtml) {
empty += 'Nessun pacchetto registrato' + (filter ? ' per questo filtro' : '') + '</td></tr>';
}

tbody.innerHTML = rowsHtml || empty;
}
function showLegendModal() { document.getElementById('legend-modal').classList.add('active'); }
// Apre la legenda solo alla prima visita, e solo una volta. Un utente che
// torna ogni giorno non vuole un pannello che gli spiega "cosa significa
// phantom" ogni volta che apre la pagina: il flag è locale e sopravvive al
// riavvio della dashboard.
function showLegendOnce() {
let seen = null;
try { seen = localStorage.getItem('bn.legend.seen'); } catch (e) { seen = null; }
if (seen === '1') return;
// In screenshot mode il riquadro coprirebbe proprio la parte da
// fotografare: la tabella dei dispositivi.
try { localStorage.setItem('bn.legend.seen', '1'); } catch (e) { /* modalità privata */ }
setTimeout(showLegendModal, 700);
}
function closeLegendModal() { document.getElementById('legend-modal').classList.remove('active'); }
function showShortcutsModal() { document.getElementById('shortcuts-modal').classList.add('active'); }
function closeShortcutsModal() { document.getElementById('shortcuts-modal').classList.remove('active'); }

// Radar: posizione angolare stabile (hash del MAC), distanza dall'RSSI.
function macAngle(mac) {
let h = 0;
for (let i = 0; i < mac.length; i++) h = (h * 31 + mac.charCodeAt(i)) >>> 0;
return (h % 360) * Math.PI / 180;
}
function renderPktChart(history) {
const h = history || [];
if (h.length === 0) return '';
const max = Math.max.apply(null, h);
const bars = h.map(c => {
const pct = max > 0 ? Math.max(2, Math.round((c / max) * 100)) : 2;
return '<div class="pkt-bar" style="height: ' + pct + '%;" title="' + c + ' pacchetti"></div>';
}).join('');
return '<div class="pkt-chart">' + bars + '</div>' +
'<div style="font-size: 0.55rem; color: var(--text-muted); margin-top: 0.2rem;">pacchetti per finestra · ultimi ' + h.length + '×5s</div>';
}

let silentState = false;
let muted = localStorage.getItem('bluesniff_mute') === 'true';
function playAlarm() {
if (muted) return;
try {
const ctx = new (window.AudioContext || window.webkitAudioContext)();
for (let i = 0; i < 3; i++) {
const osc = ctx.createOscillator();
const gain = ctx.createGain();
osc.type = 'square';
osc.frequency.value = 880;
osc.connect(gain);
gain.connect(ctx.destination);
const t = ctx.currentTime + i * 0.45;
gain.gain.setValueAtTime(0.12, t);
gain.gain.exponentialRampToValueAtTime(0.001, t + 0.35);
osc.start(t);
osc.stop(t + 0.35);
}
} catch (e) {}
}
function toggleMute() {
muted = !muted;
localStorage.setItem('bluesniff_mute', muted);
const b = document.getElementById('mute-btn');
if (b) b.textContent = muted ? '🔕 allarme silenziato' : '🔔 allarme attivo';
}
async function retryScan() {
const btn = document.getElementById('scan-retry-btn');
const old = btn ? btn.textContent : '';
if (btn) { btn.disabled = true; btn.textContent = 'Scansione in corso...'; }
try {
await fetch('/api/scan/retry', { method: 'POST' });
await refresh();
} catch (e) {
console.error('Errore retry scan:', e);
}
if (btn) { btn.disabled = false; btn.textContent = old; }
}

// Ferma il processo dall'interfaccia. Il server risponde subito ma la
// dashboard muore con lui: sostituiamo la pagina con un avviso, altrimenti
// l'utente vede un'interfaccia viva che non riceve piu' nulla e pensa che il
// pulsante non abbia funzionato.
async function stopBluesniff() {
if (!confirm('Fermare bluesniff? Il processo chiude e libera il PC. La dashboard non rispondera piu')) return;
const btn = document.getElementById('scan-stop-btn');
if (btn) { btn.disabled = true; btn.textContent = '⏳ Arresto in corso…'; }
try { await fetch('/api/scan/stop', { method: 'POST' }); } catch (e) { /* il server muore: era previsto */ }
document.body.innerHTML = '<div style="padding: 4rem 1.5rem; text-align: center; font-family: -apple-system, system-ui, sans-serif; color: #888; line-height: 1.6;">' +
'<div style="font-size: 2rem;">⏹</div>' +
'<div style="font-size: 1rem; color: #e0e0e0; margin-top: 0.5rem;"><b>bluesniff fermato</b></div>' +
'<div style="font-size: 0.8rem; margin-top: 0.5rem;"><p>Puoi chiudere questa pagina. I dati registrati sono in presenze.csv.<br>Per ripartire: <code>bluesniff</code></p></div></div>';
}

async function pauseScan() {
try {
await fetch('/api/scan/pause', { method: 'POST' });
await refreshRadio();
} catch (e) {
console.error('Errore pausa scansione:', e);
}
}

async function resumeScan() {
try {
await fetch('/api/scan/resume', { method: 'POST' });
await refreshRadio();
} catch (e) {
console.error('Errore ripresa scansione:', e);
}
}

// Esito dell'ultimo reset radio. Vive fuori dal DOM perché renderRadio
// ricostruisce l'innerHTML del pannello a ogni refresh: senza questa copia
// il messaggio sparirebbe subito dopo essere comparso.
let radioResetMsg = '';
let radioResetOk = true;
let radioResetBusy = false;

// Spegne e riaccende la radio Bluetooth: recupera uno scanner LE muto senza
// riavviare il PC. L'esito arriva dal server in d.message.
async function resetRadio() {
const btn = document.getElementById('radio-reset-btn');
if (btn) { btn.disabled = true; btn.textContent = '⏳ Reset in corso…'; }
radioResetBusy = true;
radioResetOk = true;
radioResetMsg = 'Reset in corso: spengo la radio 2s e la riaccendo…';
await refreshRadio();
try {
const res = await fetch('/api/radio/reset', { method: 'POST' });
const d = await res.json();
radioResetOk = !!d.ok;
radioResetMsg = (d.ok ? '✔ ' : '✖ ') + (d.message || '');
} catch (e) {
radioResetOk = false;
radioResetMsg = '✖ Reset non riuscito: ' + e;
}
radioResetBusy = false;
await refreshRadio();
}

function renderRadio(d) {
const el = document.getElementById('radio-info');
if (!el) return;
// Allarme: suona e lampeggia solo alla transizione muta.
if (d.silent && !silentState) {
silentState = true;
playAlarm();
}
if (!d.silent) {
silentState = false;
}
let warn = '';
if (d.silent) {
warn = '<div style="background: rgba(220, 38, 38, 0.15); border: 1px solid var(--accent-red); color: var(--accent-red); border-radius: 3px; padding: 0.4rem; font-size: 0.65rem; margin-bottom: 0.4rem; animation: pulse 1s infinite;">⚠ Radio muta da ' + Math.round((d.silent_secs || 0) / 60) + ' min: nessun pacchetto BLE ricevuto. Verifica il pass-through USB del dongle o riavvialo (Impostazioni → Bluetooth → spegni/accendi). ' +
'<button class="btn" id="mute-btn" onclick="toggleMute()" style="margin-top: 0.3rem; width: 100%; font-size: 0.6rem; padding: 0.3rem;">' + (muted ? '🔕 allarme silenziato' : '🔔 allarme attivo') + '</button></div>';
}
if (!d.radios || d.radios.length === 0) {
el.innerHTML = warn + '<div class="radar-empty">Nessuna radio rilevata dal sistema</div>';
return;
}
const r = d.radios[0];
const st = r.state === 'on'
? '<span style="color: var(--accent-green); font-weight: 700;">● ON</span>'
: '<span style="color: var(--accent-red); font-weight: 700;">● OFF</span>';
// Portata del dongle: attenuazione ambiente (P10 dei path loss) e portata
// teorica stimata; quando atten è disponibile le distanze del radar/scheda
// vengono corrette con essa.
let rangeHtml = '';
if (d.range && d.range.samples > 0) {
const atten = d.range.atten_db == null ? 'in raccolta...' : '~' + d.range.atten_db.toFixed(1) + ' dB';
const portata = d.range.range_m == null ? '—' :
(d.range.range_m > 1000 ? '> 1 km' : '~' + d.range.range_m.toFixed(1) + ' m');
rangeHtml = '<div style="font-size: 0.7rem; margin-top: 0.45rem; padding-top: 0.3rem; border-top: 1px solid var(--border-color);">📏 <b>Portata dongle</b>' +
'<div style="font-size: 0.65rem; color: var(--text-secondary); margin-top: 0.2rem;">attenuazione ambiente <b>' + atten + '</b> · portata teorica <b>' + portata + '</b> · ' + d.range.samples + ' campioni path-loss</div>' +
'<div style="font-size: 0.55rem; color: var(--text-muted); margin-top: 0.15rem;">stima dall\'attenuazione dei dispositivi vicini (P10 di tx−rssi, n=2.0, floor −96 dBm); corregge le distanze mostrate</div></div>';
}
// Modalità scansione e stato pausa
const modeLabel = d.passive ? '<span style="color: var(--accent-amber);">PASSIVE</span>' : '<span style="color: var(--accent-green);">ACTIVE</span>';
const pauseBtn = d.paused
? '<button class="btn" id="scan-pause-btn" onclick="resumeScan()" style="width: 100%; margin-top: 0.4rem; background: var(--accent-green);">▶ Riprendi scansione</button>'
: '<button class="btn" id="scan-pause-btn" onclick="pauseScan()" style="width: 100%; margin-top: 0.4rem;">⏸ Pausa scansione</button>';
el.innerHTML = warn +
'<div style="font-size: 0.75rem; margin-bottom: 0.35rem;">' + st + ' <span class="mac-addr">' + obfuscateMAC(r.mac || '') + '</span></div>' +
'<div style="font-size: 0.7rem; color: var(--text-secondary); margin-bottom: 0.35rem;">' + obfuscateName(r.name || '') + '</div>' +
'<div style="font-size: 0.7rem; margin-bottom: 0.35rem;">📡 Modalità: ' + modeLabel + (d.paused ? ' <span style="color: var(--accent-red);">● IN PAUSA</span>' : '') + '</div>' +
'<div style="font-size: 0.7rem; margin-bottom: 0.35rem;">🎯 Radio attiva: ' + (d.selected ? escapeHtml('[' + d.selected.index + '] ' + obfuscateMAC(d.selected.address) + ' (' + obfuscateName(d.selected.name) + ')') : 'predefinita di sistema') + '</div>' +
'<div style="font-size: 0.75rem;">📡 pacchetti BLE: <span style="color: var(--accent-amber); font-weight: 700;">' + (d.packets || 0) + '</span></div>' +
renderPktChart(d.packet_history) +
'<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.3rem;">conteggio totale dal avvio · aggiornato ogni 5s</div>' +
rangeHtml +
pauseBtn +
'<button class="btn" id="radio-reset-btn" onclick="resetRadio()" style="width: 100%; margin-top: 0.4rem;">⟳ Reset radio (off/on)</button>' +
'<div id="radio-reset-msg" style="font-size: 0.65rem; margin-top: 0.25rem; color: ' + (radioResetBusy ? 'var(--text-muted)' : (radioResetOk ? 'var(--accent-green)' : 'var(--accent-red)')) + ';">' + escapeHtml(radioResetMsg) + '</div>' +
'<button class="btn" id="scan-retry-btn" onclick="retryScan()" style="width: 100%; margin-top: 0.4rem;">⟳ Riprova scansione (~9s)</button>' +
// Fermare il processo e' definitivo: sta in fondo, dopo tutto quello
// che e' reversibile, e chiede conferma.
'<button class="btn" id="scan-stop-btn" onclick="stopBluesniff()" style="width: 100%; margin-top: 0.4rem; color: var(--accent-red);">⏹ Ferma bluesniff</button>' +
'<div style="font-size: 0.6rem; color: var(--text-muted); margin-top: 0.2rem;">chiude il processo: i dati restano salvati, poi la dashboard non risponde</div>';
}
async function refreshRadio() {
try {
const res = await fetch('/api/radio');
const d = await res.json();
renderRadio(d);
} catch (e) {
console.error('Errore radio:', e);
}
}

function renderInquiry(d) {
const el = document.getElementById('inquiry-info');
if (!el) return;
const count = d.count || 0;
const ts = d.timestamp ? new Date(d.timestamp).toLocaleTimeString('it-IT') : 'mai';
const btn = document.getElementById('inquiry-run');
if (btn) btn.disabled = false;
if (count === 0) {
el.innerHTML = '<div class="radar-empty">Nessun dispositivo classic trovato · ultima: ' + ts + '</div>';
return;
}
el.innerHTML = '<div style="font-size: 0.6rem; color: var(--text-muted); margin-bottom: 0.35rem;">' + count + ' dispositivo/i · ' + ts + '</div>' +
d.devices.map(x =>
'<div style="font-size: 0.7rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border-color);">' +
'<span class="mac-addr">' + escapeHtml(x.mac) + '</span> ' +
(x.name ? escapeHtml(x.name) : '') +
'<span style="color: var(--text-muted); font-size: 0.6rem; float: right;">' + escapeHtml(x.class) + '</span></div>'
).join('');
}
let eventsFilter = 'all';
let lastEvents = { events: [] };
let monitorRunning = false;
const EF_LABELS = { all: 'Tutti', new: 'Nuovi', packets: 'Pacchetti', gone: 'Spariti', spam: 'Spam' };
function eventMatchesFilter(e) {
if (eventsFilter === 'all') return true;
if (eventsFilter === 'new') return (e.new_devices || []).length > 0;
if (eventsFilter === 'packets') return (e.packets || 0) > 0;
if (eventsFilter === 'gone') return (e.gone_devices || []).length > 0;
if (eventsFilter === 'spam') return !!(e.spam && e.spam.detected);
return true;
}
function renderEvents(d) {
const el = document.getElementById('events-info');
if (!el) return;
const evs = d.events || [];
const sum = document.getElementById('events-summary');
// Contatore aggregato per ora: ultima ora di eventi.
const now = Date.now();
const hour = evs.filter(e => e.ts && (now - new Date(e.ts).getTime()) < 3600000);
const nNew = hour.reduce((a, e) => a + (e.new_devices || []).length, 0);
const nPkt = hour.reduce((a, e) => a + (e.packets || 0), 0);
const nGone = hour.reduce((a, e) => a + (e.gone_devices || []).length, 0);
const nRssi = hour.reduce((a, e) => a + (e.rssi_updates || []).length, 0);
const nSpam = hour.reduce((a, e) => a + (e.spam && e.spam.detected ? 1 : 0), 0);
if (sum) {
if (hour.length > 0) {
sum.style.display = '';
sum.textContent = 'Ultima ora: ' + nNew + ' nuovi · ' + nPkt + ' pkt · ' + nGone + ' spariti' + (nRssi ? ' · ' + nRssi + ' ~rssi' : '') + (nSpam ? ' · ' + nSpam + ' ⚠spam' : '');
sum.style.textAlign = 'left';
sum.style.padding = '0.3rem 0.5rem';
sum.style.fontSize = '0.65rem';
} else {
sum.style.display = 'none';
}
}
if (evs.length === 0) {
el.innerHTML = '<div class="radar-empty">Nessun evento (filtro: ' + (EF_LABELS[eventsFilter] || eventsFilter) + ') — avvia il monitor: bluesniff.exe --inq</div>';
return;
}
const filtered = evs.filter(eventMatchesFilter);
if (filtered.length === 0) {
el.innerHTML = '<div class="radar-empty">Nessun evento di questo tipo</div>';
return;
}
el.innerHTML = filtered.slice(0, 12).map(e => {
const ts = e.ts ? new Date(e.ts).toLocaleTimeString('it-IT') : '';
const parts = [];
(e.new_devices || []).forEach(nd => {
parts.push('<span style="color: var(--accent-green);">[+]</span> <span class="evt-link" title="Apri la scheda" onclick="tryShowDevice(\'' + nd.mac + '\')">' + escapeHtml(nd.name || nd.mac || '') + '</span> <span style="color: var(--text-muted);">(' + (nd.type || '') + ')</span>');
});
(e.gone_devices || []).forEach(g => {
parts.push('<span style="color: var(--accent-amber);">[-]</span> <span class="evt-link" title="Apri la scheda" onclick="tryShowDevice(\'' + g.mac + '\')">' + escapeHtml(g.name || g.mac || '') + '</span>');
});
(e.rssi_updates || []).forEach(r => {
const dir = r.to > r.from ? '▲' : '▼';
const nm = r.name && r.name !== r.mac ? escapeHtml(r.name) + ' ' : '';
parts.push('<span style="color: var(--accent-cyan);">[~]</span> ' + nm + '<span class="evt-link" title="Apri la scheda" onclick="tryShowDevice(\'' + r.mac + '\')">' + escapeHtml(r.mac || '') + '</span> ' + r.from + '→' + r.to + ' dBm ' + dir);
});
if (e.packets > 0) {
parts.push('<span style="color: var(--accent-cyan);">📡</span> ' + e.packets + ' pkt');
}
if (e.spam && e.spam.detected) {
const dup = (e.spam.dup_model_ids || []).map(x => escapeHtml(x.model || String(x.model_id))).join(', ');
const ph = e.spam.popup_hard || 0;
parts.push('<span style="color: #f0a6ff; font-weight: 700;">[SPAM]</span> ' + (ph ? 'burst ' + ph + ' popup/phantom' : '') + (dup ? ' · stesso Modello ID da più MAC (' + dup + ')' : '') + ' — <span style="color: var(--text-muted);">possibile spammer BLE</span>');
}
if (parts.length === 0) {
parts.push('<span style="color: var(--text-muted);">silenzio</span>');
}
return '<div style="font-size: 0.65rem; padding: 0.2rem 0; border-bottom: 1px solid var(--border-color);">' +
'<span style="color: var(--text-muted);">' + ts + '</span> ' + parts.join(' ') + '</div>';
}).join('') +
'<div style="font-size: 0.55rem; color: var(--text-muted); margin-top: 0.3rem;">feed dal monitor --inq (inq_events.jsonl)</div>';
}
async function refreshEvents() {
try {
const res = await fetch('/api/events');
const d = await res.json();
lastEvents = d;
monitorRunning = !!d.monitor_running;
setMonitorBtn();
renderEvents(d);
} catch (e) {
console.error('Errore events:', e);
}
}
function setMonitorBtn() {
const btn = document.getElementById('monitor-btn');
if (!btn) return;
if (monitorRunning) {
btn.textContent = '■ Ferma monitor';
btn.title = 'Il monitor --inq è in esecuzione: clicca per fermarlo';
} else {
btn.textContent = '▶ Avvia monitor';
btn.title = 'Avvia il monitor --inq come processo separato (feed inq_events.jsonl)';
}
}
async function toggleMonitor() {
const btn = document.getElementById('monitor-btn');
if (!btn) return;
btn.disabled = true;
try {
if (monitorRunning) {
await fetch('/api/events/stop', { method: 'POST' });
} else {
await fetch('/api/events', { method: 'POST' });
}
} catch (e) {
console.error('Errore toggle monitor:', e);
}
btn.disabled = false;
refreshEvents();
}
// Feed eventi: click su un dispositivo -> apre la scheda. Se il dispositivo
// non è (ancora) nella tabella (es. dashboard-only + monitor separato),
// apre una scheda minima con i dati dell'evento.
function tryShowDevice(mac) {
const d = allDevices.find(x => x.mac.toUpperCase() === mac.toUpperCase());
if (d) { showDevice(d.mac); return; }
let name = '';
(lastEvents.events || []).forEach(e => {
(e.new_devices || []).forEach(nd => { if (nd.mac === mac) name = nd.name || mac; });
(e.gone_devices || []).forEach(g => { if (g.mac === mac) name = g.name || name || mac; });
(e.rssi_updates || []).forEach(r => { if (r.mac === mac) name = r.name || name || mac; });
});
// Se il dispositivo e' gia' in lista usiamo la scheda vera: il fallback qui
// sotto mostrava `watched: false` e zero avvistamenti per un device che in
// tabella era seguito e visto 300 volte, e i pulsoni "Segui"/"Ignora" su quel
// fallback avrebbero scritto una riga duplicata per un MAC gia' presente.
const reale = allDevices.find(x => x.mac === mac);
if (reale) { showDeviceData(reale); return; }
showDeviceData({
mac: mac, name: name || mac, vendor: '', rssi: null, zone: '-', category: 'other',
randomized: false, identified: false, watched: false, ignored: false, is_me: false, active: false,
sightings: 0, first_seen: new Date().toISOString(), last_seen: new Date().toISOString(),
rssi_history: []
});
}
// Filtri eventi: delegazione sul contenitore (sopravvive a eventuali
// re-render della lista) — un click sulla voce filtra subito il feed.
document.getElementById('events-filter-group').addEventListener('click', function (e) {
const b = e.target.closest('[data-efilter]');
if (!b) return;
eventsFilter = b.dataset.efilter;
document.querySelectorAll('[data-efilter]').forEach(x => x.classList.toggle('active', x === b));
renderEvents(lastEvents);
});

async function refreshInquiry() {
try {
const res = await fetch('/api/inquiry');
const d = await res.json();
renderInquiry(d);
} catch (e) {
console.error('Errore inquiry:', e);
}
}
async function runInquiry() {
const el = document.getElementById('inquiry-info');
const btn = document.getElementById('inquiry-run');
if (btn) btn.disabled = true;
const old = el ? el.innerHTML : '';
if (el) el.innerHTML = '<div class="radar-empty">Inquiry in corso (~7s)...</div>';
try {
const res = await fetch('/api/inquiry', { method: 'POST' });
const d = await res.json();
renderInquiry(d);
} catch (e) {
if (el) el.innerHTML = old;
if (btn) btn.disabled = false;
console.error('Errore inquiry:', e);
}
}

function drawRadar(el, devices, highlightMac) {
if (!el) return;
if (!devices || devices.length === 0) {
el.innerHTML = '<div class="radar-empty">In attesa di dispositivi...</div>';
return;
}
const C = 100, R = 95;
const rings = [0.3, 0.5, 0.7, 0.92].map(f =>
'<circle cx="' + C + '" cy="' + C + '" r="' + (R * f).toFixed(1) + '" class="radar-ring"></circle>').join('');
// Tracciati storici: per ogni dispositivo una linea attraverso gli RSSI
// passati (stesso angolo, distanza = RSSI), colore per zona e linea più
// marcata per il dispositivo evidenziato nel radar ingrandito.
const traces = devices.map(d => {
const hist = d.rssi_history || [];
if (hist.length < 2) return '';
const a = macAngle(d.mac);
const pts = hist.map(v => {
const strength = Number.isFinite(v) ? Math.max(0, Math.min(1, (-v - 40) / 50)) : 1;
const r = 12 + strength * (R - 20);
return ((C + r * Math.cos(a)).toFixed(1)) + ',' + ((C + r * Math.sin(a)).toFixed(1));
}).join(' ');
const zoneCls = ZONE_CLS[d.zone] || '';
const hl = highlightMac && d.mac === highlightMac;
return '<polyline points="' + pts + '" class="radar-trace ' + zoneCls + (hl ? ' hl' : '') + '"></polyline>';
}).join('');
const dots = devices.map(d => {
// Su schermi stretti l'etichetta testuale accanto al punto e' illeggibile
// (3-4px di altezza) e copre i vicini: si toglie e resta il tap, che apre
// comunque la scheda. Il punto cresce perche' il dito e' molto meno
// preciso del mouse.
const narrow = isMobile;
const a = macAngle(d.mac);
const strength = Number.isFinite(d.rssi) ? Math.max(0, Math.min(1, (-d.rssi - 40) / 50)) : 1;
const r = 12 + strength * (R - 20);
const x = (C + r * Math.cos(a)).toFixed(1);
const y = (C + r * Math.sin(a)).toFixed(1);
// Etichetta compatta: con un MAC senza nome restano 4 ottetti (es.
// AA:BB:CC:DD) per non sporcare il radar — il tooltip però mostra il MAC
// intero, così l'informazione completa resta accessibile.
const label = (d.name || d.mac).substring(0, 12);
const fullMac = d.mac || '';
// Etichette speculari: se il punto è a destra del centro il testo va a
// sinistra (text-anchor end) così non esce dal viewBox e non viene tagliato.
const flip = parseFloat(x) > C;
const recent = (Date.now() - new Date(d.last_seen).getTime()) < 60000;
// Marcatori minaccia: 👻 phantom (viola) e ⚠ CVE (rosso) a colpo d'occhio.
const isPhantom = d.category === 'phantom' || !!d.phantom;
const hasCve = (d.cves || []).length > 0;
// Distanza stimata (path-loss) e connettibilità dal Tx Power / flags:
// la distanza va su una riga dedicata sotto il nome/zona del tooltip.
const distInfo = Number.isFinite(d.distance_m) ? '📏 ~' + d.distance_m.toFixed(1) + ' m' : '';
const conn = d.connectable == null ? '' : (d.connectable ? '🔗 connettibile' : '📡 non connettibile');
const fpMark = (d.static_dev ? ' 📌 statico' : '') + (d.rotating ? ' 🔄 ' + (d.rotating_n || 0) + ' MAC' : '');
const line1 = (d.name ? escapeHtml(d.name) : escapeHtml(fullMac)) + ' — ' + (Number.isFinite(d.rssi) ? d.rssi + ' dBm' : 'n/a') + ' — ' + d.zone +
(isPhantom ? ' 👻 ' + escapeHtml(d.phantom ? phantomLabel(d.phantom) : 'phantom') : '') + (hasCve ? ' ⚠ ' + escapeHtml(d.cves[0].cve) : '') + fpMark;
const line2 = [distInfo, conn].filter(Boolean).join(' · ');
const title = line1 + (line2 ? '\n' + line2 : '');
const hl = highlightMac && d.mac === highlightMac;
const connRing = (d.connectable === true) ? '<circle class="conn-ring" r="7"></circle>' : '';
return '<g class="radar-dot' + (recent ? '' : ' stale') + (hl ? ' hl' : '') +
(isPhantom ? ' phantom' : '') + (hasCve ? ' cve' : '') + '" transform="translate(' + x + ',' + y + ')" ' +
'onclick="event.stopPropagation();openRadarModal(\'' + d.mac + '\')" title="' + title + '">' +
(hl ? '<circle class="hl-ring" r="10"></circle>' : '') + connRing +
'<circle r="' + (narrow ? 6 : 4) + '"></circle>' + (narrow ? '' : '<text x="' + (flip ? -7 : 7) + '" y="-5"' + (flip ? ' text-anchor="end"' : '') + '>' + escapeHtml(label) + '</text>') + '</g>';
}).join('');
el.innerHTML = '<svg viewBox="0 0 200 200">' +
'<circle cx="100" cy="100" r="' + R + '" class="radar-outer"></circle>' + rings + traces +
'<line x1="100" y1="100" x2="100" y2="5" class="radar-sweep"></line>' + dots + '</svg>';
}
function renderRadar() { drawRadar(document.getElementById('radar'), allDevices, null); }
// Click su un'area vuota del radar -> apre il Radar Ingrandito. Il click sui
// pallini ha il proprio handler con stopPropagation (apre il radar grande con
// quel dispositivo evidenziato), quindi qui arriva solo il click sulla
// superficie/area vuota.
function radarSurfaceClick(ev) {
if (ev && ev.target && ev.target.closest && ev.target.closest('.radar-dot')) return;
openRadarModal();
}
// Radar ingrandito: popup con il dispositivo cliccato evidenziato.
function openRadarModal(mac) {
const d = allDevices.find(x => x.mac === mac);
const info = document.getElementById('radar-big-info');
if (info) {
info.innerHTML = d
? '📍 ' + escapeHtml(obfuscateName(d.name) || d.mac) + ' — ' + (Number.isFinite(d.rssi) ? d.rssi + ' dBm' : 'n/a') + ' · zona ' + d.zone +
(Number.isFinite(d.distance_m) ? ' · 📏 ' + d.distance_m.toFixed(1) + ' m' : '') +
(d.connectable != null ? (d.connectable ? ' · 🔗 connettibile' : ' · 📡 non connettibile') : '') +
' &nbsp; <button class="btn" onclick="closeRadarModal(); showDevice(\'' + mac + '\');" style="padding: 0.1rem 0.4rem; font-size: 0.65rem;">ℹ️ Scheda dispositivo</button>'
: 'clicca un punto per aprire la scheda del dispositivo';
}
drawRadar(document.getElementById('radar-big'), allDevices, mac || null);
document.getElementById('radar-modal').classList.add('active');
}
function closeRadarModal() { document.getElementById('radar-modal').classList.remove('active'); }
// Animazione della spazzata (JS per compatibilità cross-browser): ruota
// tutte le spazzate presenti (sidebar e radar ingrandito).
let sweepAngle = 0;
setInterval(() => {
// La spazzata si ferma quando il server non risponde: continuerebbe a
// simulare una lettura dal vivo che non esiste piu'. E' la differenza fra
// "nessun dispositivo vicino" e "non lo so".
if (!serverOnline) return;
sweepAngle = (sweepAngle + 5) % 360;
const rad = sweepAngle * Math.PI / 180;
document.querySelectorAll('line.radar-sweep').forEach(el => {
el.setAttribute('x2', (100 + 92 * Math.cos(rad)).toFixed(1));
el.setAttribute('y2', (100 + 92 * Math.sin(rad)).toFixed(1));
});
}, 60);

// Notifiche ntfy
async function openNtfy() {
try {
const res = await fetch('/api/ntfy');
const d = await res.json();
document.getElementById('ntfy-enabled').checked = !!d.enabled;
document.getElementById('ntfy-topic').value = d.topic || '';
document.getElementById('ntfy-server').value = d.server || 'https://ntfy.sh';
document.getElementById('ntfy-arrival').checked = d.arrival !== false;
document.getElementById('ntfy-departure').checked = d.departure !== false;
document.getElementById('ntfy-status').textContent = '';
document.getElementById('ntfy-topic-error').style.display = 'none';
document.getElementById('ntfy-server-error').style.display = 'none';
document.getElementById('ntfy-modal').classList.add('active');
} catch (e) {
console.error('Errore caricamento ntfy:', e);
}
}
function closeNtfyModal() { document.getElementById('ntfy-modal').classList.remove('active'); }
// Mostra l'errore accanto al campo che lo ha causato, non solo nella riga di
// stato: «Topic non valido» in fondo a un modale con quattro campi non dice
// all'utente *quale* dei due nomi è sbagliato.
function ntfyFieldError(err) {
const msg = String(err || '');
const low = msg.toLowerCase();
document.getElementById('ntfy-topic-error').style.display = 'none';
document.getElementById('ntfy-server-error').style.display = 'none';
const id = low.includes('topic') ? 'ntfy-topic-error' : (low.includes('server') ? 'ntfy-server-error' : null);
if (!id) return;
const el = document.getElementById(id);
el.textContent = msg;
el.style.display = '';
}
function ntfyClearErrors() {
document.getElementById('ntfy-topic-error').style.display = 'none';
document.getElementById('ntfy-server-error').style.display = 'none';
}
function ntfyStatus(text, ok) {
const el = document.getElementById('ntfy-status');
el.textContent = text;
el.style.color = ok ? 'var(--accent-green)' : 'var(--accent-red)';
}
async function saveNtfy() {
ntfyClearErrors();
const topic = document.getElementById('ntfy-topic').value.trim();
const server = document.getElementById('ntfy-server').value.trim() || 'https://ntfy.sh';
const body = {
enabled: document.getElementById('ntfy-enabled').checked,
topic: topic,
server: server,
arrival: document.getElementById('ntfy-arrival').checked,
departure: document.getElementById('ntfy-departure').checked
};
try {
const res = await fetch('/api/ntfy', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify(body)
});
const d = await res.json();
if (d.ok) {
ntfyStatus('✓ Salvato', true);
} else {
ntfyStatus('✗ ' + (d.error || 'errore'), false);
ntfyFieldError(d.error);
}
} catch (e) {
ntfyStatus('✗ errore rete: ' + e.message, false);
}
}
// Invia una notifica di prova con il topic e il server attualmente scritti
// nei campi, non con quelli salvati: e' cosi' che si puo' provare un topic
// prima di decidere di adottarlo. Non salva niente: il salvataggio e' un
// gesto separato, e un test fallito non deve cambiare la configurazione.
async function testNtfy() {
ntfyClearErrors();
const btn = document.getElementById('ntfy-test-btn');
const topic = document.getElementById('ntfy-topic').value.trim();
const server = document.getElementById('ntfy-server').value.trim() || 'https://ntfy.sh';
if (!topic) {
ntfyFieldError('Inserisci un topic');
ntfyStatus('✗ manca il topic', false);
return;
}
const oldLabel = btn.textContent;
btn.disabled = true;
btn.textContent = '⏳ Invio…';
ntfyStatus('Invio in corso…', true);
try {
const res = await fetch('/api/ntfy/test', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ topic: topic, server: server })
});
const d = await res.json();
if (d.ok) {
ntfyStatus('✓ ' + (d.message || 'notifica inviata'), true);
} else {
ntfyStatus('✗ ' + (d.error || 'errore'), false);
ntfyFieldError(d.error);
}
} catch (e) {
ntfyStatus('✗ errore rete: ' + e.message, false);
} finally {
btn.disabled = false;
btn.textContent = oldLabel;
}
}

function exportCsv() {
window.location.href = '/api/export';
}
// Report HTML: lo scarica come allegato. Il pulsante resta disabilitato e
// cambia etichetta durante la generazione perche' su una settimana di dati il
// report impiega qualche secondo, e un bottone su cui si puo' cliccare due
// volte fa partire due generazioni (e due richieste di parsing dello stesso
// CSV) per un file che l'utente ne vuole uno.
function downloadReport() {
const btn = document.getElementById('report-btn');
if (btn.classList.contains('busy')) return;
btn.classList.add('busy');
const old = btn.textContent;
btn.textContent = 'genero…';
window.location.href = '/api/report';
// Non c'e' modo di sapere quando il download e' finito (il browser lo
// gestisce da solo senza eventi), quindi si ripristina dopo un tempo
// plausibile: il peggio che capita e' un'etichetta che torna indietro un
// secondo prima del download, il peggio che NON capita e' un bottone bloccato.
setTimeout(function () { btn.classList.remove('busy'); btn.textContent = old; }, 6000);
}
function exportSecurity() {
// Report per-dispositivo stile BlueToolkit: CVE note, servizi SDP e note di
// esposizione. Scarica un JSON leggibile, non solo il CSV grezzo.
fetch('/api/export/security').then(function (r) { return r.json(); }).then(function (j) {
const blob = new Blob([JSON.stringify(j, null, 2)], { type: 'application/json' });
const a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'security-report-' + new Date().toISOString().slice(0, 10) + '.json';
document.body.appendChild(a); a.click(); a.remove();
}).catch(function () { alert('Errore durante la generazione del report sicurezza'); });
}

// Scorciatoie da tastiera
document.addEventListener('keydown', function (e) {
if (e.key === 'Escape') { closeModal(); closeNtfyModal(); closeShortcutsModal(); closeRadarModal(); closeShareModal(); closeRawModal(); return; }
if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT')) {
if (e.key === 'Enter' && e.target.id === 'search') { e.target.blur(); }
return;
}
if (e.key === '/') { e.preventDefault(); document.getElementById('search').focus(); }
else if (e.key === 'r') refresh();
else if (e.key === 'c') toggleViewMode();
else if (e.key === 'n') openNtfy();
else if (e.key === 'h') showLegendModal();
else if (e.key === '?') showShortcutsModal();
else if (e.key === '1') setFilter('all');
else if (e.key === '2') setFilter('watched');
else if (e.key === '3') setFilter('phone');
else if (e.key === '4') setFilter('computer');
else if (e.key === '5') setFilter('audio');
});

// Filtri sidebar
document.getElementById('filter-group').addEventListener('click', function (e) {
const btn = e.target.closest('.filter-btn');
if (btn) setFilter(btn.dataset.filter);
});
// Le statistiche in alto (Identificati/Attivi/Nuovi/Randomizzati) sono filtri cliccabili.
document.querySelectorAll('.stat-item.stat-filter').forEach(function (item) {
item.addEventListener('click', function () { setFilter(item.dataset.filter); });
});
document.getElementById('filter-group-class').addEventListener('click', function (e) {
const btn = e.target.closest('.filter-btn');
if (btn) setFilter(btn.dataset.filter);
});
// Ricerca con debounce
let searchTimer = null;
document.getElementById('search').addEventListener('input', function () {
clearTimeout(searchTimer);
searchTimer = setTimeout(function () {
searchTerm = document.getElementById('search').value.trim();
pagination.page = 1;
render();
}, 200);
});

// Ordinamento tabella: click sull'intestazione ordina (ripeti per invertire).
document.querySelectorAll('.device-table th.sortable').forEach(function (th) {
th.addEventListener('click', function () { setSort(th.dataset.sort); });
});
// Evidenzia la colonna ordinata di default all'avvio (Ultimo contatto, desc).
(function () {
document.querySelectorAll('.device-table th.sortable').forEach(function (th) {
const active = th.dataset.sort === sortState.column;
th.classList.toggle('active', active);
const ind = th.querySelector('.sort-indicator');
if (ind) ind.textContent = active ? (sortState.direction === 'asc' ? '▲' : '▼') : '';
});
})();

updateViewToggle();
updateScreenshotToggle();
refresh();
setInterval(refresh, 5000);
showLegendOnce();
// Service worker solo per l'installabilita' come app. Se la registrazione
// fallisce (HTTP in chiaro, browser vecchio, SW bloccati) si prosegue senza:
// la dashboard non ha bisogno del SW per funzionare, e un'eccezione qui
// romperebbe l'ultimo pezzo di script.
if ('serviceWorker' in navigator) {
navigator.serviceWorker.register('/sw.js').catch(() => {});
}
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btclassic::{KnownBt, ProbeResult};

    #[test]
    fn estimate_distance_m_basic() {
        // RSSI = Tx Power di riferimento -> 1 metro.
        let d = estimate_distance_m(Some(-59), Some(-59), None).unwrap();
        assert!((d - 1.0).abs() < 0.01);
        // Segnale più debole -> più lontano.
        let far = estimate_distance_m(Some(-70), Some(-59), None).unwrap();
        assert!(far > 1.0);
        // Segnale più forte -> più vicino (e mai sotto il clamp 0.1 m).
        let near = estimate_distance_m(Some(-40), Some(-59), None).unwrap();
        assert!((0.1..1.0).contains(&near));
        // Clamp effettivo sotto 0.1 m.
        let clamped = estimate_distance_m(Some(-20), Some(-59), None).unwrap();
        assert_eq!(clamped, 0.1);
        // Dati mancanti -> None.
        assert!(estimate_distance_m(None, Some(-59), None).is_none());
        assert!(estimate_distance_m(Some(-59), None, None).is_none());
        // Attenuazione ambiente: stesso RSSI/Tx -> 1 m senza correzione;
        // con 6 dB di attenuazione il "1 m" reale appare a -65 dBm e la
        // distanza stimata scende (il dispositivo vicino sembrava più lontano).
        let att = estimate_distance_m(Some(-59), Some(-59), Some(6.0)).unwrap();
        assert!(att < 1.0);
        assert!((att - 10f32.powf(-6.0 / 20.0)).abs() < 0.01);
        // Oltre il range massimo plausibile (100 m indoor) il valore non viene
        // esposto: nessuna distanza assurda nel radar o nella scheda.
        assert!(estimate_distance_m(Some(-120), Some(-59), None).is_none());
        assert!(estimate_distance_m(Some(-96), Some(12), None).is_none());
        // Con attenuazione la distanza resta sotto il cap.
        let corr = estimate_distance_m(Some(-84), Some(12), Some(25.0)).unwrap();
        assert!(corr > 0.1 && corr <= MAX_DISTANCE_M);
    }

    #[test]
    fn rssi_smoother_stabilizes() {
        // Primo campione: il filtro parte dal valore grezzo.
        let (x1, v1) = rssi_smooth_step(None, 0.0, -60.0);
        assert_eq!(x1, -60.0);
        assert_eq!(v1, 0.0);
        // Valore costante: converge e resta stabile (niente deriva).
        let mut x = x1;
        let mut v = v1;
        for _ in 0..10 {
            let (nx, nv) = rssi_smooth_step(Some(x), v, -60.0);
            x = nx;
            v = nv;
        }
        assert!((x - (-60.0)).abs() < 0.05);
        // Outlier singolo (-95 da -60): il filtro lo smorza, non salta tutto
        // (si muove di ~12 dB dei 35 di salto).
        let (xa, _) = rssi_smooth_step(Some(x), v, -95.0);
        assert!(xa > -75.0 && xa < -65.0, "outlier troppo seguito: {xa}");
        // Trend graduale (-2 dB a campione): il filtro segue senza inseguire
        // i singoli campioni.
        let mut xt = x1;
        let mut vt = v1;
        for k in 1..=10 {
            let (nx, nv) = rssi_smooth_step(Some(xt), vt, -60.0 - 2.0 * k as f32);
            xt = nx;
            vt = nv;
        }
        assert!(xt < -76.0 && xt > -81.0, "non segue il trend: {xt}");
    }

    #[test]
    fn pathloss_stat_estimates_attenuation() {
        let mut p = PathlossStat::default();
        assert_eq!(p.atten_db, None);
        // Sotto 10 campioni: nessuna stima.
        for i in 0..9 {
            p.push(-59.0, -69.0 - i as f32); // path loss 10..18 dB
        }
        assert_eq!(p.atten_db, None);
        // Undicesimo campione vicino (path loss 6 dB) sblocca la stima:
        // P10 su 10 campioni = 10 dB (il secondo valore più basso).
        p.push(-59.0, -65.0);
        let att = p.atten_db.unwrap();
        assert!((att - 10.0).abs() < 0.01);
        assert!(p.range_m.is_some());
        // Campioni inverosimili (rssi > atteso a 1 m, path loss negativo)
        // ignorati: -59 dBm dichiarati con RSSI -40 dBm è impossibile.
        let before = p.samples.len();
        p.push(-59.0, -40.0);
        assert_eq!(p.samples.len(), before);
        // Potenze irradiate normalizzate all'RSSI@1m (tx - 41 dB): +12 dBm
        // visto a -50 dBm = dispositivo vicino (path loss 21 dB) -> accettato.
        p.push(12.0, -50.0);
        assert_eq!(p.samples.len(), before + 1);
        let mut q10 = PathlossStat::default();
        for _ in 0..10 {
            q10.push(12.0, -50.0); // 10 campioni a 21 dB di path loss
        }
        assert!((q10.atten_db.unwrap() - 21.0).abs() < 0.01);
        // Cap a 25 dB: stime fuori scala non sovra-correggono le distanze.
        let mut q = PathlossStat::default();
        for _ in 0..10 {
            q.push(-59.0, -110.0); // path loss 51 dB (stanza molto rumorosa)
        }
        assert_eq!(q.atten_db.unwrap(), 25.0);
    }

    #[test]
    fn eff_ref_normalizes_radiated_power() {
        // Measured power (iBeacon-style) già in scala rssi@1m.
        assert_eq!(eff_ref_dbm(-59.0), -59.0);
        // Potenza irradiata: rssi@1m = tx - 41 dB (accoppiamento indoor).
        assert_eq!(eff_ref_dbm(12.0), -29.0);
        assert_eq!(eff_ref_dbm(0.0), -41.0);
        // La distanza con la correzione non esplode più (es. +12 dBm a
        // -50 dBm di RSSI = 11 m invece di 1259 m senza normalizzazione).
        let ok = estimate_distance_m(Some(-50), Some(12), None).unwrap();
        assert!(ok < 100.0);
        assert!((ok - 10f32.powf(21.0 / 20.0)).abs() < 0.01);
    }

    #[test]
    fn update_classic_marks_present_phone_as_watched() {
        let state = new_state_with(None);
        let known = vec![KnownBt {
            mac: "EC:ED:73:65:AC:45".to_string(),
            nome: "Moto G73".to_string(),
            persona: "Mario".to_string(),
        }];
        let results = vec![ProbeResult {
            mac: "EC:ED:73:65:AC:45".to_string(),
            present: true,
            detail: "PRESENT (connected)".to_string(),
            elapsed_ms: 42,
        }];
        update_classic(&state, &results, &known);
        // Il read-guard va rilasciato prima del secondo aggiornamento,
        // altrimenti il write-lock di update_classic va in deadlock.
        {
            let devices = state.devices.read().unwrap();
            assert_eq!(devices.len(), 1);
            assert!(devices[0].watched);
            assert!(devices[0].active);
            assert_eq!(devices[0].name, "Moto G73");
            assert_eq!(devices[0].category, "phone");
        }
        // Un secondo probe presente incrementa gli avvistamenti.
        update_classic(&state, &results, &known);
        let devices = state.devices.read().unwrap();
        assert_eq!(devices[0].sightings, 2);
    }

    #[test]
    fn update_classic_ignores_absent() {
        let state = new_state_with(None);
        let known = vec![KnownBt {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            nome: "X".to_string(),
            persona: String::new(),
        }];
        let results = vec![ProbeResult {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            present: false,
            detail: "ABSENT".to_string(),
            elapsed_ms: 1,
        }];
        update_classic(&state, &results, &known);
        assert!(state.devices.read().unwrap().is_empty());
    }
}

// Test di integrazione HTTP degli endpoint /api/known/*.
//
// Vivono qui dentro (e non in tests/) perche' `spawn_server` e `stop_dashboard`
// sono funzioni private di questo modulo e `crate` non e' una libreria:
// esporle richiederebbe un src/lib.rs solo per questo.
//
// I due isolamento che servono:
//  1. `bt_known.txt` va rediretto su una directory temporanea tramite
//     BLUESNIFF_BT_KNOWN. Senza, i test scriverebbero (e poi cancellerebbero)
//     il file vero nella cartella dell'eseguibile.
//  2. `SHUTDOWN` e' un globale: due server in contemporanea si ruberebbero il
//     sender. Il mutex qui sotto serializza i test.
// Il guard di API_LOCK resta vivo per TUTTO il test, quindi attraversa dei
// punti `.await`: e' voluto. Il runtime di `#[tokio::test]` e' single threaded
// (nessuna migrazione di thread) e il lock serve a tenere i test in fila, non a
// proteggere un accesso breve.
#[allow(clippy::await_holding_lock)]
#[cfg(test)]
mod api_known_tests {
    use super::*;
    use std::sync::Mutex;

    static API_LOCK: Mutex<()> = Mutex::new(());

    /// Un `presenze.csv` piccolo e stabile: due dispositivi, uno dei quali
    /// localizzatore, con una colonna `stazione` per l'intestazione.
    const CSV_FIXTURE: &str = "ora;tipo;mac;nome;persona;rssi;fingerprint;vendor;hint;stato;stazione\n\
2026-09-30T08:00:00Z;passivo;AA:BB:CC:DD:EE:01;iPhone;Mario;-55;;Apple;;visto;8C:88:2B:31:5B:74\n\
2026-09-30T08:10:00Z;passivo;AA:BB:CC:DD:EE:01;iPhone;Mario;-57;;Apple;;visto;8C:88:2B:31:5B:74\n\
2026-09-30T08:20:00Z;passivo;CC:CC:CC:CC:CC:09;;;−70;;Apple;Apple Find My accessory;visto;8C:88:2B:31:5B:74\n";

    /// Directory temporanea unica per questo test.
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "bluesniff-api-{}-{tag}-{nanos}",
            std::process::id()
        ))
    }

    /// Server avviato su porta effimera + `bt_known.txt` isolato.
    struct Fixture {
        /// Tiene il lock per tutta la vita del test: rilasciarlo prima di
        /// `Drop` lascerebbe un altro test a parlare con questo server.
        _guard: std::sync::MutexGuard<'static, ()>,
        base: String,
        known_path: std::path::PathBuf,
        ignore_path: std::path::PathBuf,
        is_me_path: std::path::PathBuf,
        dir: std::path::PathBuf,
        /// Lo stato condiviso che gira DENTRO il server. Senza questo il test
        /// costruirebbe uno stato nuovo e verificherebbe la logica invece del
        /// wiring HTTP, che e' la parte che si puo' rompere.
        state: DashboardState,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            stop_dashboard();
            // Ripuliamo la variabile d'ambiente prima di cancellare la dir: se
            // un altro test la rilesse dopo, troverebbe un path inesistente.
            std::env::remove_var("BLUESNIFF_BT_KNOWN");
            std::env::remove_var("BLUESNIFF_BT_IGNORE");
            std::env::remove_var("BLUESNIFF_BT_ISME");
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn post_json(url: &str, body: serde_json::Value) -> serde_json::Value {
        reqwest::Client::new()
            .post(url)
            .json(&body)
            .send()
            .await
            .expect("POST fallita")
            .json()
            .await
            .expect("risposta non JSON")
    }

    async fn get_json(url: &str) -> serde_json::Value {
        reqwest::Client::new()
            .get(url)
            .send()
            .await
            .expect("GET fallita")
            .json()
            .await
            .expect("risposta non JSON")
    }

    /// Avvia il server e aspetta che risponda davvero.
    ///
    /// Non basta un sleep fisso: la porta effimera e' libera solo nel
    /// momento del bind e `spawn_server` riapre la finestra. Il ping a
    /// `/api/known` (che non tocca disco) ci dice quando il server e' pronto,
    /// e il giro di tentativi copre il caso in cui la porta venga persa.
    async fn start(tag: &str) -> Option<Fixture> {
        start_with(tag, None).await
    }

    /// Come `start`, ma con un `presenze.csv` isolato: i test che hanno bisogno
    /// di dati (il report, le heatmap) non possono usare il CSV vero
    /// accanto all'eseguibile, che cambia a ogni `--listen` e renderebbe i
    /// risultati non deterministici.
    async fn start_with(tag: &str, presenze: Option<std::path::PathBuf>) -> Option<Fixture> {
        let guard = API_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp_dir(tag);
        std::fs::create_dir_all(&dir).ok()?;
        if let Some(p) = &presenze {
            std::fs::write(p, CSV_FIXTURE).ok()?;
        }
        let known_path = dir.join("bt_known.txt");
        std::fs::write(&known_path, "# test\n").ok()?;
        let ignore_path = dir.join("ignore.txt");
        let is_me_path = dir.join("is_me.txt");
        // SAFETY: i test sono serializzati da API_LOCK, e questa variabile e'
        // globale al processo: senza il lock, due test la sovrascriverebbero
        // a vicenda e leggerebbero il file dell'altro.
        std::env::set_var("BLUESNIFF_BT_KNOWN", &known_path);
        // Gli altri due file devono puntare alla stessa directory isolata: se
        // non lo facessimo, un test che chiama /api/devices/ignore scriverebbe
        // nell'ignore.txt vero accanto all'eseguibile.
        std::env::set_var("BLUESNIFF_BT_IGNORE", &ignore_path);
        std::env::set_var("BLUESNIFF_BT_ISME", &is_me_path);
        let logger = crate::logging::Logger::open(dir.join("test.log")).ok()?;

        for _ in 0..5 {
            // Porta effimera: il kernel assegna la libera, poi la chiudiamo e
            // la riapriamo subito con spawn_server. C'e' una race minima, il
            // retry sotto la copre.
            let port = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
                l.local_addr().ok()?.port()
            };
            let state = new_state_with(presenze.clone());
            // Il risultato decide se ritentare: ignorarlo farebbe passare il
            // test anche quando il server non è mai partito, che è
            // esattamente il guasto che il test deve vedere.
            if spawn_server(
                &logger,
                state.clone(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            )
            .is_err()
            {
                stop_dashboard();
                continue;
            }
            let base = format!("http://127.0.0.1:{port}");
            for _ in 0..20 {
                if reqwest::Client::new()
                    .get(format!("{base}/api/known"))
                    .send()
                    .await
                    .is_ok()
                {
                    return Some(Fixture {
                        _guard: guard,
                        base,
                        known_path,
                        ignore_path,
                        is_me_path,
                        dir,
                        state,
                    });
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            stop_dashboard();
        }
        None
    }

    /// Un device di prova con tutti i campi elencati uno per uno.
    ///
    /// Non deriva `Default` di proposito: i campi sono 30 e ognuno dovrebbe
    /// essere una scelta. Con `..Default::default()` domani un campo nuovo
    /// passerebbe in silenzio a `false`/`0` e il test continuerebbe a
    /// passare mentre verifica qualcosa di diverso da quello che crede. Qui un
    /// campo nuovo rompe la compilazione, che e' la protezione che serve.
    fn mk_device(mac: &str, watched: bool) -> DashboardDevice {
        DashboardDevice {
            mac: mac.to_string(),
            name: "Moto G73".to_string(),
            vendor: "motorola".to_string(),
            rssi: Some(-60),
            zone: "vicino".to_string(),
            category: "phone".to_string(),
            randomized: false,
            identified: true,
            watched,
            ignored: false,
            is_me: false,
            persona: "Mario".to_string(),
            active: true,
            sightings: 3,
            first_seen: "2026-09-30T10:00:00Z".to_string(),
            last_seen: "2026-09-30T10:05:00Z".to_string(),
            rssi_history: vec![-60, -61],
            model_id: None,
            model_name: None,
            phantom: None,
            cves: Vec::new(),
            tx_power: None,
            tx_ibeacon: false,
            connectable: Some(true),
            distance_m: Some(2.0),
            rssi_smooth: None,
            rssi_vel: 0.0,
            fingerprint: String::new(),
            static_dev: false,
            rotating: false,
            rotating_n: 0,
        }
    }

    #[tokio::test]
    async fn ignore_scrive_su_disco_e_il_prossimo_update_lo_legge() {
        let Some(fx) = start("ignore").await else {
            return;
        };
        // 1) Ignore via HTTP.
        let j = post_json(
            &format!("{}/api/devices/ignore", fx.base),
            serde_json::json!({"mac": "EC:ED:73:65:AC:45"}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        assert_eq!(j["ignored"], true, "{j}");
        assert_eq!(j["was_watched"], false, "{j}");

        // 2) Il file su disco contiene il MAC, e solo quello.
        let text = std::fs::read_to_string(&fx.ignore_path).unwrap();
        assert!(text.contains("EC:ED:73:65:AC:45"), "{text}");
        assert_eq!(text.matches("EC:ED:73").count(), 1, "{text}");

        // 3) Doppio ignore: idempotente, il file non cresce.
        let _ = post_json(
            &format!("{}/api/devices/ignore", fx.base),
            serde_json::json!({"mac": "ec:ed:73:65:ac:45"}),
        )
        .await;
        let text = std::fs::read_to_string(&fx.ignore_path).unwrap();
        assert_eq!(text.matches("EC:ED:73").count(), 1, "duplicato: {text}");

        // 4) La lista per il pannello di pulizia.
        let j = get_json(&format!("{}/api/devices/ignored", fx.base)).await;
        assert_eq!(j["count"], 1, "{j}");
        assert_eq!(j["macs"][0], "EC:ED:73:65:AC:45", "{j}");

        // 5) Unignore.
        let j = post_json(
            &format!("{}/api/devices/unignore", fx.base),
            serde_json::json!({"mac": "EC:ED:73:65:AC:45"}),
        )
        .await;
        assert_eq!(j["ignored"], false, "{j}");
        let text = std::fs::read_to_string(&fx.ignore_path).unwrap();
        assert!(!text.contains("EC:ED:73"), "{text}");
        let j = get_json(&format!("{}/api/devices/ignored", fx.base)).await;
        assert_eq!(j["count"], 0, "{j}");
    }

    #[tokio::test]
    async fn ignore_su_dispositivo_seguito_risponde_was_watched() {
        let Some(fx) = start("watched").await else {
            return;
        };
        // Il device vive nello stato del server: e' la condizione che fa
        // scattare `was_watched`, cioe' l'avviso "continuerai a ricevere
        // notifiche".
        if let Ok(mut devices) = fx.state.devices.write() {
            devices.push(mk_device("AA:BB:CC:DD:EE:01", true));
        }
        let j = post_json(
            &format!("{}/api/devices/ignore", fx.base),
            serde_json::json!({"mac": "AA:BB:CC:DD:EE:01"}),
        )
        .await;
        assert_eq!(j["ignored"], true, "{j}");
        assert_eq!(
            j["was_watched"], true,
            "senza was_watched la UI non avvisa che le notifiche continuano: {j}"
        );
        // Il follow NON viene tolto: sta in un altro file, e toglierlo senza
        // che l'utente lo chieda sarebbe decidere al posto suo.
        let text = std::fs::read_to_string(&fx.ignore_path).unwrap();
        assert!(text.contains("AA:BB:CC:DD:EE:01"), "{text}");
        assert!(
            !fx.known_path.exists()
                || !std::fs::read_to_string(&fx.known_path)
                    .unwrap()
                    .contains("AA:BB"),
            "l'ignore ha toccato bt_known.txt"
        );
    }

    #[tokio::test]
    async fn api_devices_esclude_gli_ignorati_dai_conteggi() {
        let Some(fx) = start("counts").await else {
            return;
        };
        {
            let mut devices = fx.state.devices.write().unwrap();
            devices.push(mk_device("AA:BB:CC:DD:EE:01", false));
            devices.push(mk_device("AA:BB:CC:DD:EE:02", true));
        }
        // Baseline: due device, entrambi visibili.
        let j = get_json(&format!("{}/api/devices", fx.base)).await;
        assert_eq!(j["counts"]["total"], 2, "{j}");
        assert_eq!(j["counts"]["watched"], 1, "{j}");
        assert_eq!(j["counts"]["ignored"], 0, "{j}");

        // Ignoriamo il seguito: esce dai conteggi ma resta nel corpo.
        let _ = post_json(
            &format!("{}/api/devices/ignore", fx.base),
            serde_json::json!({"mac": "AA:BB:CC:DD:EE:02"}),
        )
        .await;
        // `update()` non gira nel test (non c'e' una finestra di scansione), ma
        // l'handler aggiorna il device in memoria: e' il riflesso immediato
        // che vede la UI.
        let j = get_json(&format!("{}/api/devices", fx.base)).await;
        assert_eq!(
            j["counts"]["total"], 1,
            "total non esclude gli ignorati: {j}"
        );
        assert_eq!(j["counts"]["ignored"], 1, "{j}");
        assert_eq!(j["counts"]["watched"], 0, "{j}");
        let ignorato = j["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["mac"] == "AA:BB:CC:DD:EE:02")
            .expect("l'ignorato deve restare nel corpo di default");
        assert_eq!(ignorato["ignored"], true, "{ignorato}");

        // Con include_ignored=0 sparisce anche dal corpo.
        let j = get_json(&format!("{}/api/devices?include_ignored=0", fx.base)).await;
        assert_eq!(j["devices"].as_array().unwrap().len(), 1, "{j}");
        assert_eq!(j["counts"]["ignored"], 1, "il conteggio resta: {j}");
    }

    #[tokio::test]
    async fn mac_non_valido_ritorna_ok_false_e_non_scrive() {
        let Some(fx) = start("invalido").await else {
            return;
        };
        for rotta in [
            "/api/devices/ignore",
            "/api/devices/unignore",
            "/api/devices/is-me",
        ] {
            let j = post_json(
                &format!("{}{rotta}", fx.base),
                serde_json::json!({"mac": "non-un-mac"}),
            )
            .await;
            assert_eq!(j["ok"], false, "{rotta}: {j}");
            assert!(
                j["error"].as_str().unwrap_or("").contains("non valido"),
                "{rotta}: errore poco utile: {j}"
            );
        }
        // Nessun file creato dal MAC spazzatura.
        assert!(!fx.ignore_path.exists(), "ignore.txt creato");
        assert!(!fx.is_me_path.exists(), "is_me.txt creato");
    }

    #[tokio::test]
    async fn is_me_imposta_un_solo_mac_e_il_primo_viene_restituito() {
        let Some(fx) = start("isme").await else {
            return;
        };
        {
            let mut devices = fx.state.devices.write().unwrap();
            devices.push(mk_device("AA:BB:CC:DD:EE:01", false));
            devices.push(mk_device("AA:BB:CC:DD:EE:02", false));
        }
        let j = post_json(
            &format!("{}/api/devices/is-me", fx.base),
            serde_json::json!({"mac": "AA:BB:CC:DD:EE:01"}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        assert_eq!(j["is_me"], "AA:BB:CC:DD:EE:01", "{j}");
        assert_eq!(j["previous"], serde_json::Value::Null, "{j}");

        // Il secondo dispositivo sostituisce il primo, e la risposta dice quale
        // era: senza questo la UI non puo' spiegare la sparizione del badge.
        let j = post_json(
            &format!("{}/api/devices/is-me", fx.base),
            serde_json::json!({"mac": "AA:BB:CC:DD:EE:02"}),
        )
        .await;
        assert_eq!(j["is_me"], "AA:BB:CC:DD:EE:02", "{j}");
        assert_eq!(j["previous"], "AA:BB:CC:DD:EE:01", "{j}");

        // In memoria il badge e' su uno solo.
        let j = get_json(&format!("{}/api/devices", fx.base)).await;
        let me: Vec<&serde_json::Value> = j["devices"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| d["is_me"] == true)
            .collect();
        assert_eq!(me.len(), 1, "due dispositivi con il badge: {j}");
        assert_eq!(me[0]["mac"], "AA:BB:CC:DD:EE:02", "{j}");

        // Revoca.
        let j = post_json(
            &format!("{}/api/devices/is-me/clear", fx.base),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        let j = get_json(&format!("{}/api/devices", fx.base)).await;
        assert!(
            j["devices"]
                .as_array()
                .unwrap()
                .iter()
                .all(|d| d["is_me"] == false),
            "badge rimasto dopo la revoca: {j}"
        );
    }

    #[tokio::test]
    async fn unignore_all_svuota_il_file_e_azzera_i_conteggi() {
        let Some(fx) = start("clearall").await else {
            return;
        };
        std::fs::write(
            &fx.ignore_path,
            "# miei\nAA:BB:CC:DD:EE:01\nAA:BB:CC:DD:EE:02\n",
        )
        .unwrap();
        if let Ok(mut devices) = fx.state.devices.write() {
            devices.push(mk_device("AA:BB:CC:DD:EE:01", false));
        }
        let _ = post_json(
            &format!("{}/api/devices/ignore", fx.base),
            serde_json::json!({"mac": "AA:BB:CC:DD:EE:02"}),
        )
        .await;
        let j = post_json(
            &format!("{}/api/devices/ignored/clear", fx.base),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        assert_eq!(j["removed"], 2, "{j}");
        let text = std::fs::read_to_string(&fx.ignore_path).unwrap();
        assert!(!text.contains("AA:BB"), "MAC rimasti: {text}");
        assert!(text.contains("# miei"), "commento perso: {text}");
        let j = get_json(&format!("{}/api/devices", fx.base)).await;
        assert_eq!(j["counts"]["ignored"], 0, "{j}");
        assert_eq!(j["counts"]["total"], 1, "il device torna in tabella: {j}");
    }

    /// GET /api/report: HTML, allegato, e i MAC mascherati quando richiesto.
    #[tokio::test]
    async fn report_html_e_un_allegato() {
        let dir = tmp_dir("report");
        std::fs::create_dir_all(&dir).ok();
        let presenze = dir.join("presenze.csv");
        let Some(fx) = start_with("report", Some(presenze)).await else {
            return;
        };

        let res = reqwest::Client::new()
            .get(format!("{}/api/report", fx.base))
            .send()
            .await
            .expect("GET /api/report fallita");
        assert_eq!(res.status(), 200);
        let disp = res
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(disp.contains("attachment"), "manca l'allegato: {disp}");
        assert!(
            disp.contains("bluesniff-report-"),
            "manca il nome file: {disp}"
        );
        let ct = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ct.contains("text/html"), "content-type: {ct}");
        let body = res.text().await.unwrap();
        assert!(
            body.starts_with("<!DOCTYPE html>"),
            "non e' un documento HTML"
        );
        // I dati del fixture devono arrivare nel documento.
        assert!(body.contains("iPhone"), "il dispositivo seguito manca");
        assert!(body.contains("8C:88:2B:31:5B:74"), "manca la stazione");

        // anonymize=1: nessun MAC completo nel corpo.
        let body_anon = reqwest::Client::new()
            .get(format!("{}/api/report?anonymize=1", fx.base))
            .send()
            .await
            .expect("GET anonimo fallita")
            .text()
            .await
            .unwrap();
        assert!(
            !body_anon.contains("AA:BB:CC:DD:EE:01"),
            "MAC completo presente nel report anonimo"
        );
        assert!(body_anon.contains("AA:BB:CC:XX:XX:XX"));

        // Lo stesso report non anonimo li contiene: il flag e' l'unica differenza.
        let body_normale = reqwest::Client::new()
            .get(format!("{}/api/report", fx.base))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(body_normale.contains("AA:BB:CC:DD:EE:01"));
    }

    /// Server finto che risponde a una sola richiesta con lo status indicato.
    ///
    /// Non serve un axum di secondo: al test basta qualcosa che stia in
    /// ascolto e risponda, e `std::net::TcpListener` e' la via piu' corta
    /// per provare che `/api/ntfy/test` parla davvero col'esterno (e che legge
    /// lo status) senza toccare la rete pubblica.
    fn fake_ntfy(status_line: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            // Un solo scambio: il test fa una richiesta per server finto.
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            use std::io::{Read, Write};
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf);
            let body = "{\"ok\":true}";
            let risposta = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(risposta.as_bytes());
        });
        base
    }

    async fn post_ntfy_test(base: &str, topic: &str, server: &str) -> serde_json::Value {
        reqwest::Client::new()
            .post(format!("{base}/api/ntfy/test"))
            .json(&serde_json::json!({ "topic": topic, "server": server }))
            .send()
            .await
            .expect("POST /api/ntfy/test fallita")
            .json()
            .await
            .expect("risposta non JSON")
    }

    #[tokio::test]
    async fn manifest_e_icone_per_linstallazione_come_app() {
        let Some(fx) = start("pwa").await else {
            return;
        };
        let client = reqwest::Client::new();

        // Manifest: senza questi campi chiave l'installazione fallisce in
        // silenzio (Chrome non dice nulla, semplicemente non propone).
        let res = client
            .get(format!("{}/manifest.json", fx.base))
            .send()
            .await
            .expect("GET /manifest.json fallita");
        assert_eq!(res.status(), 200);
        let ct = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ct.contains("manifest+json"), "content-type: {ct}");
        let m: serde_json::Value = res.json().await.unwrap();
        assert_eq!(m["display"], "standalone");
        assert_eq!(m["start_url"], "/");
        assert!(m["name"].as_str().unwrap().contains("bluesniff"), "{m}");
        let icone = m["icons"].as_array().expect("icons mancanti");
        assert_eq!(icone.len(), 2, "{m}");

        // Le icone devono essere PNG veri: e' il controllo che distingue un
        // file incluso per errore da un'immagine che il browser mostra.
        for (path, size) in [("/icon-192.png", 192u32), ("/icon-512.png", 512)] {
            let r = client
                .get(format!("{}{}", fx.base, path))
                .send()
                .await
                .unwrap_or_else(|_| panic!("GET {path} fallita"));
            assert_eq!(r.status(), 200, "{path}");
            assert_eq!(
                r.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(""),
                "image/png",
                "{path}"
            );
            let b = r.bytes().await.unwrap();
            assert_eq!(
                &b[0..8],
                &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
                "{path} non e' un PNG"
            );
            let larghezza = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
            let altezza = u32::from_be_bytes([b[20], b[21], b[22], b[23]]);
            assert_eq!(
                (larghezza, altezza),
                (size, size),
                "{path}: dimensioni diverse da quelle dichiarate nel manifest"
            );
        }

        // Il service worker deve esistere ma non deve fare niente: i dati
        // cambiano ogni 5 secondi e una cache mostrerebbe uno stato vecchio
        // come se fosse attuale.
        let sw = client
            .get(format!("{}/sw.js", fx.base))
            .send()
            .await
            .expect("GET /sw.js fallita");
        assert_eq!(sw.status(), 200);
        let body = sw.text().await.unwrap();
        assert!(body.contains("skipWaiting"), "{body}");
        assert!(
            !body.contains("caches.") && !body.contains("cache.match"),
            "il service worker non deve cacheare: {body}"
        );
    }

    #[test]
    fn le_due_viste_della_dashboard_esistono_e_sono_complete() {
        // Il sintomo di questo test e' gia' successo: uno `;` di troppo dentro
        // una callback `.map()` lascia lo script interrotto a meta'. La pagina si
        // carica, la tabella sparisce, e non c'e' errore visibile: solo una
        // dashboard "meta' viva". Qui si controlla la struttura, non la sintassi
        // (validarla richiederebbe un parser JavaScript, e un contatore di
        // graffe sbaglierebbe sui regex e sulle divisioni).
        let script = INDEX_HTML
            .split_once("<script>")
            .and_then(|(_, s)| s.split_once("</script>"))
            .map(|(s, _)| s)
            .expect("nessun blocco <script> in INDEX_HTML");

        // Le due viste devono esistere entrambe: senza una delle due il
        // telefono o il PC restano senza lista, senza che nessun errore lo dica.
        for (nome, segno) in [
            ("renderMobile", "function renderMobile(page) {"),
            ("renderDesktop", "function renderDesktop(page) {"),
            ("renderMobileChips", "function renderMobileChips() {"),
        ] {
            assert!(
                script.contains(segno),
                "{nome} non esiste: la vista non cambierebbe mai"
            );
        }

        // Bilanciamento grezzo di graffe, parentesi e quadre. Non e' un
        // parser: conta anche dentro stringhe e regex (in questo file sono
        // 153, e i loro `{2}` falserebbero qualunque conteggio piu' furbo), ma
        // e' proprio questa sua rozzezza che lo rende utile: non produce falsi
        // positivi. Ha gia' preso un difetto vero — una funzione lasciata senza
        // graffa finale, che spegneva lo script a meta' senza alcun errore in
        // console: la dashboard sembrava viva e non mostrava piu' nulla.
        //
        // Per la sintassi vera (un punto e virgola nel posto sbagliato dentro
        // una callback) serve un parser: quello e' `node --check` sul blocco
        // `<script>` estratto, e va fatto quando si tocca INDEX_HTML, non in
        // cargo test — dove nessun parser JavaScript e' disponibile.
        for (apre, chiude, nome) in [
            ('{', '}', "graffe"),
            ('(', ')', "parentesi"),
            ('[', ']', "parentesi quadre"),
        ] {
            let a = script.matches(apre).count();
            let b = script.matches(chiude).count();
            assert_eq!(
                a, b,
                "{nome} non bilanciate: {a} `{apre}` contro {b} `{chiude}`.                  Lo script si interrompe a meta' e la pagina sembra viva ma                  muta, senza errori in console"
            );
        }

        // Gli onclick generati devono usare un solo backslash prima
        // dell'apostrofo. Con due, l'apostrofo non chiude la stringa: lo
        // script si interrompe e la card sembra cliccabile ma non apre
        // niente.
        //
        // La forma attesa e' una raw string perche' in una stringa Rust
        // normale il backslash va raddoppiato, e qui si rischierebbe di
        // scrivere un test che confronta una cosa diversa da quella del file.
        let atteso = r#"showDevice(\'' + d.mac + '\')"#;
        assert!(
            script.contains(atteso),
            "la forma dell'onclick nelle card e' sbagliata: attendo {atteso}"
        );
    }

    #[test]
    fn il_pulsante_di_arresto_e_nel_pannello_radio() {
        // Difetto gia' successo: il pulsante era scritto come espressione
        // separata dopo il `;` che chiude `el.innerHTML`. Il codice era
        // JavaScript valido — `node --check` passava — ma il pulsante non
        // finiva mai nel DOM, quindi non c'era. Un pulsante che non appare e'
        // indistinguibile da un pulsante che non esiste.
        let script = INDEX_HTML
            .split_once("<script>")
            .and_then(|(_, s)| s.split_once("</script>"))
            .map(|(s, _)| s)
            .expect("nessun blocco <script> in INDEX_HTML");
        let inizio = script
            .find("el.innerHTML = warn")
            .expect("il pannello radio non imposta innerHTML");
        let fine = inizio
            + script[inizio..]
                .find("async function refreshRadio")
                .expect("il pannello radio non finisce");
        let pannello = &script[inizio..fine];
        assert!(
            pannello.contains("scan-stop-btn"),
            "il pulsante di arresto non e' nel pannello radio"
        );
        // Deve stare nella stessa catena di `el.innerHTML`, non in una
        // istruzione a se': quello che distingue i due casi e' il `+` dopo
        // il pulsante precedente.
        assert!(
            pannello.contains("Riprova scansione (~9s)</button>' +"),
            "il pulsante di arresto non e' concatenato a innerHTML"
        );
    }

    #[test]
    fn la_nota_del_radar_dice_che_l_angolo_non_e_una_direzione() {
        // Il radar e' l'unico pezzo della dashboard che si presta a essere
        // letto come mappa, e un utente che lo crede si convince che il punto
        // in alto a sinistra sia "dall'altra parte della stanza". La nota sotto
        // il radar deve dire che l'angolo non e' una direzione fisica e che la
        // distanza dal centro e' RSSI. Tolta quella frase il grafico resta
        // formalmente corretto e sostanzialmente fuorviante.
        assert!(
            INDEX_HTML.contains("L'angolo non indica una direzione fisica"),
            "la nota sotto il radar deve dire che l'angolo non e' una direzione fisica"
        );
        assert!(
            INDEX_HTML.contains("quanto sia vicino a voi (RSSI)"),
            "la nota sotto il radar deve dire che cosa misura davvero la distanza"
        );
        // La voce lunga della legenda non deve tornare a spiegare la stessa
        // cosa in modo diverso: due spiegazioni diverse dello stesso grafico
        // sono la prima riga di un fraintendimento.
        assert!(
            !INDEX_HTML.contains("l'angolo è fisso per ogni dispositivo"),
            "la legenda deve usare la stessa formulazione della nota"
        );
    }

    #[test]
    fn lo_script_della_dashboard_e_javascript_valido() {
        // Il controllo delle graffe sopra e' rozzo e lascia passare i difetti
        // veri: un apostrofo non escapato dentro una stringa, un punto e
        // virgola nel posto sbagliato. Entrambi si vedono solo dal parser, e il
        // sintomo e' sempre lo stesso: la pagina si carica, non mostra errori,
        // e la dashboard resta "meta' viva". Un apostrofo non escapato in una
        // stringa single-quoted spegne lo script dalla riga in cui si trova.
        //
        // `node --check` e' l'unico controllo vero disponibile senza portare
        // dentro un parser JavaScript. Se node non e' installato il test salta:
        // un controllo che passa quando non ha girato e' peggio di nessuno.
        let script = INDEX_HTML
            .split_once("<script>")
            .and_then(|(_, s)| s.split_once("</script>"))
            .map(|(s, _)| s)
            .expect("nessun blocco <script> in INDEX_HTML");
        let dir = std::env::temp_dir().join("bluesniff-js-check");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("dashboard.js");
        std::fs::write(&file, script).expect("scrivo lo script su disco");

        let out = match std::process::Command::new("node")
            .arg("--check")
            .arg(&file)
            .output()
        {
            Ok(o) => o,
            Err(_) => {
                eprintln!("node non installato: sintassi dello script non verificata");
                return;
            }
        };
        assert!(
            out.status.success(),
            "node --check ha rifiutato lo script:
{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[tokio::test]
    async fn la_pagina_dichiara_le_meta_per_ios_e_android() {
        let Some(fx) = start("pwa-meta").await else {
            return;
        };
        let html = reqwest::Client::new()
            .get(format!("{}/", fx.base))
            .send()
            .await
            .expect("GET / fallita")
            .text()
            .await
            .unwrap();
        for ago in [
            "rel=\"manifest\" href=\"/manifest.json\"",
            "apple-mobile-web-app-capable",
            "apple-mobile-web-app-title",
            "rel=\"apple-touch-icon\"",
            "theme-color",
        ] {
            assert!(html.contains(ago), "manca nei meta: {ago}");
        }
        // Il CSS e il JS del layout telefono devono essere nella pagina: se il
        // fallback manca, un telefono vedrebbe la tabella traboccata.
        assert!(html.contains(".device-card"), "manca il CSS delle card");
        assert!(
            html.contains("function renderMobile"),
            "manca renderMobile()"
        );
        assert!(html.contains("renderMobileChips"), "manco i chip mobile");
    }

    #[tokio::test]
    async fn ntfy_test_conferma_l_invio_e_dice_a_che_topic() {
        let Some(_fx) = start("ntfy-test-ok").await else {
            return;
        };
        let server = fake_ntfy("200 OK");
        let r = post_ntfy_test(&_fx.base, "mario-casa", &server).await;
        assert_eq!(r["ok"], true, "l'invia e' fallito: {r}");
        assert!(r["message"].as_str().unwrap().contains("mario-casa"), "{r}");
        assert!(
            !r["error"].as_str().unwrap_or("ok").contains("fallito"),
            "{r}"
        );
    }

    #[tokio::test]
    async fn ntfy_test_distingue_un_rifiuto_del_server() {
        let Some(fx) = start("ntfy-test-400").await else {
            return;
        };
        // ntfy risponde cosi' a un topic che non gli piace: 200 con ok:false e
        // il corpo nella stringa. Un test che mostrasse solo «errore» lascerebbe
        // l'utente senza sapere che il problema e' li'.
        let server = fake_ntfy("400 Bad Request");
        let r = post_ntfy_test(&fx.base, "mario-casa", &server).await;
        assert_eq!(r["ok"], false, "{r}");
        let err = r["error"].as_str().unwrap_or("");
        assert!(err.contains("400"), "manca lo status: {err}");
    }

    #[tokio::test]
    async fn ntfy_test_nonparte_su_topic_o_server_invalidi() {
        let Some(fx) = start("ntfy-test-valida").await else {
            return;
        };
        // La validazione avviene prima di qualsiasi rete: qui non deve
        // partire proprio nessuna richiesta.
        let r = post_ntfy_test(&fx.base, "", "https://ntfy.sh").await;
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(r["error"], "Topic vuoto", "{r}");

        let r = post_ntfy_test(&fx.base, "con spazi", "https://ntfy.sh").await;
        assert_eq!(r["ok"], false, "{r}");
        let err = r["error"].as_str().unwrap_or("");
        assert!(
            err.contains(' '),
            "il motivo deve citare il carattere: {err}"
        );

        let r = post_ntfy_test(&fx.base, "mario-casa", "ntfy.sh").await;
        assert_eq!(r["ok"], false, "{r}");
        let err = r["error"].as_str().unwrap_or("");
        assert!(
            err.contains("http://"),
            "manca il rimando allo schema: {err}"
        );
    }

    #[tokio::test]
    async fn ntfy_test_riporta_un_server_irraggiungibile() {
        let Some(fx) = start("ntfy-test-morto").await else {
            return;
        };
        // Porta 1: nessuno la ascolta, quindi la connessione viene rifiutata
        // subito (niente attesa dei 5 secondi).
        let r = post_ntfy_test(&fx.base, "mario-casa", "http://127.0.0.1:1").await;
        assert_eq!(r["ok"], false, "{r}");
        assert!(
            r["error"].as_str().unwrap_or("").contains("Invio fallito"),
            "il motivo deve essere quello dell'invio, non un errore generico: {r}"
        );
    }

    #[tokio::test]
    async fn ntfy_post_rifiuta_un_topic_malformato_e_non_lo_salva() {
        let Some(fx) = start("ntfy-post-invalido").await else {
            return;
        };
        let res = reqwest::Client::new()
            .post(format!("{}/api/ntfy", fx.base))
            .json(&serde_json::json!({ "topic": "topic con spazi", "enabled": true }))
            .send()
            .await
            .expect("POST /api/ntfy fallita");
        let j: serde_json::Value = res.json().await.unwrap();
        assert_eq!(j["ok"], false, "{j}");
        assert!(j["error"].as_str().unwrap_or("").contains("Topic"), "{j}");
        // Il rifiuto deve aver lasciato intatta la configurazione: un salvataggio
        // parziale sarebbe il peggio (l'utente crede di aver salvato un topic
        // che in realta non e' mai arrivato da nessuna parte).
        let cur = get_json(&format!("{}/api/ntfy", fx.base)).await;
        assert_ne!(cur["topic"], "topic con spazi", "{cur}");
    }

    #[tokio::test]
    async fn report_accetta_un_intervallo_e_rifiuta_un_timestamp_invalido() {
        let dir = tmp_dir("report-range");
        std::fs::create_dir_all(&dir).ok();
        let presenze = dir.join("presenze.csv");
        let Some(fx) = start_with("report-range", Some(presenze)).await else {
            return;
        };
        // Un intervallo che nel fixture non contiene nessuna riga: il report
        // deve dirlo, invece di ripiegare su "tutto il file". Un controllo su
        // una fascia vuota e' pulito perche' non puo' essere un falso positivo
        // (una stringa come "08:00" compare anche nella heatmap, quindi
        // asserire l'assenza di un orario sarebbe Fragile).
        let body = reqwest::Client::new()
            .get(format!(
                "{}/api/report?from=2026-09-30T09:00:00Z&to=2026-09-30T10:00:00Z",
                fx.base
            ))
            .send()
            .await
            .expect("GET con intervallo fallita")
            .text()
            .await
            .unwrap();
        assert!(body.contains("09:00"), "l'intestazione non mostra l'inizio");
        assert!(body.contains("10:00"), "l'intestazione non mostra la fine");
        assert!(
            body.contains("Nessun dato"),
            "un intervallo vuoto deve dirlo, non ripiegare su tutto il file"
        );

        // Un timestamp non parseabile e' un 400 esplicito, non un report
        // dell'ultima settimana: produrre il fallback silenzioso darebbe un
        // file che descrive il periodo sbagliato.
        let res = reqwest::Client::new()
            .get(format!("{}/api/report?from=ieri-mattina", fx.base))
            .send()
            .await
            .expect("GET con from invalida fallita");
        assert_eq!(
            res.status(),
            400,
            "un timestamp invalido deve essere un 400"
        );
    }

    #[tokio::test]
    async fn follow_list_e_unfollow() {
        let Some(fx) = start("ciclo").await else {
            eprintln!("skip: server non avviabile");
            return;
        };

        // 1) Lista vuota (solo l'header "# test").
        let j = get_json(&format!("{}/api/known", fx.base)).await;
        assert_eq!(j["count"], 0, "lista non vuota: {j}");

        // 2) Follow.
        let j = post_json(
            &format!("{}/api/known/follow", fx.base),
            serde_json::json!({"mac": "EC:ED:73:65:AC:45", "name": "Moto G73"}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        assert_eq!(j["watched"], true, "{j}");

        // 3) La lista lo riflette, con il nome dalla richiesta.
        let j = get_json(&format!("{}/api/known", fx.base)).await;
        assert_eq!(j["count"], 1, "follow non registrato: {j}");
        assert_eq!(j["devices"][0]["mac"], "EC:ED:73:65:AC:45");
        assert_eq!(j["devices"][0]["nome"], "Moto G73");

        // 4) Il file su disco contiene la riga.
        let text = std::fs::read_to_string(&fx.known_path).unwrap();
        assert!(text.contains("EC:ED:73:65:AC:45;Moto G73;"), "{text}");

        // 5) Unfollow.
        let j = post_json(
            &format!("{}/api/known/unfollow", fx.base),
            serde_json::json!({"mac": "EC:ED:73:65:AC:45"}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        assert_eq!(j["watched"], false, "{j}");

        // 6) Lista di nuovo vuota, file senza la riga.
        let j = get_json(&format!("{}/api/known", fx.base)).await;
        assert_eq!(j["count"], 0, "unfollow non registrato: {j}");
        let text = std::fs::read_to_string(&fx.known_path).unwrap();
        assert!(!text.contains("EC:ED:73:65:AC:45"), "{text}");
    }

    #[tokio::test]
    async fn follow_ripetuto_non_duplica_la_riga() {
        let Some(fx) = start("idem").await else {
            return;
        };
        for _ in 0..2 {
            let j = post_json(
                &format!("{}/api/known/follow", fx.base),
                serde_json::json!({"mac": "AA:BB:CC:DD:EE:01", "name": "X"}),
            )
            .await;
            assert_eq!(j["ok"], true, "{j}");
        }
        let text = std::fs::read_to_string(&fx.known_path).unwrap();
        assert_eq!(text.matches("AA:BB:CC:DD:EE:01").count(), 1, "{text}");
        let j = get_json(&format!("{}/api/known", fx.base)).await;
        assert_eq!(j["count"], 1, "riga duplicata in lista: {j}");
    }

    #[tokio::test]
    async fn follow_con_mac_invalido_riporta_l_errore() {
        let Some(fx) = start("invalido").await else {
            return;
        };
        let j = post_json(
            &format!("{}/api/known/follow", fx.base),
            serde_json::json!({"mac": "non-un-mac", "name": "X"}),
        )
        .await;
        // HTTP 200 con ok=false: e' la convenzione del progetto, la UI legge
        // il campo `error` e non lo status.
        assert_eq!(j["ok"], false, "MAC invalido accettato: {j}");
        assert!(j["error"].as_str().unwrap_or("").contains("MAC"), "{j}");
    }

    #[tokio::test]
    async fn follow_ripulisce_i_separatori_del_nome() {
        let Some(fx) = start("separatori").await else {
            return;
        };
        let j = post_json(
            &format!("{}/api/known/follow", fx.base),
            serde_json::json!({"mac": "AA:BB:CC:DD:EE:02", "name": "Nome;con;separatori"}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        let text = std::fs::read_to_string(&fx.known_path).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with("AA:BB:CC:DD:EE:02"))
            .expect("riga assente");
        // Esattamente due separatori: MAC;Nome;Persona-vuota. Con un ';' in
        // piu' la riga non sarebbe leggibile come un dispositivo.
        assert_eq!(line.matches(';').count(), 2, "riga malformata: {line}");
    }

    #[tokio::test]
    async fn unfollow_di_mac_mai_seguito_e_un_noop() {
        let Some(fx) = start("noop").await else {
            return;
        };
        let j = post_json(
            &format!("{}/api/known/unfollow", fx.base),
            serde_json::json!({"mac": "FF:FF:FF:FF:FF:FF"}),
        )
        .await;
        // L'operazione e' "assicurati che non ci sia", non "cancella o fallisci":
        // un doppio click su un follow gia' annullato non deve essere un errore.
        assert_eq!(j["ok"], true, "{j}");
        assert_eq!(j["watched"], false, "{j}");
    }

    #[tokio::test]
    async fn follow_non_tocca_le_righe_scritte_a_mano() {
        let Some(fx) = start("manuali").await else {
            return;
        };
        // Un utente che ha editato a mano: commenti, persona, riga vuota.
        let orig = "# Dispositivi di casa\nAA:BB:CC:DD:EE:01;iPhone;Mario\n\n# fine\n";
        std::fs::write(&fx.known_path, orig).unwrap();

        let j = post_json(
            &format!("{}/api/known/follow", fx.base),
            serde_json::json!({"mac": "EC:ED:73:65:AC:45", "name": "Moto"}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");

        let text = std::fs::read_to_string(&fx.known_path).unwrap();
        // Tutto il contenuto originale e' ancora li...
        assert!(text.starts_with("# Dispositivi di casa"), "{text}");
        assert!(text.contains("AA:BB:CC:DD:EE:01;iPhone;Mario"), "{text}");
        assert!(text.contains("# fine"), "{text}");
        // ...e la riga nuova e' in fondo, non inserita in mezzo.
        let pos_fine = text.find("# fine").unwrap();
        let pos_new = text.find("EC:ED:73:65:AC:45").unwrap();
        assert!(pos_new > pos_fine, "riga nuova fuori posto:\n{text}");

        // E l'unfollow riporta il file esattamente com'era.
        let j = post_json(
            &format!("{}/api/known/unfollow", fx.base),
            serde_json::json!({"mac": "EC:ED:73:65:AC:45"}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        assert_eq!(std::fs::read_to_string(&fx.known_path).unwrap(), orig);
    }

    #[tokio::test]
    async fn follow_aggiorna_watched_nello_stato_del_server() {
        let Some(fx) = start("live").await else {
            return;
        };
        // Il dispositivo e' gia' in lista ma NON e' seguito: lo mettiamo li'
        // come farebbe una finestra BLE che lo vede per la prima volta.
        // Usiamo `update` e non `update_classic`: quest'ultimo, per definizione,
        // riceve gia' i telefoni noti e li marca sempre come watched.
        let mac = "AA:BB:CC:DD:EE:05";
        crate::dashboard::update(
            &fx.state,
            &[crate::blewatcher::Seen {
                mac: mac.to_string(),
                name: Some("Moto".to_string()),
                rssi: Some(-60),
                vendor: None,
                hint: None,
                fingerprint: None,
                model_id: None,
                phantom: None,
                tx_power: None,
                tx_ibeacon: false,
                connectable: None,
            }],
            &[],
        );
        {
            let devs = fx.state.devices.read().unwrap();
            assert_eq!(devs.len(), 1, "dispositivo non inserito");
            // Con `known` vuoto non e' ancora seguito.
            assert!(!devs[0].watched, "partito gia' come watched");
        }

        // Il follow passa per HTTP, sullo stato vero del server.
        let j = post_json(
            &format!("{}/api/known/follow", fx.base),
            serde_json::json!({"mac": mac, "name": "Moto"}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        assert!(
            fx.state.devices.read().unwrap()[0].watched,
            "watched non aggiornato in memoria: la stella non comparirebbe subito"
        );

        // E l'unfollow lo toglie di nuovo.
        let j = post_json(
            &format!("{}/api/known/unfollow", fx.base),
            serde_json::json!({"mac": mac}),
        )
        .await;
        assert_eq!(j["ok"], true, "{j}");
        assert!(!fx.state.devices.read().unwrap()[0].watched);
    }
}
