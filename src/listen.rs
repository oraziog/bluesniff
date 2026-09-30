//! `--listen` mode: the passive/active presence recorder.
//!
//! Every 10 s the BLE radio opens for 8 s and every unique device seen is
//! appended to `presenze.csv` (semicolon-delimited, RFC3339 UTC first column,
//! same timeline key as netmonloc). Every 60 s (6 cycles) the known phones
//! are actively paged (Bluetooth Classic, see `btclassic`). Every 5 min (30
//! cycles) an inquiry scans for discoverable devices as a learning hint.
//!
//! The recorder is deliberately "dumb": it only stores what the radio sees.
//! Who entered/left is decided afterwards, in analysis, from netmonloc.

use std::error::Error;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::alerts::AlertTracker;
use crate::btclassic::{self, KnownBt, ProbeResult};
use crate::classify::{classify_device, proximity_zone, DeviceCategory};
use crate::dashboard::DashboardState;
use crate::logging::Logger;

/// Passive cycle: radio open for 8 s every 10 s — one BLE sample every 10 s,
/// aligned with the live plot refresh (live_plot.py --interval 10).
pub const CYCLE_SECS: u64 = 10;
pub const SCAN_SECS: u64 = 8;
/// Active probe of the known phones every 6 cycles (60 s).
pub const ACTIVE_EVERY: usize = 6;
/// Inquiry for discoverable devices every 30 cycles (5 min).
pub const INQUIRY_EVERY: usize = 30;

/// Run the passive/active recorder for `seconds` if `Some`, otherwise until
/// Ctrl+C or the `q` key. Appends rows to `presenze.csv`, flushed after every
/// sample so partial data survives a kill. `alerts` receives the active-probe
/// results each round to fire watched-device ntfy.sh notifications.
//
// Come `run_listen`: i parametri sono uno per uno i flag della riga di comando.
#[allow(clippy::too_many_arguments)]
pub async fn listen(
    logger: &Logger,
    seconds: Option<u64>,
    presenze_path: &Path,
    mut known: Vec<KnownBt>,
    alerts: &mut AlertTracker,
    dashboard: Option<DashboardState>,
    stream: Option<crate::stream::StreamHandle>,
    passive: bool,
    // Riga di contesto per il PID file: i flag con cui siamo partiti. La
    // costruisce `run_listen`, che conosce i flag, e la usa `--status`.
    ctl_context: &str,
) -> Result<(), Box<dyn Error>> {
    // Streaming (netmonloc): in modalità `--json` lo stdout è riservato alle
    // righe NDJSON, quindi i banner umani vanno solo nel log. In modalità
    // streaming presenze.csv NON viene scritto: i dati passano via chiamate
    // (stdout/push), non via file.
    let stream_json = stream.as_ref().is_some_and(|h| h.cfg.json);
    // Warn loudly when no Bluetooth radio is present (e.g. this VM without
    // the USB passthrough from Proxmox) instead of silently recording 0 BLE.
    if crate::blewatcher::radio_present().await {
        logger.log("listen: Bluetooth radio present (BLE watcher active)");
        if passive {
            logger.log("listen: PASSIVE scanning mode (no SCAN_REQ packets)");
        }
    } else {
        logger.log("listen: !! NO Bluetooth radio reported by the OS — BLE will record 0 devices.");
        logger.log("listen: !! Check the Proxmox USB passthrough (qm set 101 --usb0 host=... + stop/start).");
        if !stream_json {
            crate::bn!("\x1b[31m[BLUESNIFF] WARNING: no Bluetooth radio detected — BLE will record 0 devices.\x1b[0m");
            crate::bn!("\x1b[31m[BLUESNIFF] Check the Proxmox USB passthrough (qm set 101 --usb0 host=... + stop/start).\x1b[0m");
        }
    }

    if let Some(handle) = &stream {
        let chans: Vec<&str> = {
            let mut c = Vec::new();
            if handle.cfg.json {
                c.push("stdout NDJSON");
            }
            if handle.cfg.push_url.is_some() {
                c.push("--push");
            }
            c
        };
        logger.log(&format!(
            "listen: streaming mode ({}) — presenze.csv NOT written",
            chans.join(" + ")
        ));
    }

    // APPEND mode (solo senza streaming): un restart non deve mai troncare
    // presenze.csv, altrimenti la live plot (ancorata all'ultima riga) perde
    // tutti i campioni precedenti e riparte "da adesso". Header scritto solo
    // su file nuovo/vuoto.
    let mut wtr: Option<csv::Writer<std::fs::File>> = None;
    if stream.is_none() {
        use std::fs::OpenOptions;
        let is_new = !presenze_path.exists()
            || presenze_path
                .metadata()
                .map(|m| m.len() == 0)
                .unwrap_or(true);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(presenze_path)?;
        let mut w = csv::WriterBuilder::new().delimiter(b';').from_writer(file);
        if is_new {
            w.write_record([
                "ora",
                "tipo",
                "mac",
                "nome",
                "persona",
                "rssi",
                "fingerprint",
                "vendor",
                "hint",
                "stato",
                "stazione",
            ])?;
        } else {
            logger.log("listen: presenze.csv exists, APPEND — previous data is preserved");
        }
        wtr = Some(w);
    }

    let start = Instant::now();
    let mut n = 0usize;
    // Ultima volta che abbiamo riletto il file. Se la dashboard aggiunge o
    // toglie un dispositivo con il pulsante Segui, ce ne accorgiamo qui senza
    // che l'utente debba riavviare --listen.
    let mut known_checked = std::time::Instant::now();
    let known_path = crate::known::path();
    let mut known_mtime = std::fs::metadata(&known_path)
        .and_then(|m| m.modified())
        .ok();

    // Identificativo della stazione server BT: il MAC dell'adattatore (per
    // distinguere più stazioni sulla stessa rete nelle analisi di presenze.csv).
    // Fallback: nome host Windows quando l'OS non espone l'adattatore.
    let station = match crate::blewatcher::local_adapter_mac().await {
        Some(m) => m,
        None => std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
    };
    logger.log(&format!("listen: stazione server = {station}"));
    // Nome della stazione (host) incluso nello snapshot per netmonloc.
    let station_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());

    // Stato di controllo condiviso: lo alimentano tre canali (Ctrl+C, la
    // tastiera su stdin, il file di controllo / l'HTTP) e lo legge il loop.
    // Prima erano due AtomicBool locali e solo lo stdin poteva toccarli: da
    // un .bat o da Task Scheduler non c'e' stdin, e quindi non c'era modo di
    // fermare il processo senza taskkill /F.
    let mode = ctl_context.to_string();
    let mut ctl_state = crate::control::ControlState::new(&mode);
    // Un solo flag di pausa per processo. Prima erano due: quello del canale di
    // controllo e quello della dashboard, e un utente che metteva in pausa dal
    // pannello e poi riprendeva da riga di comando restava fermo (o il
    // contrario), senzache nessuno dei due dicesse perche'. Qui la dashboard
    // cede il suo `Arc`, cosi' i due canali scrivono sullo stesso stato.
    if let Some(d) = &dashboard {
        ctl_state.paused = d.paused.clone();
    }
    ctl_state.set_info(|i| {
        i.user = std::env::var("USERNAME").unwrap_or_default();
    });
    // PID file: dichiara questo processo a `--status` e impedisce a un secondo
    // bluesniff nella stessa cartella di scrivere sugli stessi CSV. Va scritto
    // dopo l'inizializzazione (c'e' gia' la radio, il writer e la dashboard) e
    // prima del loop: un comando che arriva prima del loop aspetterebbe un
    // ciclo intero, e l'utente leggerebbe quel ritardo come un blocco.
    if let Err(e) = crate::control::write_pid_at(&crate::control::paths(), &mode) {
        return Err(e.into());
    }
    // Canale HTTP: se la dashboard e' accesa la riusiamo (un solo server per
    // processo), altrimenti parte un server di controllo su 127.0.0.1.
    let http_port: Arc<std::sync::Mutex<Option<u16>>> = Arc::new(std::sync::Mutex::new(None));
    if let Some(p) = crate::control::ensure_http_control(
        dashboard.as_ref().map(|d| d.port()),
        ctl_state.clone(),
        logger,
    )
    .await
    {
        if let Ok(mut slot) = http_port.lock() {
            *slot = Some(p);
        }
    }
    crate::control::spawn_ctl_watcher(ctl_state.clone(), logger.clone(), http_port.clone());

    // Ctrl+C -> clean close.
    {
        let shutdown = ctl_state.shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.store(true, Ordering::Relaxed);
        });
    }
    {
        let state = ctl_state.clone();
        // 'q' / 'Q' on stdin -> clean close (long night runs). In modalita`
        // `--json` il comando 'snapshot' (alias 'devices'/'s') risponde subito con
        // una riga JSON dell'ultimo snapshot: netmonloc, che ci ha avviato come
        // sottoprocesso, puo' chiederlo quando vuole senza aspettare il ciclo.
        //
        // Se stdin non e' un terminale (`.bat`, Task Scheduler, servizio) la
        // lettura restituisce subito EOF e questo task muore: non e' un errore,
        // e' la situazione normale in quei contesti. Il canale di controllo
        // (file e HTTP) resta disponibile.
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let t = line.trim();
                if t.eq_ignore_ascii_case("q") {
                    state.shutdown.store(true, Ordering::Relaxed);
                    break;
                }
                if t.eq_ignore_ascii_case("snapshot")
                    || t.eq_ignore_ascii_case("devices")
                    || t.eq_ignore_ascii_case("s")
                {
                    if let Ok(guard) = state.latest_json.lock() {
                        if let Some(v) = guard.as_ref() {
                            println!("{v}");
                        }
                    }
                }
                // Comandi interattivi: stop/start/clear
                if t.eq_ignore_ascii_case("stop") || t.eq_ignore_ascii_case("pause") {
                    state.paused.store(true, Ordering::Relaxed);
                    println!("[BLUESNIFF] Scanner in pausa. Digita 'start' per riprendere.");
                }
                if t.eq_ignore_ascii_case("start") || t.eq_ignore_ascii_case("resume") {
                    state.paused.store(false, Ordering::Relaxed);
                    println!("[BLUESNIFF] Scanner ripreso.");
                }
                if t.eq_ignore_ascii_case("clear") {
                    // Clear terminal screen
                    println!("[2J[H");
                }
            }
        });
    }

    // Stato presenza per l'auto-SDP: true = telefono noto già sondato nella
    // presenza corrente (il flag torna false quando risulta assente, così la
    // sonda riparte alla presenza successiva).
    let mut sdp_done: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    // Storico RSSI/fingerprint per la marcatura falsi positivi ambientali
    // in console (stessa matematica della dashboard: pin statico per varianza
    // RSSI, doppia-freccia rotante per fingerprint condiviso tra piu MAC).
    let mut rssi_hist: std::collections::HashMap<String, Vec<i16>> =
        std::collections::HashMap::new();
    let mut fp_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    loop {
        if let Some(secs) = seconds {
            if start.elapsed() >= Duration::from_secs(secs) {
                break;
            }
        }
        if ctl_state.shutdown.load(Ordering::Relaxed) {
            break;
        }
        // Se in pausa (tastiera, file di controllo, HTTP o pulsante della
        // dashboard: ora e' lo stesso flag), aspetta 1 secondo e riprova.
        let is_paused = ctl_state.paused.load(Ordering::Relaxed);
        if is_paused {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        n += 1;

        // 1) Passive BLE window (WinRT advertisement watcher: a device that
        // stops advertising simply stops generating events, so the window
        // reflects exactly what is on air right now — no frozen-cache ghosts).
        let seen = crate::blewatcher::scan_window(Duration::from_secs(SCAN_SECS), passive).await;
        // Live dashboard: aggiorna lo stato condiviso con i dispositivi visti
        // in questa finestra (il server HTTP li serve ai client).
        if let Some(state) = &dashboard {
            crate::dashboard::update(state, &seen, &known);
        }
        let ora = crate::logging::utc_now_rfc3339();
        // Category tally for the enriched sample line (bluehood-style).
        let mut tally: Vec<(DeviceCategory, usize)> = Vec::new();
        for d in &seen {
            let category =
                classify_device(d.name.as_deref(), d.vendor.as_deref(), d.hint.as_deref());
            match tally.iter_mut().find(|(c, _)| *c == category) {
                Some(entry) => entry.1 += 1,
                None => tally.push((category, 1)),
            }
            if let Some(zone) = proximity_zone(d.rssi) {
                logger.log(&format!(
                    "listen: ble {} [{}] rssi={:?} zone={} cat={}",
                    d.mac,
                    d.name.as_deref().unwrap_or("-"),
                    d.rssi,
                    zone,
                    category.label()
                ));
            }
            if let Some(w) = wtr.as_mut() {
                w.write_record([
                    ora.clone(),
                    "passivo".to_string(),
                    d.mac.clone(),
                    d.name.clone().unwrap_or_default(),
                    String::new(), // persona: assigned by analysis (BLE MACs rotate)
                    d.rssi.map(|v| v.to_string()).unwrap_or_default(),
                    d.fingerprint.clone().unwrap_or_default(),
                    d.vendor.clone().unwrap_or_default(),
                    d.hint.clone().unwrap_or_default(),
                    "visto".to_string(),
                    station.clone(),
                ])?;
            }
        }

        // Streaming verso netmonloc (canale stdout NDJSON con `--json` e/o
        // HTTP con `--push`): snapshot di questo ciclo con tutti i device
        // visti. Aggiorna anche l'ultimo snapshot (comando `snapshot` su
        // stdin). In modalità streaming il blocco CSV qui sopra è saltato.
        if let Some(handle) = &stream {
            let payload = crate::stream::snapshot_value(&station, &station_name, &ora, n, &seen);
            if handle.cfg.json {
                println!("{payload}");
                if let Ok(mut latest) = ctl_state.latest_json.lock() {
                    *latest = Some(payload.clone());
                }
            }
            if let Some(tx) = &handle.push_tx {
                // Non bloccante: il pusher in background ritenta con backoff.
                let _ = tx.send(payload);
            }
        }

        // Rileggiamo `bt_known.txt` una volta ogni tanto: il pulsante Segui
        // della dashboard lo modifica mentre il processo gira, e senza questo
        // il nuovo dispositivo entrerebbe in lista solo al riavvio. Il file e'
        // minuscolo (poche decine di righe) e la lettura costa una
        // `read_to_string`: trascurabile rispetto a una finestra di scansione.
        if known_checked.elapsed() >= std::time::Duration::from_secs(30) {
            known_checked = std::time::Instant::now();
            // Confronto la data di modifica, non il numero di righe: cosi'
            // vale anche se l'utente corregge a mano un nome o riempe la
            // colonna Persona mentre il processo gira.
            let mtime = std::fs::metadata(&known_path)
                .and_then(|m| m.modified())
                .ok();
            if mtime != known_mtime {
                known_mtime = mtime;
                let fresh = btclassic::load_bt_known(&known_path);
                logger.log(&format!(
                    "listen: bt_known.txt changed on disk, reloaded ({} -> {} known device(s))",
                    known.len(),
                    fresh.len()
                ));
                known = fresh;
            }
        }

        // 2) Active probe of the known phones (parallel, every ACTIVE_EVERY).
        if n.is_multiple_of(ACTIVE_EVERY) && !known.is_empty() {
            let known2 = known.clone();
            let results: Vec<ProbeResult> =
                tokio::task::spawn_blocking(move || btclassic::probe_macs(&known2))
                    .await
                    .unwrap_or_default();
            let ora = crate::logging::utc_now_rfc3339();
            for r in &results {
                let (nome, persona) = known
                    .iter()
                    .find(|k| k.mac == r.mac)
                    .map(|k| (k.nome.clone(), k.persona.clone()))
                    .unwrap_or_default();
                if let Some(w) = wtr.as_mut() {
                    w.write_record([
                        ora.clone(),
                        "attivo".to_string(),
                        r.mac.clone(),
                        nome,
                        persona,
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        if r.present { "presente" } else { "assente" }.to_string(),
                        station.clone(),
                    ])?;
                }
            }
            logger.log(&format!(
                "listen: active probe {} known, {}/{} present",
                results.len(),
                results.iter().filter(|r| r.present).count(),
                results.len()
            ));
            for r in &results {
                logger.log(&format!(
                    "listen: probe {} -> {} ({} ms)",
                    r.mac, r.detail, r.elapsed_ms
                ));
            }
            // Watched-device arrival/departure push notifications.
            alerts.update(logger, &results, &known);
            // Live dashboard: il telefono presente compare nei pannelli
            // Seguiti/Attivi anche senza annunci BLE.
            if let Some(state) = &dashboard {
                crate::dashboard::update_classic(state, &results, &known);
            }

            // Auto-SDP (idea da bluing `br --sdp`): quando un telefono noto
            // diventa presente si sonda UNA volta per presenza la sua tabella
            // servizi classici (MAP/PBAP/OBEX...) e si salva la fingerprint:
            // riga tipo `sdp` in presenze.csv + cache dashboard (`sdp:<mac>`,
            // così la scheda la mostra senza rilanciare la sonda).
            let mut sdp_runs: Vec<(
                String,
                String,
                String,
                tokio::task::JoinHandle<crate::sdp::SdpProbe>,
            )> = Vec::new();
            for r in &results {
                if !r.present {
                    sdp_done.insert(r.mac.clone(), false);
                    continue;
                }
                if sdp_done.get(&r.mac).copied().unwrap_or(false) {
                    continue; // già sondato in questa presenza
                }
                sdp_done.insert(r.mac.clone(), true);
                let (nome, persona) = known
                    .iter()
                    .find(|k| k.mac == r.mac)
                    .map(|k| (k.nome.clone(), k.persona.clone()))
                    .unwrap_or_default();
                let mac2 = r.mac.clone();
                sdp_runs.push((
                    r.mac.clone(),
                    nome,
                    persona,
                    tokio::task::spawn_blocking(move || crate::sdp::probe(&mac2)),
                ));
            }
            if !sdp_runs.is_empty() {
                logger.log(&format!(
                    "listen: auto-SDP su {} telefono/i appena presente/i...",
                    sdp_runs.len()
                ));
            }
            let ora_sdp = crate::logging::utc_now_rfc3339();
            for (mac, nome, persona, handle) in sdp_runs {
                if let Ok(p) = handle.await {
                    let services = p
                        .services
                        .iter()
                        .map(|s| s.class_name.clone())
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let hint = match &p.error {
                        Some(e) => format!("sdp errore: {e}"),
                        None => services,
                    };
                    logger.log(&format!(
                        "listen: auto-SDP {} -> {} servizi{}",
                        mac,
                        p.services.len(),
                        if p.risks.is_empty() {
                            String::new()
                        } else {
                            format!(
                                " (esposizioni: {})",
                                p.risks
                                    .iter()
                                    .map(|r| r.title)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        }
                    ));
                    if let Some(w) = wtr.as_mut() {
                        w.write_record([
                            ora_sdp.clone(),
                            "sdp".to_string(),
                            mac.clone(),
                            nome,
                            persona,
                            String::new(),
                            String::new(),
                            String::new(),
                            hint,
                            "presente".to_string(),
                            station.clone(),
                        ])?;
                    }
                    if let Some(state) = &dashboard {
                        if let Ok(v) = serde_json::to_value(&p) {
                            crate::dashboard::store_probe(state, "sdp", &mac, &v);
                        }
                    }
                }
            }
        }

        // 3) Inquiry every INQUIRY_EVERY cycles (learning hint only).
        if n.is_multiple_of(INQUIRY_EVERY) {
            let found = tokio::task::spawn_blocking(|| btclassic::inquiry(5))
                .await
                .unwrap_or_default();
            logger.log(&format!(
                "listen: inquiry found {} discoverable classic device(s)",
                found.len()
            ));
            for d in &found {
                logger.log(&format!(
                    "listen: discoverable {} name=\"{}\" class=0x{:06X}",
                    d.mac, d.nome, d.class_of_device
                ));
            }
            // Live dashboard: aggiorna il pannello "Inquiry Classic".
            if let Some(state) = &dashboard {
                crate::dashboard::set_inquiry(state, &found);
            }

            // Auto-SDP reattivo (idea da bluing `br --sdp`): se un telefono
            // noto è comparso nell'inquiry (page-scan/discoverable) prima del
            // prossimo probe attivo, sondalo subito invece di aspettare i 60 s
            // del ciclo ACTIVE_EVERY. Stesso gating di "una sonda per
            // presenza" e stessa registrazione (riga `sdp` in presenze.csv +
            // cache dashboard `sdp:<mac>`).
            let found_known: Vec<String> = found
                .iter()
                .map(|d| d.mac.to_uppercase())
                .filter(|m| known.iter().any(|k| k.mac.to_uppercase() == *m))
                .filter(|m| !sdp_done.get(m).copied().unwrap_or(false))
                .collect();
            if !found_known.is_empty() {
                let mut sdp_runs: Vec<(
                    String,
                    String,
                    String,
                    tokio::task::JoinHandle<crate::sdp::SdpProbe>,
                )> = Vec::new();
                for mac in found_known {
                    sdp_done.insert(mac.clone(), true);
                    let (nome, persona) = known
                        .iter()
                        .find(|k| k.mac.to_uppercase() == mac)
                        .map(|k| (k.nome.clone(), k.persona.clone()))
                        .unwrap_or_default();
                    let mac2 = mac.clone();
                    sdp_runs.push((
                        mac.clone(),
                        nome,
                        persona,
                        tokio::task::spawn_blocking(move || crate::sdp::probe(&mac2)),
                    ));
                }
                logger.log(&format!(
                    "listen: auto-SDP via inquiry su {} telefono/i...",
                    sdp_runs.len()
                ));
                let ora_sdp = crate::logging::utc_now_rfc3339();
                for (mac, nome, persona, handle) in sdp_runs {
                    if let Ok(p) = handle.await {
                        let services = p
                            .services
                            .iter()
                            .map(|s| s.class_name.clone())
                            .collect::<Vec<_>>()
                            .join(" | ");
                        let hint = match &p.error {
                            Some(e) => format!("sdp errore: {e}"),
                            None => services,
                        };
                        logger.log(&format!(
                            "listen: auto-SDP (inquiry) {} -> {} servizi{}",
                            mac,
                            p.services.len(),
                            if p.risks.is_empty() {
                                String::new()
                            } else {
                                format!(
                                    " (esposizioni: {})",
                                    p.risks
                                        .iter()
                                        .map(|r| r.title)
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )
                            }
                        ));
                        if let Some(w) = wtr.as_mut() {
                            w.write_record([
                                ora_sdp.clone(),
                                "sdp".to_string(),
                                mac.clone(),
                                nome,
                                persona,
                                String::new(),
                                String::new(),
                                String::new(),
                                hint,
                                "presente".to_string(),
                                station.clone(),
                            ])?;
                        }
                        if let Some(state) = &dashboard {
                            if let Ok(v) = serde_json::to_value(&p) {
                                crate::dashboard::store_probe(state, "sdp", &mac, &v);
                            }
                        }
                    }
                }
            }
        }

        if let Some(w) = wtr.as_mut() {
            w.flush()?;
        }

        // Marcatura falsi positivi ambientali in console: stessa matematica
        // della dashboard (fpfilter) — varianza RSSI < 4.0 su >= 5 campioni
        // -> statico; stesso fingerprint su >= 2 MAC -> rotante.
        let mut env_flags = String::new();
        for d in &seen {
            if let Some(rssi) = d.rssi {
                let hist = rssi_hist.entry(d.mac.to_uppercase()).or_default();
                hist.push(rssi);
                if hist.len() > 120 {
                    hist.drain(..hist.len() - 120);
                }
            }
            if let Some(fp) = &d.fingerprint {
                if !fp.is_empty() {
                    fp_map.insert(d.mac.to_uppercase(), fp.clone());
                }
            }
        }
        if !seen.is_empty() {
            use crate::fpfilter::{
                is_static_rssi, rotating_families, MIN_SAMPLES, VARIANCE_THRESHOLD,
            };
            let mut parts: Vec<String> = Vec::new();
            for d in &seen {
                let mac_up = d.mac.to_uppercase();
                if rssi_hist
                    .get(&mac_up)
                    .is_some_and(|h| is_static_rssi(h, MIN_SAMPLES, VARIANCE_THRESHOLD))
                {
                    parts.push(format!("📌 {mac_up}"));
                }
            }
            let pairs: Vec<(&str, &str)> = fp_map
                .iter()
                .map(|(m, f)| (m.as_str(), f.as_str()))
                .collect();
            for (_, macs) in rotating_families(&pairs) {
                let n = macs.len();
                for m in &macs {
                    if seen.iter().any(|s| s.mac.eq_ignore_ascii_case(m)) {
                        parts.push(format!("🔄{n} {m}"));
                    }
                }
            }
            if !parts.is_empty() {
                env_flags = format!(" | {}", parts.join(" "));
            }
        }

        // Stato per `--status`: quello che il loop sa e che nessun altro
        // file sa. Scritto qui, non nel task di controllo, perche' i dati
        // esistono solo qui.
        let unique_now = match &dashboard {
            Some(d) => d.devices.read().map(|v| v.len()).unwrap_or(0),
            None => 0,
        };
        ctl_state.set_info(|i| {
            i.cycles = n as u64;
            i.unique = unique_now;
            i.packets = crate::radiostate::ble_total();
            // Non diciamo "radio ON": dai dati sappiamo solo se il canale LE
            // sta producendo pacchetti, e quello e' un fatto utile. Lo stato
            // WinRT della radio e' un'altra cosa, e dirlo qui sarebbe una
            // deduzione non fondata.
            i.radio = match crate::radiostate::since_last_ble_ms() {
                None => "nessun pacchetto BLE ricevuto".to_string(),
                Some(ms) => format!("ultimo pacchetto BLE {}s fa", ms / 1000),
            };
            i.last_cycle_secs = Some(0);
        });
        logger.log(&format!(
            "listen sample {n}: {} BLE seen, {} known BT probed{env_flags}",
            seen.len(),
            known.len()
        ));
        let cats = tally
            .iter()
            .map(|(c, k)| format!("{} x{}", c.label(), k))
            .collect::<Vec<_>>()
            .join(", ");
        // In modalità `--json` lo stdout è riservato all'NDJSON: la riga
        // umana del campione va solo nel log.
        if !stream_json {
            crate::bn!(
                "\x1b[34m[BLUESNIFF]\x1b[0m listen sample {n}: {} BLE ({}) , {} known BT{env_flags}",
                seen.len(),
                if cats.is_empty() { "-".to_string() } else { cats },
                known.len()
            );
        }

        // Sleep until the next cycle boundary. The passive window already
        // took SCAN_SECS, so sleep CYCLE_SECS - SCAN_SECS to keep the real
        // cadence at CYCLE_SECS (e.g. 8 s radio + 2 s pause = 10 s cycle).
        let pause = CYCLE_SECS.saturating_sub(SCAN_SECS);
        if let Some(secs) = seconds {
            let left = secs.saturating_sub(start.elapsed().as_secs());
            if left > 0 {
                tokio::time::sleep(Duration::from_secs(pause.min(left))).await;
            }
        } else {
            tokio::time::sleep(Duration::from_secs(pause)).await;
        }
    }

    if let Some(w) = wtr.as_mut() {
        w.flush()?;
    }
    // File di controllo: il processo non e' piu' vivo, quindi non deve
    // lasciare traccia che farebbero pensare il contrario. Se il processo e'
    // stato ucciso con taskkill /F questo codice non gira: se ne accorge il
    // prossimo avvio, che trova un PID morto e lo sovrascrive.
    crate::control::remove_files_at(&crate::control::paths());
    logger.log("listen: finished (clean close, presenze flushed)");
    Ok(())
}
