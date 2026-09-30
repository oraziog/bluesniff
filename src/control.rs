//! Controllo del processo senza stdin.
//!
//! bluesniff lo si lancia in molti modi: da un terminale (e allora i comandi
//! `q`, `stop`, `start` arrivano su stdin), ma anche da un `.bat`, da Task
//! Scheduler, da un servizio Windows, da SSH non interattivo, o come
//! sottoprocesso di un orchestratore. In tutti questi casi stdin non è un
//! terminale e i comandi interattivi non arrivano mai: il processo gira e
//! l'unico modo per fermarlo diventa `taskkill /F`, che tronca `presenze.csv`.
//!
//! Qui nasce un secondo canale di controllo, che non passa da stdin:
//!
//! - `bluesniff.ctl` — un file con un comando (`pause`, `resume`, `stop`,
//!   `snapshot`, `status`). Funziona ovunque, non richiede porte né permessi.
//! - `bluesniff.http` — la porta di un piccolo server locale che espone gli
//!   stessi cinque comandi come POST. Se la dashboard è già attiva, non se ne
//!   avvia un secondo: si riusa la sua porta (un solo server HTTP per
//!   processo, sempre).
//!
//! I file di stato (`bluesniff.pid`, `bluesniff.status`, `bluesniff.ack`) sono
//! testo semplice e leggibili a mano: `type bluesniff.status` dal prompt dei
//! comandi dice più di qualunque endpoint, e un utente che non ha letto il
//! README può comunque capire cosa sta succedendo.
//!
//! Il ritardo del canale file è di un secondo (polling), il canale HTTP è
//! immediato. Per una pausa un secondo di ritardo non è un problema: il ciclo
//! di scansione dura dieci secondi, quindi l'effetto è comunque al ciclo
//! successivo.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::logging::Logger;

/// Percorso di base dei file di controllo.
///
/// Tutti i file stanno nella stessa cartella, scelta da `exe_dir()`: spostare
/// l'eseguibile porta con sé il PID file, e questo è ciò che l'utente si
/// aspetta. I test usano `Paths::in_dir` per non scrivere nella cartella
/// dell'eseguabile.
#[derive(Clone, Debug)]
pub struct Paths {
    dir: PathBuf,
}

impl Paths {
    /// Percorsi in una directory specifica. Esiste per i test: scrivere
    /// `bluesniff.pid` nella cartella dell'eseguabile durante un test
    /// farebbe credere a un processo in esecuzione che ce n'e' un altro, e i
    /// test in parallelo si romperebbero a vicenda.
    #[cfg(test)]
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Percorsi reali, accanto all'eseguibile.
    pub fn default() -> Self {
        Self {
            dir: crate::logging::exe_dir(),
        }
    }

    /// PID del processo long-running, con la riga di contesto (i flag).
    pub fn pid(&self) -> PathBuf {
        self.dir.join("bluesniff.pid")
    }
    /// Comando da eseguire (scritto dai flag `--pause`, `--stop`, ...).
    pub fn ctl(&self) -> PathBuf {
        self.dir.join("bluesniff.ctl")
    }
    /// Conferma dell'esito del comando, con l'eventuale messaggio.
    pub fn ack(&self) -> PathBuf {
        self.dir.join("bluesniff.ack")
    }
    /// Stato corrente del processo, in JSON su una riga.
    pub fn status(&self) -> PathBuf {
        self.dir.join("bluesniff.status")
    }
    /// Porta del server di controllo HTTP (quella della dashboard, se c'è).
    pub fn http(&self) -> PathBuf {
        self.dir.join("bluesniff.http")
    }
    /// Ultimo snapshot JSON, scritto su richiesta del comando `snapshot`.
    pub fn snapshot(&self) -> PathBuf {
        self.dir.join("bluesniff.snapshot.json")
    }
}

pub fn paths() -> Paths {
    Paths::default()
}

/// Lo stato in `bluesniff.status`, letto dalla dashboard.
pub fn status_path() -> PathBuf {
    paths().status()
}

// ---------------------------------------------------------------------------
// Comandi
// ---------------------------------------------------------------------------

/// I comandi che il processo in ascolto accetta.
///
/// Gli alias sono quelli che l'utente può già digitare su stdin (`stop` per la
/// pausa, `start` per riprendere, `q` per uscire): scrivere `stop` nel file di
/// controllo per fermare la scansione e `q` per chiudere è la stessa cosa che
/// l'utente conosce, e confonderli sarebbe una trappola.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Sospende la scansione, il processo resta vivo e scrive ancora.
    Pause,
    /// Riprende la scansione dopo una pausa.
    Resume,
    /// Chiude il processo in modo pulito (i file vengono flushati).
    Stop,
    /// Scrive l'ultimo snapshot JSON su `bluesniff.snapshot.json`.
    Snapshot,
    /// Riscrive `bluesniff.status`.
    Status,
}

impl Control {
    /// Il nome canonico scritto nel file di controllo.
    pub fn as_str(&self) -> &'static str {
        match self {
            Control::Pause => "pause",
            Control::Resume => "resume",
            Control::Stop => "stop",
            Control::Snapshot => "snapshot",
            Control::Status => "status",
        }
    }

    /// Il path dell'endpoint HTTP che espone questo comando.
    pub fn http_route(&self) -> &'static str {
        match self {
            Control::Pause => "/api/scan/pause",
            Control::Resume => "/api/scan/resume",
            Control::Stop => "/api/scan/stop",
            Control::Snapshot => "/api/scan/snapshot",
            Control::Status => "/api/scan/status",
        }
    }

    /// Il messaggio di conferma all'utente, in italiano.
    pub fn done_message(&self) -> &'static str {
        match self {
            Control::Pause => "scanner in pausa",
            Control::Resume => "scanner ripreso",
            Control::Stop => "arresto richiesto",
            Control::Snapshot => "snapshot scritto",
            Control::Status => "stato aggiornato",
        }
    }

    /// Parsa il contenuto del file di controllo. Tollera spazi e maiuscole.
    pub fn parse(s: &str) -> Option<Control> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pause" | "stop-scan" | "stop_scan" => Some(Control::Pause),
            "resume" | "start" => Some(Control::Resume),
            "stop" | "quit" | "exit" | "q" => Some(Control::Stop),
            "snapshot" | "devices" | "s" => Some(Control::Snapshot),
            "status" => Some(Control::Status),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PID file
// ---------------------------------------------------------------------------

/// Il PID scritto nel file, insieme alla riga di contesto (i flag con cui il
/// processo è stato avviato). Il contesto serve a `--status`: «ascolto da 6
/// ore» dice molto meno di «ascolto da 6 ore con --dashboard --ntfy X».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidInfo {
    pub pid: u32,
    pub context: String,
}

/// Legge il PID file. `None` se assente, illeggibile o malformato.
pub fn read_pid_info_at(p: &Paths) -> Option<PidInfo> {
    let text = std::fs::read_to_string(p.pid()).ok()?;
    let mut lines = text.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    let context = lines.next().unwrap_or("").trim().to_string();
    Some(PidInfo { pid, context })
}

pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(windows)]
    {
        // `tasklist` è la via più semplice senza legare il progetto a Win32.
        // Non è veloce ( spawning di un processo), ma lo chiamiamo una volta
        // per comando, non nel loop.
        let filter = format!("PID eq {pid}");
        match std::process::Command::new("tasklist")
            .args(["/FI", &filter, "/NH"])
            .output()
        {
            Ok(o) => {
                let out = String::from_utf8_lossy(&o.stdout);
                // `tasklist` con un PID inesistente stampa "Nessun processo
                //..." o "INFO: No tasks are running"; in entrambi i casi il
                // numero non compare. Cerchiamo il numero come parola intera,
                // per non prendere un PID che sta dentro un altro numero.
                out.split_whitespace().any(|w| w == pid.to_string())
            }
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
}

/// Scrive il PID file del processo corrente.
///
/// Se c'è già un PID file con un processo **vivo**, non lo sovrascriviamo: due
/// bluesniff nella stessa cartella scriverebbero sugli stessi CSV e sui file
/// dell'altro, e l'utente non saprebbe quale dei due fermare. Se invece il
/// PID nel file è morto (un `taskkill /F` della sera prima), il file è un
/// orfano e lo prendiamo noi.
///
/// I file di comando e di conferma di esecuzioni precedenti vengono cancellati:
/// un `--stop` arrivato mentre il vecchio processo stava già chiudendo
/// rimarrebbe nel `.ctl` e fermerebbe quello appena avviato, un secondo dopo.
pub fn write_pid_at(p: &Paths, context: &str) -> std::io::Result<()> {
    if let Some(existing) = read_pid_info_at(p) {
        if occupa_la_cartella(existing.pid, std::process::id(), pid_alive(existing.pid)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "un altro bluesniff è già in esecuzione (PID {}): {}. \
                     Fermalo con `bluesniff --stop`, oppure cancella {} se sei sicuro che non sia vivo",
                    existing.pid,
                    if existing.context.is_empty() {
                        "modalità sconosciuta".to_string()
                    } else {
                        existing.context.clone()
                    },
                    p.pid().display()
                ),
            ));
        }
    }
    std::fs::write(p.pid(), format!("{}\n{}\n", std::process::id(), context))?;
    let _ = std::fs::remove_file(p.ctl());
    let _ = std::fs::remove_file(p.ack());
    let _ = std::fs::remove_file(p.status());
    let _ = std::fs::remove_file(p.snapshot());
    Ok(())
}

/// La domanda che decide se si puo' scrivere il PID file: un altro processo
/// vivo che scrive sugli stessi CSV e sui file di controllo e' un problema,
/// un PID morto e' solo un file da sostituire, e il nostro stesso PID non e'
/// un conflitto (rilancio della stessa istanza, o doppio avvio in un test).
///
/// La funzione e' separata perche' `pid_alive` chiama `tasklist` e su una
/// macchina di sviluppo non c'e' un secondo bluesniff da trovare: senza
/// questo passaggio la guardia sarebbe verificata solo per il caso "nessuno".
fn occupa_la_cartella(pid_trovato: u32, mio_pid: u32, vivo: bool) -> bool {
    pid_trovato != mio_pid && vivo
}

/// Rimuove i file di questo processo (PID, porta HTTP, snapshot). Chiamata alla
/// chiusura pulita. Il `.ctl` non lo tocchiamo: se qualcuno ci ha scritto `stop`
/// mentre chiudevamo, non serve a nessuno e il prossimo avvio lo cancella.
pub fn remove_files_at(p: &Paths) {
    let _ = std::fs::remove_file(p.pid());
    let _ = std::fs::remove_file(p.http());
    let _ = std::fs::remove_file(p.status());
    let _ = std::fs::remove_file(p.snapshot());
}

// ---------------------------------------------------------------------------
// File di controllo e conferma
// ---------------------------------------------------------------------------

/// Scrive un comando nel file di controllo. Un comando solo, non una coda:
/// due `--pause` di seguito sovrascrivono, e va bene (`pause` è idempotente).
/// Chi mandates una sequenza di comandi deve attendere l'ack di ciascuno.
pub fn send_command_at(p: &Paths, cmd: Control) -> std::io::Result<()> {
    std::fs::write(p.ctl(), format!("{}\n", cmd.as_str()))
}

pub fn send_command(cmd: Control) -> std::io::Result<()> {
    send_command_at(&paths(), cmd)
}

/// Legge il file di controllo e lo cancella, così un comando non viene
/// eseguito due volte. `None` se il file non c'è o il contenuto non è un
/// comando noto (in quel caso il file è comunque consumato: lasciarlo lì
/// farebbe bloccare ogni comando successivo).
pub fn take_command_at(p: &Paths) -> Option<Control> {
    let text = std::fs::read_to_string(p.ctl()).ok()?;
    let _ = std::fs::remove_file(p.ctl());
    match Control::parse(&text) {
        Some(c) => Some(c),
        None => {
            // Non sappiamo chi ci abbia scritto, ma sappiamo che non è un
            // comando: il file è rumore, e tenerlo fa perdere il comando
            // successivo. Lo mettiamo nel log di chi lo ha scritto.
            crate::bn!(
                "\x1b[33m[BLUESNIFF]\x1b[0m Controllo ignorato in {}: {:?} (comandi: pause, resume, stop, snapshot, status)",
                p.ctl().display(),
                text.trim()
            );
            None
        }
    }
}

/// Scrive la conferma di un comando. Sovrascrive la precedente: un solo
/// comando in volo è il modello che abbiamo scelto per il file di controllo.
pub fn write_ack_at(p: &Paths, ok: bool, message: &str) {
    let _ = std::fs::write(
        p.ack(),
        format!("{}\n{}\n", if ok { "ok" } else { "err" }, message),
    );
}

/// Legge e cancella la conferma, se presente.
pub fn take_ack_at(p: &Paths) -> Option<(bool, String)> {
    let text = std::fs::read_to_string(p.ack()).ok()?;
    let _ = std::fs::remove_file(p.ack());
    let mut lines = text.lines();
    let ok = lines.next()?.trim() == "ok";
    // Il resto puo' essere su piu' righe: `--status` risponde con lo stato
    // formattato, e troncarlo alla prima riga lascerebbe all'utente solo
    // "PID: ..." senza uptime ne' cicli.
    let msg = lines.collect::<Vec<_>>().join("\n");
    Some((ok, msg))
}

// ---------------------------------------------------------------------------
// Stato condiviso
// ---------------------------------------------------------------------------

/// Informazioni sul processo che il comando `status` e `--status` leggono.
///
/// Sono tutte cose che il loop di ascolto conosce già: qui le raccogliamo in
/// un posto solo, perché `--status` non deve dover ricostruire la verità da
/// file diversi (e sbagliare).
#[derive(Debug, Clone, Default)]
pub struct StatusInfo {
    /// I flag con cui il processo è stato avviato.
    pub mode: String,
    /// Numero di cicli di scansione completati.
    pub cycles: u64,
    /// Dispositivi unici visti dall'avvio.
    pub unique: usize,
    /// Stato della radio, come lo riporta il pannello Radio.
    pub radio: String,
    /// Quando è finito l'ultimo ciclo (uptime al momento della lettura).
    pub last_cycle_secs: Option<u64>,
    /// Numero di pacchetti BLE ricevuti.
    pub packets: u64,
    /// Utente loggato, quando noto.
    pub user: String,
}

/// Stato condiviso fra il loop di ascolto, il canale di controllo e (tramite
/// file) i flag CLI.
#[derive(Clone)]
pub struct ControlState {
    pub paused: Arc<AtomicBool>,
    pub shutdown: Arc<AtomicBool>,
    pub started: Instant,
    /// Ultimo snapshot NDJSON (canale `--json`), per il comando `snapshot`.
    pub latest_json: Arc<Mutex<Option<serde_json::Value>>>,
    pub info: Arc<Mutex<StatusInfo>>,
}

impl ControlState {
    pub fn new(mode: &str) -> Self {
        Self {
            paused: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            started: Instant::now(),
            latest_json: Arc::new(Mutex::new(None)),
            info: Arc::new(Mutex::new(StatusInfo {
                mode: mode.to_string(),
                ..StatusInfo::default()
            })),
        }
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Aggiorna un campo dello stato (usato dal loop a ogni ciclo).
    pub fn set_info(&self, f: impl FnOnce(&mut StatusInfo)) {
        if let Ok(mut i) = self.info.lock() {
            f(&mut i);
        }
    }

    /// Lo stato in forma di JSON: è quello che finisce in `bluesniff.status`
    /// e quello che `--status` sa stampare.
    pub fn status_value(&self, pid: u32, http_port: Option<u16>) -> serde_json::Value {
        let info = self.info.lock().map(|i| i.clone()).unwrap_or_default();
        serde_json::json!({
            "pid": pid,
            "mode": info.mode,
            "uptime_s": self.uptime_secs(),
            "scanner": if self.is_paused() { "in-pausa" } else { "attivo" },
            "paused": self.is_paused(),
            "cycles": info.cycles,
            "unique": info.unique,
            "packets": info.packets,
            "radio": info.radio,
            "last_cycle_secs": info.last_cycle_secs,
            "user": info.user,
            "http_port": http_port,
            "version": env!("CARGO_PKG_VERSION"),
        })
    }
}

/// Scrive `bluesniff.status` con lo stato corrente.
pub fn write_status_at(p: &Paths, state: &ControlState, http_port: Option<u16>) {
    let v = state.status_value(std::process::id(), http_port);
    let _ = std::fs::write(p.status(), format!("{v}\n"));
}

/// Il testo che `--status` mostra all'utente: leggibile, non un dump di JSON.
pub fn format_status(v: &serde_json::Value) -> String {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_string();
    let n = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    let mut out = Vec::new();
    out.push(format!("PID: {}", n("pid")));
    let mode = s("mode");
    if !mode.is_empty() && mode != "?" {
        out.push(format!("Modalità: {mode}"));
    }
    out.push(format!("Stato: in esecuzione, scanner {}", s("scanner")));
    out.push(format!("Uptime: {}", fmt_uptime_secs(n("uptime_s"))));
    let radio = s("radio");
    if radio != "?" && !radio.is_empty() {
        out.push(format!("Radio: {radio}"));
    }
    out.push(format!("Cicli: {}", n("cycles")));
    out.push(format!("Dispositivi unici: {}", n("unique")));
    match v.get("http_port").and_then(|x| x.as_u64()) {
        Some(p) => out.push(format!("Controllo HTTP: 127.0.0.1:{p}")),
        None => out.push("Controllo HTTP: non attivo".to_string()),
    }
    out.join("\n")
}

/// `2h 14m`, `45s`: leggibile come uptime, unlike `7940`.
pub fn fmt_uptime_secs(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

// ---------------------------------------------------------------------------
// Task di controllo (polling del file)
// ---------------------------------------------------------------------------

/// Avvia il task che guarda `bluesniff.ctl` e lo riscrive ogni `STATUS_EVERY`
/// secondi.
///
/// Il polling gira in un task separato e non blocca mai il loop di scansione:
/// il ciclo dura dieci secondi e non deve risentirne la cadenza. Un `sleep`
/// di un secondo tra due letture è il prezzo del canale file, e va bene
/// perché l'effetto di una pausa si vede comunque al ciclo successivo.
pub fn spawn_ctl_watcher(state: ControlState, logger: Logger, http_port: Arc<Mutex<Option<u16>>>) {
    let p = paths();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut status_tick = tokio::time::interval(Duration::from_secs(STATUS_EVERY_SECS));
        status_tick.tick().await; // il primo tick è immediato: non lo vogliamo
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if state.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Some(cmd) = take_command_at(&p) {
                        logger.log(&format!(
                            "control: comando '{cmd:?}' da {}, applicato",
                            p.ctl().display()
                        ));
                        apply_command(&state, &p, cmd, &http_port);
                    }
                }
                _ = status_tick.tick() => {
                    let port = http_port.lock().ok().and_then(|g| *g);
                    write_status_at(&p, &state, port);
                }
            }
        }
    });
}

/// Ogni quanti secondi `bluesniff.status` viene riscritto. Cinque secondi è la
/// stessa cadenza con cui la dashboard si aggiorna: più fitto non serve, e il
/// file è scritto in modo atomico per `--status` che lo legge.
pub const STATUS_EVERY_SECS: u64 = 5;

/// Applica un comando al processo, e lascia la conferma per chi l'ha chiesto.
fn apply_command(
    state: &ControlState,
    p: &Paths,
    cmd: Control,
    http_port: &Arc<Mutex<Option<u16>>>,
) {
    let port = http_port.lock().ok().and_then(|g| *g);
    match cmd {
        Control::Pause => {
            state.paused.store(true, Ordering::Relaxed);
            write_status_at(p, state, port);
            write_ack_at(p, true, "scanner in pausa");
        }
        Control::Resume => {
            state.paused.store(false, Ordering::Relaxed);
            write_status_at(p, state, port);
            write_ack_at(p, true, "scanner ripreso");
        }
        Control::Stop => {
            // L'arresto è un semplice flag: il loop lo vede al ciclo
            // successivo, chiude il writer di presenze.csv e rimuove i file.
            // Non lo forziamo qui, o un `stop` arrivato mentre la radio è
            // dentro una finestra di 8 secondi lascerebbe a metà la riga.
            state.shutdown.store(true, Ordering::Relaxed);
            write_ack_at(p, true, "arresto richiesto");
        }
        Control::Snapshot => {
            let snapshot = state.latest_json.lock().ok().and_then(|g| g.clone());
            match snapshot {
                Some(v) => {
                    let _ = std::fs::write(p.snapshot(), v.to_string());
                    write_ack_at(
                        p,
                        true,
                        &format!("snapshot scritto in {}", p.snapshot().display()),
                    );
                }
                None => write_ack_at(
                    p,
                    false,
                    "nessuno snapshot disponibile: serve --listen --json",
                ),
            }
        }
        Control::Status => {
            write_status_at(p, state, port);
            let v = state.status_value(std::process::id(), port);
            // Su piu' righe: l'ack e' un file di testo e l'utente lo puo'
            // leggere con `type`, quindi una riga sola con dei separatori
            // sarebbe un formato proprietario senza vantaggio.
            write_ack_at(p, true, &format_status(&v));
        }
    }
}

// ---------------------------------------------------------------------------
// Server HTTP di controllo
// ---------------------------------------------------------------------------

/// Fa in modo che ci sia un modo veloce di impartire i comandi, e scrive la
/// porta in `bluesniff.http`.
///
/// Un solo server HTTP per processo: se la dashboard è attiva la sua porta
/// viene riusata (i suoi endpoint `/api/scan/pause` e `/resume` esistono già,
/// e `/stop`, `/status`, `/snapshot` sono aggiunti a `dashboard.rs`), altrimenti
/// qui parte un server minimale su porta effimera, **solo su 127.0.0.1**: un
/// canale di controllo non deve essere raggiungibile dalla rete locale, dove
/// chiunque potrebbe fermare la scansione di qualcun altro.
pub async fn ensure_http_control(
    dashboard_port: Option<u16>,
    state: ControlState,
    logger: &Logger,
) -> Option<u16> {
    let p = paths();
    if let Some(port) = dashboard_port {
        // La dashboard espone già questi comandi: basta ricordare la porta.
        let _ = std::fs::write(p.http(), format!("{port}\n"));
        logger.log(&format!("control: canale HTTP = dashboard su porta {port}"));
        return Some(port);
    }
    let std_listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            logger.log(&format!(
                "control: server HTTP non disponibile ({e}), uso il file .ctl"
            ));
            crate::bn!(
                "\x1b[33m[BLUESNIFF]\x1b[0m Controllo HTTP non disponibile ({e}): i comandi passano dal file bluesniff.ctl (fino a 1s di ritardo)."
            );
            return None;
        }
    };
    let port = match std_listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            logger.log(&format!(
                "control: porta non leggibile ({e}), uso il file .ctl"
            ));
            return None;
        }
    };
    if std_listener.set_nonblocking(true).is_err() {
        return None;
    }
    let listener = match tokio::net::TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            logger.log(&format!("control: listener non utilizzabile ({e})"));
            return None;
        }
    };
    let _ = std::fs::write(p.http(), format!("{port}\n"));
    logger.log(&format!("control: server HTTP su 127.0.0.1:{port}"));
    let app = control_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Some(port)
}

/// Le cinque rotte di controllo. Stessi path della dashboard, così lo stesso
/// client (i flag CLI) funziona con e senza `--dashboard`.
fn control_router(state: ControlState) -> axum::Router {
    use axum::routing::post;
    let pause_state = state.clone();
    let resume_state = state.clone();
    let stop_state = state.clone();
    let status_state = state.clone();
    let snap_state = state.clone();
    axum::Router::new()
        .route(
            "/api/scan/pause",
            post(move || {
                let s = pause_state.clone();
                async move {
                    s.paused.store(true, Ordering::Relaxed);
                    axum::Json(serde_json::json!({ "ok": true, "paused": true }))
                }
            }),
        )
        .route(
            "/api/scan/resume",
            post(move || {
                let s = resume_state.clone();
                async move {
                    s.paused.store(false, Ordering::Relaxed);
                    axum::Json(serde_json::json!({ "ok": true, "paused": false }))
                }
            }),
        )
        .route(
            "/api/scan/stop",
            post(move || {
                let s = stop_state.clone();
                async move {
                    s.shutdown.store(true, Ordering::Relaxed);
                    axum::Json(serde_json::json!({ "ok": true, "message": "arresto richiesto" }))
                }
            }),
        )
        .route(
            "/api/scan/status",
            post(move || {
                let s = status_state.clone();
                async move {
                    let v = s.status_value(std::process::id(), None);
                    axum::Json(v)
                }
            }),
        )
        .route(
            "/api/scan/snapshot",
            post(move || {
                let s = snap_state.clone();
                async move {
                    let snap = s.latest_json.lock().ok().and_then(|g| g.clone());
                    match snap {
                        Some(v) => axum::Json(v),
                        None => axum::Json(serde_json::json!({
                            "ok": false,
                            "error": "nessuno snapshot disponibile: serve --listen --json"
                        })),
                    }
                }
            }),
        )
}

// ---------------------------------------------------------------------------
// Lato client: i flag --pause / --resume / --stop / --status / --snapshot
// ---------------------------------------------------------------------------

/// Esito di un comando di controllo, per il testo che l'utente vede.
pub struct ControlOutcome {
    pub pid: Option<u32>,
    /// Messaggio da stampare. `None` = tutto bene, il testo è già pronto.
    pub message: String,
    /// `false` quando non c'è nessun processo o non ha risposto: in questo
    /// caso main esce con codice 1.
    pub ok: bool,
}

/// Cerca un processo bluesniff long-running.
///
/// Se il file c'è ma il PID è morto, lo rimuove: è un orfano di un
/// `taskkill /F`, e tenerlo farebbe fallire ogni avvio successivo con un
/// errore che sembrerebbe "un altro bluesniff è già in esecuzione".
fn find_process(p: &Paths) -> Result<u32, ControlOutcome> {
    match read_pid_info_at(p) {
        None => Err(ControlOutcome {
            pid: None,
            message: format!(
                "Nessun bluesniff in esecuzione ({} non trovato).",
                p.pid().display()
            ),
            ok: false,
        }),
        Some(info) if !pid_alive(info.pid) => {
            let _ = std::fs::remove_file(p.pid());
            let _ = std::fs::remove_file(p.http());
            let _ = std::fs::remove_file(p.status());
            Err(ControlOutcome {
                pid: None,
                message: format!(
                    "Trovato un PID file orfano (PID {}, processo non più vivo): rimosso. Avvia bluesniff e riprova.",
                    info.pid
                ),
                ok: false,
            })
        }
        Some(info) => Ok(info.pid),
    }
}

/// Invia un comando al processo in escolto.
///
/// Ordine di preferenza:
/// 1. HTTP su 127.0.0.1, se `bluesniff.http` c'è e risponde — immediato.
/// 2. File `.ctl` + attesa dell'ack fino a 3 secondi — universale.
///
/// Il fallback non è un caso raro: la porta può essere occupata da un altro
/// programma, o il firewall può bloccarla, e in quel caso l'utente deve
/// poter fermare il processo lo stesso.
pub async fn send_to_running(cmd: Control, logger: &Logger, wait: Duration) -> ControlOutcome {
    let p = paths();
    let pid = match find_process(&p) {
        Ok(pid) => pid,
        Err(out) => return out,
    };

    if let Some(port) = read_http_port(&p) {
        let url = format!("http://127.0.0.1:{port}{}", cmd.http_route());
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                logger.log(&format!("control: client HTTP non creato: {e}"));
                return via_ctl(&p, cmd, logger, wait);
            }
        };
        match client.post(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                logger.log(&format!("control: {url} -> {status}"));
                // La dashboard risponde con il JSON del comando; se c'è un
                // campo `message` lo preferiamo, altrimenti la conferma
                // canonica del comando.
                let msg = serde_json::from_str::<serde_json::Value>(body.trim())
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| cmd.done_message().to_string());
                let out = ControlOutcome {
                    pid: Some(pid),
                    message: msg,
                    ok: true,
                };
                // Anche via HTTP `stop` non vuol dire "fermo": vuol dire che la
                // richiesta e' arrivata. Il ciclo di scansione puo' aspettare
                // ancora qualche secondo prima di chiudere.
                return if cmd == Control::Stop {
                    wait_for_exit(&p, out)
                } else {
                    out
                };
            }
            other => {
                logger.log(&format!(
                    "control: {url} non ha risposto ({:?}), passo al file .ctl",
                    other.map(|r| r.status())
                ));
            }
        }
    }
    let out = via_ctl(&p, cmd, logger, wait);
    if cmd == Control::Stop && out.ok {
        return wait_for_exit(&p, out);
    }
    out
}

/// Dopo un `stop` aspetta che il PID file sparisca, e dice la differenza.
///
/// "Arresto richiesto" e "fermato" non sono la stessa cosa, e a uno script che
/// deve rilasciare una porta o spegnere un PC serve la seconda. Il loop chiude
/// entro un ciclo di dieci secondi, quindi qui si aspetta un po' di piu' e poi
/// si dice quello che si sa davvero: la richiesta e' arrivata, la chiusura
/// non e' ancora confermata.
fn wait_for_exit(p: &Paths, out: ControlOutcome) -> ControlOutcome {
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        if !p.pid().exists() {
            return ControlOutcome {
                pid: out.pid,
                message: "bluesniff fermato: i file sono stati salvati".to_string(),
                ok: true,
            };
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    ControlOutcome {
        pid: out.pid,
        message: "arresto richiesto, ma il processo non ha ancora chiuso.                   Se entro qualche secondo lo trovi ancora vivo, apri bluesniff.log:                   si ferma al massimo al ciclo di scansione successivo."
            .to_string(),
        ok: true,
    }
}

/// Percorso via file: scrive il comando e aspetta la conferma.
fn via_ctl(p: &Paths, cmd: Control, logger: &Logger, wait: Duration) -> ControlOutcome {
    if let Err(e) = send_command_at(p, cmd) {
        return ControlOutcome {
            pid: None,
            message: format!("Impossibile scrivere il comando: {e}"),
            ok: false,
        };
    }
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if let Some((ok, msg)) = take_ack_at(p) {
            logger.log(&format!("control: .ctl {cmd:?} -> {ok} ({msg})"));
            return ControlOutcome {
                pid: None,
                message: if msg.is_empty() {
                    cmd.done_message().to_string()
                } else {
                    msg
                },
                ok,
            };
        }
    }
    ControlOutcome {
        pid: None,
        message: format!(
            "Nessuna conferma entro {} secondi. Il processo è vivo ma non risponde al controllo: \
             controlla se è partito prima di questo comando, o se un antivirus ha bloccato la cartella.",
            wait.as_secs()
        ),
        ok: false,
    }
}

/// Legge la porta del server di controllo da `bluesniff.http`.
pub fn read_http_port(p: &Paths) -> Option<u16> {
    std::fs::read_to_string(p.http()).ok()?.trim().parse().ok()
}

/// Stato del processo in escolto, per il flag `--status`.
///
/// Non scrive nulla: `--status` è una domanda, e una domanda che modifica il
/// sistema è una domanda a cui non si sa rispondere. Se il file non c'è ma il
/// processo è vivo (per esempio lanciato senza la dashboard in una versione
/// precedente, o il file non ancora scritto) si dice anche questo, invece di
/// far fede che il processo non esista.
pub fn query_status(logger: &Logger) -> ControlOutcome {
    let p = paths();
    let info = match find_process(&p) {
        Ok(pid) => read_pid_info_at(&p).map(|i| (pid, i.context)),
        Err(out) => return out,
    };
    let (pid, context) = match info {
        Some(v) => v,
        None => {
            return ControlOutcome {
                pid: None,
                message: "Nessun bluesniff in esecuzione.".to_string(),
                ok: false,
            }
        }
    };
    // Lo stato completo vive nel processo: si chiede con un comando `status`
    // e si legge la conferma, che è già formattata per l'utente.
    if let Err(e) = send_command_at(&p, Control::Status) {
        logger.log(&format!("control: status non scrivibile: {e}"));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut body = String::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if let Some((ok, msg)) = take_ack_at(&p) {
            if ok && !msg.is_empty() {
                body = msg;
                break;
            }
        }
    }
    let head = format!("PID: {pid}").to_string()
        + &if context.is_empty() {
            String::new()
        } else {
            format!("\nModalità: {context}")
        };
    if body.is_empty() {
        // Il processo non ha risposto ma è vivo: si dice anche questo, e non
        // si inventa uno stato.
        ControlOutcome {
            pid: Some(pid),
            message: format!("{head}\nStato: in esecuzione, non risponde al canale di controllo"),
            ok: true,
        }
    } else {
        // Il corpo riporta gia' PID e modalita' (li ha messi il processo, che
        // li sa): prependere l'header qui li stamperebbe due volte, e chi
        // legge "PID: 9608" due di fila pensa che ci siano due processi.
        ControlOutcome {
            pid: Some(pid),
            message: body,
            ok: true,
        }
    }
}

/// Ultimo snapshot JSON, per il flag `--snapshot`.
pub async fn fetch_snapshot(logger: &Logger) -> ControlOutcome {
    let p = paths();
    let pid = match find_process(&p) {
        Ok(pid) => pid,
        Err(out) => return out,
    };
    // Prima prova l'HTTP: lì lo snapshot è il body della risposta.
    if let Some(port) = read_http_port(&p) {
        let url = format!("http://127.0.0.1:{port}/api/scan/snapshot");
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(_) => reqwest::Client::new(),
        };
        if let Ok(resp) = client.post(&url).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body.trim()) {
                    if v.get("ok").and_then(|o| o.as_bool()) == Some(false) {
                        return ControlOutcome {
                            pid: Some(pid),
                            message: v
                                .get("error")
                                .and_then(|e| e.as_str())
                                .unwrap_or("nessuno snapshot disponibile")
                                .to_string(),
                            ok: false,
                        };
                    }
                    return ControlOutcome {
                        pid: Some(pid),
                        message: v.to_string(),
                        ok: true,
                    };
                }
            }
        }
    }
    // Via file: il processo scrive lo snapshot su disco e conferma.
    if let Err(e) = send_command_at(&p, Control::Snapshot) {
        logger.log(&format!("control: snapshot non scrivibile: {e}"));
        return ControlOutcome {
            pid: None,
            message: format!("Impossibile chiedere lo snapshot: {e}"),
            ok: false,
        };
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if let Some((ok, msg)) = take_ack_at(&p) {
            if !ok {
                return ControlOutcome {
                    pid: Some(pid),
                    message: msg,
                    ok: false,
                };
            }
            match std::fs::read_to_string(p.snapshot()) {
                Ok(text) => {
                    return ControlOutcome {
                        pid: Some(pid),
                        message: text.trim().to_string(),
                        ok: true,
                    }
                }
                Err(e) => {
                    return ControlOutcome {
                        pid: Some(pid),
                        message: format!("Snapshot dichiarato ma non leggibile: {e}"),
                        ok: false,
                    }
                }
            }
        }
    }
    ControlOutcome {
        pid: Some(pid),
        message: "Nessuno snapshot entro 5 secondi.".to_string(),
        ok: false,
    }
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
