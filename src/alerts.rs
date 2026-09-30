//! Push notifications for watched devices via ntfy.sh (idea ported from
//! bluehood's notification feature).
//!
//! Watched devices = the known phones from `bt_known.txt` (their presence is
//! already probed every 60 s in `--listen`). State changes trigger a POST to
//! `https://ntfy.sh/<topic>`; the topic (and optional server override) lives
//! in `ntfy.txt` next to the exe: line 1 = topic, optional line 2 =
//! `server=https://ntfy.example.com`.
//!
//! When the dashboard is running, an `Arc<RwLock<NtfySettings>>` is shared
//! with the tracker: the web UI can change topic/server and enable/disable
//! arrival/departure alerts at runtime; the tracker reads them at every probe
//! round.

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::btclassic::{KnownBt, ProbeResult};
use crate::logging::Logger;

/// Configuration loaded from `ntfy.txt` (or disabled when absent/empty).
#[derive(Debug, Clone)]
pub struct NtfyConfig {
    pub topic: String,
    pub server: String,
}

impl NtfyConfig {
    /// Load from `ntfy.txt` next to the exe. Returns `None` when the file is
    /// missing or has no usable topic, meaning notifications are disabled.
    pub fn load_default() -> Option<NtfyConfig> {
        Self::load(&crate::logging::exe_dir().join("ntfy.txt"))
    }

    pub fn load(path: &Path) -> Option<NtfyConfig> {
        let content = std::fs::read_to_string(path).ok()?;
        let mut topic = String::new();
        let mut server = "https://ntfy.sh".to_string();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(v) = line.strip_prefix("server=") {
                let v = v.trim();
                if !v.is_empty() {
                    server = v.to_string();
                }
            } else if topic.is_empty() {
                topic = line.to_string();
            }
        }
        if topic.is_empty() {
            return None;
        }
        Some(NtfyConfig { topic, server })
    }
}

/// Runtime notification settings shared between the dashboard and the alert
/// tracker. Persisted to `ntfy.txt` (topic/server, same format the CLI
/// reads) and `ntfy_settings.txt` (toggles) next to the exe.
#[derive(Debug, Clone)]
pub struct NtfySettings {
    pub enabled: bool,
    pub topic: String,
    pub server: String,
    pub notify_arrival: bool,
    pub notify_departure: bool,
}

impl Default for NtfySettings {
    fn default() -> Self {
        NtfySettings {
            enabled: false,
            topic: String::new(),
            server: "https://ntfy.sh".to_string(),
            notify_arrival: true,
            notify_departure: true,
        }
    }
}

impl NtfySettings {
    /// Load from `ntfy.txt` + `ntfy_settings.txt` next to the exe.
    pub fn load_default() -> NtfySettings {
        let exe = crate::logging::exe_dir();
        Self::load(&exe.join("ntfy.txt"), &exe.join("ntfy_settings.txt"))
    }

    pub fn load(ntfy_path: &Path, settings_path: &Path) -> NtfySettings {
        let mut s = NtfySettings::default();
        if let Some(cfg) = NtfyConfig::load(ntfy_path) {
            s.topic = cfg.topic;
            s.server = cfg.server;
            s.enabled = true;
        }
        if let Ok(content) = std::fs::read_to_string(settings_path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(v) = line.strip_prefix("enabled=") {
                    s.enabled = v == "1" || v.eq_ignore_ascii_case("true");
                } else if let Some(v) = line.strip_prefix("arrival=") {
                    s.notify_arrival = v == "1" || v.eq_ignore_ascii_case("true");
                } else if let Some(v) = line.strip_prefix("departure=") {
                    s.notify_departure = v == "1" || v.eq_ignore_ascii_case("true");
                }
            }
        }
        if s.topic.trim().is_empty() {
            s.enabled = false;
        }
        s
    }

    /// Persist to `ntfy.txt` + `ntfy_settings.txt` next to the exe so the
    /// settings survive restarts (and the CLI-only path picks them up too).
    pub fn save(&self) {
        let exe = crate::logging::exe_dir();
        let _ = std::fs::write(
            exe.join("ntfy.txt"),
            format!("{}\nserver={}\n", self.topic, self.server),
        );
        let _ = std::fs::write(
            exe.join("ntfy_settings.txt"),
            format!(
                "enabled={}\narrival={}\ndeparture={}\n",
                self.enabled as u8, self.notify_arrival as u8, self.notify_departure as u8
            ),
        );
    }
}

/// Valida un topic ntfy secondo le regole ufficiali.
///
/// Un topic valido e' lungo da 1 a 64 caratteri e contiene solo lettere,
/// numeri, `_` e `-`. Niente spazi, niente slash, niente punti. ntfy
/// distingue `Topic` da `topic`: sono due canali diversi.
///
/// La funzione esiste perche' il modo tipico in cui la configurazione fallisce
/// non e' un errore di rete ma un topic scritto male (con uno spazio, per
/// esempio): in quel caso ntfy risponde 400 a ogni notifica e l'utente vede
/// semplicemente che "non arrive niente".
pub fn validate_topic(topic: &str) -> Result<(), String> {
    let t = topic.trim();
    if t.is_empty() {
        return Err("Topic vuoto".to_string());
    }
    if t.chars().count() > 64 {
        return Err(format!(
            "Topic non valido: troppo lungo ({} caratteri, massimo 64)",
            t.chars().count()
        ));
    }
    for (i, c) in t.chars().enumerate() {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
            return Err(format!(
                "Topic non valido: carattere '{}' alla posizione {}. Usa solo lettere, numeri, _ e -",
                c,
                i + 1
            ));
        }
    }
    Ok(())
}

/// Valida l'URL del server ntfy.
///
/// Accetta solo `http://` e `https://`, e rifiuta la barra finale: ntfy la
/// tratta come parte del topic e risponde 404, quindi accettarla qui
/// significherebbe un canale che non funziona ma sembra configurato.
pub fn validate_server(server: &str) -> Result<(), String> {
    let s = server.trim();
    if s.is_empty() {
        return Err("Server vuoto".to_string());
    }
    if !s.starts_with("http://") && !s.starts_with("https://") {
        return Err("Il server deve iniziare con http:// o https://".to_string());
    }
    if s.ends_with('/') {
        return Err("Il server non deve finire con /".to_string());
    }
    let rest = s
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if rest.is_empty() || rest.contains(char::is_whitespace) {
        return Err("URL del server non valido".to_string());
    }
    Ok(())
}

/// Tracks the present/absent state of every watched device and fires a push
/// notification on transitions. A device must be absent for
/// `absence_threshold_cycles` probes before "left" fires, so a single failed
/// probe does not spam (bluehood's configurable departure threshold).
pub struct AlertTracker {
    config: Option<NtfyConfig>,
    /// Runtime settings shared with the dashboard (optional: without a
    /// dashboard the static `config` is used).
    settings: Option<Arc<RwLock<NtfySettings>>>,
    /// Coda verso il thread che fa le POST: l'`update` sul runtime condiviso
    /// non deve mai toccare reqwest (vedi `AlertTracker::new`).
    tx: std::sync::mpsc::SyncSender<NtfyPost>,
    /// MAC -> was present at the previous probe.
    state: std::collections::HashMap<String, bool>,
    /// MAC -> consecutive absent probes seen so far.
    absent_streak: std::collections::HashMap<String, usize>,
    absence_threshold: usize,
}

/// Una notifica da consegnare. Passata per valore al thread dedicato: niente
/// `&NtfyConfig` che vivrebbe oltre la sua portata.
#[derive(Clone)]
struct NtfyPost {
    url: String,
    title: String,
    msg: String,
}

impl AlertTracker {
    pub fn new(
        config: Option<NtfyConfig>,
        absence_threshold: usize,
        logger: Logger,
    ) -> AlertTracker {
        // IMPORTANT (this VM): le POST ntfy NON girano sul runtime tokio
        // condiviso. Lo stesso ragionamento di `stream::spawn_pusher` e
        // `ops::spawn_heartbeat`: reqwest sul runtime principale bloccava il
        // loop di ascolto e il processo finiva in STATUS_HEAP_CORRUPTION
        // (0xC0000374) con il watcher WinRT attivo.
        //
        // Qui la soluzione e' un thread dedicato con coda: `update` resta
        // sincrono dal punto di vista del chiamante e non blocca mai il loop
        // su una rete lenta. La coda e' limitata: se ntfy e' irraggiungibile
        // le notifiche in eccesso vengono scartate, non accumulate per sempre.
        let (tx, rx) = std::sync::mpsc::sync_channel::<NtfyPost>(64);
        // Il thread parte **sempre**, anche senza `--ntfy` al lancio: la
        // dashboard puo' attivare le notifiche in un secondo momento, e un
        // thread avviato solo quando c'e' una config iniziale renderebbe
        // silenziosamente inapplicabile proprio l'uso da web UI.
        {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            // Il `Logger` e' clonabile e condiviso: il thread dedicato scrive
            // nello stesso file del main, quindi gli esiti delle POST restano
            // tracciati accanto al resto.
            let log = logger.clone();
            let _ = std::thread::Builder::new()
                .name("bt-ntfy".to_string())
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        // Senza runtime non possiamo spedire niente: esciamo
                        // subito, invece di lasciare una coda che cresce in
                        // silenzio e sembra funzionante.
                        Err(_) => return,
                    };
                    rt.block_on(async move {
                        while let Ok(post) = rx.recv() {
                            // Un errore non uccide il thread: la notifica
                            // successiva riprova.
                            post.send(&client, &log).await;
                        }
                    });
                });
        }
        AlertTracker {
            config,
            settings: None,
            tx,
            state: std::collections::HashMap::new(),
            absent_streak: std::collections::HashMap::new(),
            absence_threshold: absence_threshold.max(1),
        }
    }

    /// Attach the runtime settings shared with the dashboard: from now on the
    /// web UI controls topic/server and which alerts fire.
    pub fn set_runtime_settings(&mut self, settings: Arc<RwLock<NtfySettings>>) {
        self.settings = Some(settings);
    }

    /// Effective config for this round: runtime settings win over the static
    /// config; disabled/empty topic means no notifications.
    fn effective_config(&self) -> Option<NtfyConfig> {
        if let Some(s) = &self.settings {
            let s = s.read().ok()?;
            if !s.enabled || s.topic.trim().is_empty() {
                return None;
            }
            return Some(NtfyConfig {
                topic: s.topic.clone(),
                server: s.server.clone(),
            });
        }
        self.config.clone()
    }

    fn effective_toggles(&self) -> (bool, bool) {
        if let Some(s) = &self.settings {
            if let Ok(s) = s.read() {
                return (s.notify_arrival, s.notify_departure);
            }
        }
        (true, true)
    }

    /// Whether notifications are configured **right now**: the dashboard can
    /// enable or disable them at runtime, so this reads the live settings and
    /// falls back to the static config.
    pub fn enabled(&self) -> bool {
        if let Some(s) = &self.settings {
            if let Ok(s) = s.read() {
                return s.enabled && !s.topic.trim().is_empty();
            }
        }
        self.config.is_some()
    }

    /// Feed one probe round; queues notifications for transitions.
    ///
    /// Non e' piu' `async`: non tocca la rete. Si limita ad accodare le
    /// notifiche, cosi' il loop di ascolto non puo' essere rallentato da una
    /// rete lenta ne' dal TLS.
    pub fn update(&mut self, logger: &Logger, results: &[ProbeResult], known: &[KnownBt]) {
        if !self.enabled() {
            return;
        }
        let Some(cfg) = self.effective_config() else {
            return;
        };
        let (notify_arrival, notify_departure) = self.effective_toggles();
        for r in results {
            let name = known
                .iter()
                .find(|k| k.mac == r.mac)
                .map(|k| k.nome.clone())
                .unwrap_or_else(|| r.mac.clone());
            let prev = self.state.insert(r.mac.clone(), r.present);
            if prev == Some(r.present) {
                self.absent_streak.insert(r.mac.clone(), 0);
                continue;
            }
            if r.present {
                self.absent_streak.insert(r.mac.clone(), 0);
                if notify_arrival {
                    let msg = format!("{name} arrived ({})", r.mac);
                    self.enqueue(logger, &cfg, &msg);
                }
            } else {
                // Only notify "left" after N consecutive absent probes.
                let streak = self.absent_streak.entry(r.mac.clone()).or_insert(0);
                *streak += 1;
                let fire = *streak >= self.absence_threshold;
                if fire {
                    *streak = 0;
                }
                if fire && notify_departure {
                    let msg = format!("{name} left ({})", r.mac);
                    self.enqueue(logger, &cfg, &msg);
                }
            }
        }
    }

    /// Accoda una notifica. Non blocca: se il thread di invio e' indietro, la
    /// coda (limitata) scarta il surplus e lo dice nel log, invece di
    /// accumulare memoria o fermare il loop di ascolto.
    fn enqueue(&self, logger: &Logger, cfg: &NtfyConfig, msg: &str) {
        let post = NtfyPost {
            url: format!("{}/{}", cfg.server.trim_end_matches('/'), cfg.topic),
            title: "bluesniff".to_string(),
            msg: msg.to_string(),
        };
        match self.tx.try_send(post) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                logger.log(&format!(
                    "ntfy: coda piena, notifica scartata \"{msg}\" (ntfy raggiungibile?)"
                ));
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                logger.log(&format!(
                    "ntfy: thread di invio non attivo, \"{msg}\" perso"
                ));
            }
        }
    }
}

impl NtfyPost {
    /// Gira solo nel thread dedicato, quindi qui l'async e' innocuo: non
    /// tocca mai il runtime condiviso con il watcher WinRT.
    async fn send(&self, client: &reqwest::Client, logger: &Logger) {
        match client
            .post(&self.url)
            .header("Title", &self.title)
            .header("Tags", "bluetooth")
            .body(self.msg.clone())
            .send()
            .await
        {
            Ok(resp) => {
                logger.log(&format!(
                    "ntfy: sent \"{}\" -> {} ({})",
                    self.msg,
                    self.url,
                    resp.status()
                ));
            }
            Err(e) => {
                logger.log(&format!("ntfy: failed \"{}\": {e}", self.msg));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parse() {
        let dir = std::env::temp_dir().join(format!("bluesniff-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ntfy.txt");
        std::fs::write(&path, "my-topic\nserver=https://ntfy.example.com\n").unwrap();
        let cfg = NtfyConfig::load(&path).unwrap();
        assert_eq!(cfg.topic, "my-topic");
        assert_eq!(cfg.server, "https://ntfy.example.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_missing_is_disabled() {
        assert!(NtfyConfig::load(Path::new("Z:/definitely/not/here/ntfy.txt")).is_none());
    }

    #[test]
    fn topic_valido_accettato() {
        assert!(validate_topic("mario-rossi-ufficio").is_ok());
        assert!(validate_topic("abc123").is_ok());
        assert!(validate_topic("___").is_ok());
        assert!(validate_topic("A-B_C").is_ok());
        assert!(validate_topic(&"a".repeat(64)).is_ok());
        // ntfy distingue le maiuscole: non possiamo controllare che Topic e
        // topic non siano lo stesso canale, ma entrambi sono nomi validi.
        assert!(validate_topic("Topic").is_ok());
        assert!(validate_topic("topic").is_ok());
    }

    #[test]
    fn topic_invalido_rifiutato() {
        assert!(validate_topic("").is_err());
        assert!(validate_topic("   ").is_err());
        assert!(validate_topic("con spazi").is_err());
        assert!(validate_topic("con/slash").is_err());
        assert!(validate_topic("con.punti").is_err());
        assert!(validate_topic(&"a".repeat(65)).is_err());
        assert!(validate_topic("emoji\u{1F680}").is_err());
    }

    #[test]
    fn topic_vuoto_il_motivo_e_quello_giusto() {
        // La UI distingue i casi per colorare il campo giusto: il messaggio
        // per un topic vuoto deve dirlo.
        assert_eq!(validate_topic("").unwrap_err(), "Topic vuoto");
    }

    #[test]
    fn server_valido_accettato() {
        assert!(validate_server("https://ntfy.sh").is_ok());
        assert!(validate_server("http://ntfy.example.com").is_ok());
        assert!(validate_server("http://192.168.1.10:8080").is_ok());
        assert!(validate_server("https://ntfy.example.com:443").is_ok());
    }

    #[test]
    fn server_invalido_rifiutato() {
        assert!(validate_server("").is_err());
        assert!(validate_server("ntfy.sh").is_err());
        // La barra finale finisce nel topic lato ntfy: 404 garantito.
        assert!(validate_server("https://ntfy.sh/").is_err());
        assert!(validate_server("https://ntfy .sh").is_err());
        assert!(validate_server("https://").is_err());
    }

    #[test]
    fn runtime_settings_load_and_disable() {
        let dir = std::env::temp_dir().join(format!("bluesniff-ntfy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ntfy_path = dir.join("ntfy.txt");
        let settings_path = dir.join("ntfy_settings.txt");
        std::fs::write(&ntfy_path, "my-topic\nserver=https://ntfy.example.com\n").unwrap();
        std::fs::write(&settings_path, "enabled=0\narrival=0\ndeparture=1\n").unwrap();
        let s = NtfySettings::load(&ntfy_path, &settings_path);
        assert_eq!(s.topic, "my-topic");
        assert!(!s.enabled);
        assert!(!s.notify_arrival);
        assert!(s.notify_departure);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
