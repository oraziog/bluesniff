//! `--doctor`: la diagnosi che l'utente deve poter fare da solo.
//!
//! Il punto di questo modulo e' **la separazione**: `run_checks` raccoglie i
//! fatti, `format_report` li stampa. Non e' un dettaglio estetico: e' l'unico
//! modo per testare il report senza avviare il processo e toccare l'hardware.
//!
//! ## Cosa il doctor fa, e cosa non fa mai
//!
//! I check sono di tre nature, e la differenza e' tutta nel `fix`:
//!
//! - **Fail con `fix` sicuro**: il `--fix` lo applica da solo (creare un file
//!   che manca, cancellare un `.tmp` orfano). Idempotente per costruzione: se
//!   la condizione non si verifica, il fix non fa niente.
//! - **Warn/Fail con `fix` rischioso**: mai applicato in automatico. Il reset
//!   radio stacca le cuffie collegate: e' una decisione dell'utente, quindi il
//!   doctor si limita a stampare il comando. `--fix-risky` esiste ma non e'
//!   implementato: e' il posto dove metterlo se un giorno serve.
//! - **Fail senza fix**: richiede admin o una decisione umana (firewall,
//!   passthrough USB). Il doctor stampa il comando e non lo esegue. Aprire
//!   una porta del firewall non e' un fix, e' una modifica di sicurezza.
//!
//! Nessun check tocca `presenze.csv`, `raw_log.*` o i file di configurazione
//! dell'utente: sono dati, non guasti.

use std::path::{Path, PathBuf};

use crate::logging::Logger;

/// Esito di un singolo check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    /// Glifo: il check e' la parte che l'utente legge per primo, quindi la
    /// forma conta piu' del colore (le emoji sono disordinate nel terminale).
    pub fn glyph(self) -> &'static str {
        match self {
            Status::Pass => "OK",
            Status::Warn => "ATTENZIONE",
            Status::Fail => "GUASTO",
        }
    }
}

/// Un check, con la sua diagnosi e l'eventuale rimedio.
pub struct Check {
    pub status: Status,
    pub title: String,
    /// Cosa e' stato trovato, in una riga leggibile.
    pub detail: String,
    /// Cosa fare per rimediare, quando serve un comando. Stringa pronta
    /// all'uso: e' il testo che l'utente copia dalla console.
    pub fix_hint: Option<String>,
    /// Fix automatico, se sicuro. L'unico modo in cui il doctor modifica
    /// qualcosa: nient'altro scrive su disco.
    pub fix: Option<Fix>,
    /// Esito dell'applicazione (o della simulazione) del fix.
    pub fix_result: Option<FixOutcome>,
}

/// Un rimedio automatico.
///
/// `apply` e `describe` sono due funzioni distinte per una ragione precisa: il
/// dry-run puo' chiamare solo la seconda. Se il dry-run riusasse `apply`, il
/// file verrebbe creato davvero, e l'utente che voleva solo vedere cosa sarebbe
/// successo si troverebbe con il sistema modificato sotto gli occhi.
#[derive(Clone, Debug)]
pub enum Fix {
    /// Crea il file se manca, con l'intestazione indicata.
    MissingFile { path: PathBuf, header: String },
    /// Cancella i file `.tmp` orfani di una cartella.
    TmpFiles { dir: PathBuf },
}

impl Fix {
    /// Esegue il fix. `Err` vuol dire "non ho potuto", mai "ho fatto del danno".
    pub fn apply(&self) -> Result<String, String> {
        match self {
            Fix::MissingFile { path, header } => {
                // Idempotente per costruzione: se il file c'è non lo tocchiamo.
                // `create(true)` da solo non basterebbe: scriverebbe
                // l'intestazione in mezzo ai dati dell'utente.
                if path.exists() {
                    return Err(format!("{} esiste gia': nessuna modifica", path.display()));
                }
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| format!("{}: {e}", parent.display()))?;
                    }
                }
                std::fs::write(path, header).map_err(|e| format!("{}: {e}", path.display()))?;
                Ok(format!("creato {}", path.display()))
            }
            Fix::TmpFiles { dir } => {
                let v = tmp_files(dir)?;
                if v.is_empty() {
                    return Err("nessun file .tmp da cancellare".into());
                }
                let mut done = Vec::new();
                for name in &v {
                    // Ricontrolliamo l'estensione: fra la lista e la
                    // cancellazione un altro processo potrebbe aver rinominato.
                    if !name.to_ascii_lowercase().ends_with(".tmp") {
                        continue;
                    }
                    match std::fs::remove_file(dir.join(name)) {
                        Ok(()) => done.push(name.clone()),
                        Err(e) => {
                            crate::be!("[BLUESNIFF] doctor: cancellamento di {name} fallito: {e}")
                        }
                    }
                }
                if done.is_empty() {
                    return Err("nessun file cancellato".into());
                }
                Ok(format!("cancellati: {}", done.join(", ")))
            }
        }
    }

    /// Dice cosa farebbe, senza farlo. L'unico metodo che il dry-run puo' usare.
    pub fn describe(&self) -> Result<String, String> {
        match self {
            Fix::MissingFile { path, .. } => {
                if path.exists() {
                    return Err(format!("{} esiste gia': nessuna modifica", path.display()));
                }
                Ok(format!("creato {}", path.display()))
            }
            Fix::TmpFiles { dir } => {
                let v = tmp_files(dir)?;
                if v.is_empty() {
                    return Err("nessun file .tmp da cancellare".into());
                }
                Ok(format!("cancellati: {}", v.join(", ")))
            }
        }
    }
}

/// Cosa e' successo quando il fix e' stato applicato o simulato.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FixOutcome {
    Applied(String),
    /// Solo con `--fix-dry-run`: cosa sarebbe successo.
    WouldDo(String),
    Failed(String),
    /// `--fix` non richiesto: mostriamo comunque cosa farebbe, per non
    /// costringere l'utente a leggere il sorgente.
    Skipped,
}

/// Contesto dei check: tutto quello che il runner non deve indovinare.
pub struct Ctx {
    /// Path dei file di configurazione, isolabile per i test.
    pub known_path: PathBuf,
    pub names_path: PathBuf,
    /// `ignore.txt` e `is_me.txt`: le altre due scelte dell'utente sui
    /// dispositivi, oltre a "segui". Hanno path propri (e non derivati da
    /// `data_dir`) perche' l'override da ambiente esiste anche per loro.
    pub ignore_path: PathBuf,
    pub is_me_path: PathBuf,
    pub data_dir: PathBuf,
    /// Porta della dashboard, per il check firewall.
    pub port: u16,
    /// La condivisione e' attesa? Se no, il firewall non e' un problema.
    pub share_wanted: bool,
    /// `true` se la dashboard risulta in ascolto su questa porta.
    pub dashboard_up: bool,
}

impl Default for Ctx {
    fn default() -> Self {
        let dir = crate::logging::exe_dir();
        Self {
            known_path: dir.join("bt_known.txt"),
            names_path: dir.join("names.txt"),
            ignore_path: dir.join("ignore.txt"),
            is_me_path: dir.join("is_me.txt"),
            data_dir: dir,
            port: 9000,
            share_wanted: false,
            dashboard_up: false,
        }
    }
}

/// Esecuta i check e restituisce l'esito. Non stampa: vedi `format_report`.
pub async fn run_checks(ctx: &Ctx) -> Vec<Check> {
    let mut checks = Vec::new();
    checks.push(check_radio().await);
    checks.push(check_ble().await);
    checks.push(check_dashboard(ctx));
    checks.push(check_firewall(ctx));
    checks.push(check_known(ctx));
    checks.push(check_names(ctx));
    checks.push(check_ignored(ctx));
    checks.push(check_is_me(ctx));
    checks.push(check_tmp_files(ctx));
    checks
}

/// La radio esiste e e' accesa?
///
/// La sola cosa che il doctor non puo' fare e' accenderla: serve un utente
/// che clicchi, o il reset radio, che stacca le cuffie. Quindi resta un
/// problema "manuale" anche se il sintomo e' risolvibile in trenta secondi.
async fn check_radio() -> Check {
    let mut c = Check {
        status: Status::Pass,
        title: "Radio Bluetooth".into(),
        detail: String::new(),
        fix_hint: None,
        fix: None,
        fix_result: None,
    };
    let radios = crate::radio::list_radios();
    if radios.is_empty() {
        c.status = Status::Fail;
        c.detail = "nessuna radio Bluetooth rilevata dal sistema".into();
        c.fix_hint = Some(
            "Su una macchina virtuale il dongle va passato all'host: Proxmox `qm set <VM> --usb0 host=<bus>:<dev>` + stop/start. Fuori VM: controlla il BIOS e Gestione dispositivi.".into(),
        );
        return c;
    }
    match crate::blewatcher::radio_status().await {
        Some((name, true)) => {
            c.detail = format!(
                "{}{} — {name}",
                radios[0].label(),
                if radios.len() > 1 {
                    format!(" ({} radio in totale)", radios.len())
                } else {
                    String::new()
                }
            );
        }
        Some((name, false)) => {
            c.status = Status::Fail;
            c.detail = format!("{name} — SPENTA");
            c.fix_hint = Some(
                "Attiva il Bluetooth da Impostazioni di Windows, poi `bluesniff --reset-radio` se resta muta.".into(),
            );
        }
        None => {
            // La radio c'è nell'enumerazione Win32 ma WinRT non la espone:
            // è il caso del dongle senza driver BLE,常见 su VM.
            c.status = Status::Warn;
            c.detail = format!(
                "{} presente, ma WinRT non la vede (driver Bluetooth LE assente o dongle non passato alla VM)",
                radios[0].label()
            );
            c.fix_hint = Some("Verifica il passthrough USB, poi `bluesniff --reset-radio`.".into());
        }
    }
    c
}

/// Il canale BLE riceve pacchetti? Misura reale, non un flag.
async fn check_ble() -> Check {
    let mut c = Check {
        status: Status::Pass,
        title: "Pacchetti BLE".into(),
        detail: String::new(),
        fix_hint: None,
        fix: None,
        fix_result: None,
    };
    let before = crate::blewatcher::packets_received();
    // Finestra breve: 3 secondi bastano per distinguere "muto" da " vivo"
    // quando c'è traffico, e il doctor non deve sembrare un test di banda.
    let _ = crate::blewatcher::scan_window(std::time::Duration::from_secs(3), true).await;
    let got = crate::blewatcher::packets_received().saturating_sub(before);
    if got > 0 {
        c.detail = format!("{got} pacchetti in 3 s");
    } else {
        c.status = Status::Fail;
        c.detail = "0 pacchetti in 3 s: il canale LE non riceve".into();
        c.fix_hint = Some(
            "Se anche l'inquiry Classic e' muta, il problema e' fisico (dongle/USB passthrough). Altrimenti prova `bluesniff --reset-radio`.".into(),
        );
    }
    c
}

/// La dashboard e' in ascolto?
fn check_dashboard(ctx: &Ctx) -> Check {
    let mut c = Check {
        status: Status::Pass,
        title: "Dashboard".into(),
        detail: String::new(),
        fix_hint: None,
        fix: None,
        fix_result: None,
    };
    let in_listen = std::env::args().any(|a| a == "--listen");
    if in_listen {
        if ctx.dashboard_up {
            c.detail = format!("in ascolto su http://127.0.0.1:{}", ctx.port);
        } else {
            c.status = Status::Fail;
            c.detail = format!("porta {} occupata o bind fallito", ctx.port);
            c.fix_hint = Some(
                "Prova un'altra porta: `bluesniff --listen --dashboard --dashboard-port 9001`"
                    .into(),
            );
        }
    } else if ctx.dashboard_up {
        c.detail = format!("in ascolto su http://127.0.0.1:{}", ctx.port);
    } else {
        c.status = Status::Warn;
        c.detail = "non in esecuzione (normale senza --listen --dashboard)".into();
    }
    c
}

/// Il firewall lascia passare la dashboard? Solo se la condivisione è accesa.
fn check_firewall(ctx: &Ctx) -> Check {
    let mut c = Check {
        status: Status::Pass,
        title: "Firewall (condivisione)".into(),
        detail: String::new(),
        fix_hint: None,
        // Mai: aprire una porta e' una modifica di sicurezza, non un fix.
        // L'utente deve poter dire "no" a questa domanda una volta sola.
        fix: None,
        fix_result: None,
    };
    if !ctx.share_wanted {
        c.detail = "condivisione spenta: nessuna porta da aprire".into();
        return c;
    }
    if crate::share::rule_exists(ctx.port) {
        c.detail = format!("porta {} aperta", ctx.port);
    } else {
        c.status = Status::Fail;
        c.detail = format!(
            "porta {} chiusa: la dashboard non e' raggiungibile in rete",
            ctx.port
        );
        c.fix_hint = Some(format!(
            "Come amministratore: netsh advfirewall firewall add rule name=\"{}\" dir=in action=allow protocol=TCP localport={}",
            crate::share::RULE_NAME, ctx.port
        ));
    }
    c
}

/// `bt_known.txt` esiste ed e' utilizzabile?
fn check_known(ctx: &Ctx) -> Check {
    let path = ctx.known_path.clone();
    let mut c = Check {
        status: Status::Pass,
        title: "bt_known.txt".into(),
        detail: String::new(),
        fix_hint: None,
        fix: Some(Fix::MissingFile {
            path: path.clone(),
            header: "# BTMAC;Nome;Persona  (fill in the Persona column)\n".into(),
        }),
        fix_result: None,
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        c.status = Status::Warn;
        c.detail = "non esiste ancora".into();
        return c;
    };
    let devices = crate::btclassic::load_bt_known(&path);
    // Righe non-commento che non sono MAC: quasi sempre un file scritto a
    // mano con colonne sbagliate, che verrebbe ignorato senza dire nulla.
    let junk = text
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with("BTMAC")
        })
        .filter(|l| {
            let first = l.split(';').next().unwrap_or("").trim();
            !crate::btclassic::looks_like_mac(&first.to_uppercase())
        })
        .count();
    if junk > 0 {
        c.status = Status::Warn;
        c.detail = format!(
            "{junk} riga/e non parseabile/i su {}: verranno ignorate",
            devices.len()
        );
        c.fix_hint = Some("Formato atteso: `BTMAC;Nome;Persona` (12 cifre hex). Non modifico il file: sono dati tuoi.".into());
    } else if devices.is_empty() {
        c.status = Status::Warn;
        c.detail = "esiste ma non ha nessun dispositivo".into();
        c.fix_hint = Some("Dalla dashboard: clicca un dispositivo e poi ⭐ Segui.".into());
    } else {
        c.detail = format!("{} dispositivo/i seguiti", devices.len());
    }
    c
}

/// `ignore.txt` e' leggibile e contiene solo MAC?
///
/// Nessun `fix` qui, a differenza di `bt_known.txt`: il file nasce col primo
/// "Ignora" e non ha senso crearlo vuoto, perche' un `ignore.txt` vuoto e un
/// `ignore.txt` assente significano la stessa cosa. Un `--fix` che crea il
/// file aggiungerebbe un file vuoto accanto all'eseguibile senza risolvere
/// nulla. Se l'utente lo vuole, basta `--ignore <MAC>`.
fn check_ignored(ctx: &Ctx) -> Check {
    let path = ctx.ignore_path.clone();
    let mut c = Check {
        status: Status::Pass,
        title: "ignore.txt".into(),
        detail: String::new(),
        fix_hint: None,
        fix: None,
        fix_result: None,
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        // Assente e' lo stato normale di un utente che non ha ancora tolto
        // niente: Pass, non Warn (vedi la nota su `names.txt`).
        c.detail = "nessun dispositivo ignorato (normale)".into();
        return c;
    };
    let macs = crate::ignore::load(&path);
    let junk = text
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && crate::fsx::normalize_mac(t).is_empty()
        })
        .count();
    if junk > 0 {
        c.status = Status::Warn;
        c.detail = format!("{junk} riga/e non-MAC su {}: verranno ignorate", macs.len());
        c.fix_hint = Some("Formato atteso: un MAC per riga, 12 cifre esadecimali. Non modifico il file: sono dati tuoi.".into());
    } else if macs.is_empty() {
        c.detail = "esiste ma non ha nessun dispositivo".into();
    } else {
        c.detail = format!("{} dispositivo/i ignorati", macs.len());
    }
    c
}

/// `is_me.txt` e' leggibile e ha (al massimo) un MAC valido?
fn check_is_me(ctx: &Ctx) -> Check {
    let path = ctx.is_me_path.clone();
    let mut c = Check {
        status: Status::Pass,
        title: "is_me.txt".into(),
        detail: String::new(),
        fix_hint: None,
        fix: None,
        fix_result: None,
    };
    if !path.exists() {
        c.detail = "nessun dispositivo personale (normale)".into();
        return c;
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        c.status = Status::Warn;
        c.detail = "leggibile solo come binario: controlla i permessi".into();
        c.fix_hint = Some("Il file deve essere un semplice testo con un MAC.".into());
        return c;
    };
    let valid = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !crate::fsx::normalize_mac(l).is_empty())
        .count();
    if valid == 0 {
        c.status = Status::Warn;
        c.detail = "nessun MAC valido".into();
        c.fix_hint = Some("Scrivi un MAC per riga (AA:BB:CC:DD:EE:FF).".into());
    } else if valid > 1 {
        // Non e' un errore che impedisce nulla, ma e' ambiguo: `mine::get`
        // prende la prima riga valida, quindi l'utente potrebbe non sapere
        // quale dei due sia "lui".
        c.status = Status::Warn;
        c.detail = format!("{valid} MAC: vale solo il primo (le notifiche non cambiano)");
        c.fix_hint = Some("Deve restare un solo MAC: tiene quello che ti interessa.".into());
    } else {
        c.detail = "dispositivo personale impostato".into();
    }
    c
}

/// `names.txt` esiste ed e' utilizzabile?
fn check_names(ctx: &Ctx) -> Check {
    let path = ctx.names_path.clone();
    let mut c = Check {
        status: Status::Pass,
        title: "names.txt".into(),
        detail: String::new(),
        fix_hint: None,
        fix: Some(Fix::MissingFile {
            path: path.clone(),
            header: String::new(),
        }),
        fix_result: None,
    };
    match std::fs::read_to_string(&path) {
        Ok(text) if !text.trim().is_empty() => {
            let n = text.lines().filter(|l| !l.trim().is_empty()).count();
            c.detail = format!("{n} nome/i personalizzati");
        }
        Ok(_) => {
            // Vuoto non e' un problema: e' lo stato in cui la dashboard
            // lascia il file se l'utente non ha ancora rinominato nulla. Se lo
            // trattassimo come Warn, il fix (che crea solo se manca) fallirebbe
            // e il riepilogo direbbe "fix falliti: 1" per un file sano.
            c.detail = "nessun nome personalizzato (normale)".into();
        }
        Err(_) => {
            // Assente e' normale: e' un file opzionale, non un guasto. Lo
            // segnaliamo come Warn e non come Fail per non urlare all'utente
            // per un file che non ha mai usato.
            c.status = Status::Warn;
            c.detail = "non esiste (facoltativo: nomi salvati dalla dashboard)".into();
        }
    }
    c
}

/// File `.tmp` rimasti da scritture interrotte.
///
/// Un `.tmp` è per definizione un file che nessuno ha finito di scrivere:
/// cancellarlo non può perdere dati. È l'unico fix "cancellazione" che il
/// doctor si concede, ed è sicuro perché il nome dice già "non finito".
fn check_tmp_files(ctx: &Ctx) -> Check {
    let dir = ctx.data_dir.clone();
    let mut c = Check {
        status: Status::Pass,
        title: "File temporanei".into(),
        detail: String::new(),
        fix_hint: None,
        fix: Some(Fix::TmpFiles { dir: dir.clone() }),
        fix_result: None,
    };
    match tmp_files(&dir) {
        Ok(v) if v.is_empty() => c.detail = "nessun file temporaneo".into(),
        Ok(v) => {
            c.status = Status::Warn;
            c.detail = format!("{} file .tmp orfano/i", v.len());
            c.fix_hint = Some(format!("Candidati: {}", v.join(", ")));
        }
        Err(e) => {
            c.status = Status::Warn;
            c.detail = format!("cartella dati non leggibile: {e}");
        }
    }
    c
}

/// Elenca i `.tmp` nella cartella dati.
fn tmp_files(dir: &Path) -> Result<Vec<String>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.to_ascii_lowercase().ends_with(".tmp") {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

/// Applica (o simula) i fix sicuri. Restituisce (applicati, falliti).
pub fn apply_fixes(checks: &mut [Check], do_fix: bool, dry_run: bool) -> (usize, usize) {
    let mut applied = 0usize;
    let mut failed = 0usize;
    for c in checks.iter_mut() {
        if c.status == Status::Pass {
            continue;
        }
        let Some(f) = c.fix.clone() else {
            continue;
        };
        if !do_fix {
            c.fix_result = Some(FixOutcome::Skipped);
            continue;
        }
        if dry_run {
            // NON chiamiamo `f()`: scriverebbe davvero. Ogni fix sa
            // descrivere se stesso (`DryRunnable`).
            // Solo `describe`: `apply` scriverebbe davvero. Un dry-run che
            // crea il file non e' un dry-run.
            c.fix_result = Some(match f.describe() {
                Ok(msg) => FixOutcome::WouldDo(msg),
                Err(e) => FixOutcome::Failed(e),
            });
            continue;
        }
        c.fix_result = match f.apply() {
            Ok(msg) => {
                applied += 1;
                c.status = Status::Pass;
                c.detail = msg.clone();
                Some(FixOutcome::Applied(msg))
            }
            Err(e) => {
                failed += 1;
                Some(FixOutcome::Failed(e))
            }
        };
    }
    (applied, failed)
}

/// Formatta il report. Funzione pura: qui dentro non c'e' I/O, cosi' e'
/// testabile senza processo e senza hardware.
pub fn format_report(checks: &[Check], applied: usize, failed: usize) -> String {
    let mut out = String::new();
    for c in checks {
        out.push_str(&format!("  {:<11} {}\n", c.status.glyph(), c.title));
        out.push_str(&format!("    {}\n", c.detail));
        if let Some(h) = &c.fix_hint {
            out.push_str(&format!("    → {h}\n"));
        }
        match &c.fix_result {
            Some(FixOutcome::Applied(m)) => out.push_str(&format!("    → Fix applicato: {m}\n")),
            Some(FixOutcome::WouldDo(m)) => out.push_str(&format!("    → Avrebbe fatto: {m}\n")),
            Some(FixOutcome::Failed(m)) => out.push_str(&format!("    → Fix fallito: {m}\n")),
            // `Skipped` esiste solo se c'era un fix da applicare: se non
            // c'era, il rimedio è già stampato come `fix_hint`.
            Some(FixOutcome::Skipped) => {
                out.push_str("    → Risolto da: `bluesniff --doctor --fix`\n");
            }
            None => {}
        }
    }
    out.push('\n');
    out.push_str(&format!(
        "[BLUESNIFF] Fix applicati: {applied} · Fix falliti: {failed} · \
         Rimane da fare a mano: {}\n",
        checks
            .iter()
            .filter(|c| c.status != Status::Pass && c.fix.is_none())
            .count()
    ));
    out
}

/// Entry point del comando.
pub async fn run(
    logger: &Logger,
    do_fix: bool,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Ctx {
        dashboard_up: std::net::TcpStream::connect(("127.0.0.1", 9000)).is_ok(),
        share_wanted: crate::share::wanted(),
        ..Ctx::default()
    };
    logger.log(&format!(
        "doctor: inizio (fix={do_fix}, dry_run={dry_run}, share={}, dashboard_up={})",
        ctx.share_wanted, ctx.dashboard_up
    ));
    let mut checks = run_checks(&ctx).await;
    // Ogni fix viene loggato *prima* di applicarlo: se l'utente ha un
    // problema dopo, il log dice cosa è stato toccato.
    for c in &checks {
        if c.status != Status::Pass && c.fix.is_some() {
            logger.log(&format!(
                "doctor: '{}' non va bene ({}), fix disponibile",
                c.title, c.detail
            ));
        }
    }
    let (applied, failed) = apply_fixes(&mut checks, do_fix, dry_run);
    let report = format_report(&checks, applied, failed);
    crate::bn!("{}", report);
    if dry_run && do_fix {
        crate::bn!("[BLUESNIFF] --fix-dry-run: nessuna modifica applicata.");
    }
    for c in &checks {
        for r in [&c.fix_result] {
            if let Some(FixOutcome::Applied(m)) = r {
                logger.log(&format!("doctor: fix applicato a '{}': {m}", c.title));
            }
        }
    }
    logger.log(&format!(
        "doctor: fine — {applied} fix applicati, {failed} falliti"
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("bluesniff-doctor-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ctx_in(dir: &Path) -> Ctx {
        Ctx {
            known_path: dir.join("bt_known.txt"),
            names_path: dir.join("names.txt"),
            ignore_path: dir.join("ignore.txt"),
            is_me_path: dir.join("is_me.txt"),
            data_dir: dir.to_path_buf(),
            port: 9000,
            share_wanted: false,
            dashboard_up: false,
        }
    }

    // --- i check puri (nessun hardware) ---

    #[test]
    fn known_mancante_e_un_warn_con_fix() {
        let dir = tmp_dir("known-missing");
        let c = check_known(&ctx_in(&dir));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("non esiste"));
        assert!(c.fix.is_some(), "manca il fix sicuro");
    }

    #[test]
    fn known_valido_conta_i_dispositivi() {
        let dir = tmp_dir("known-ok");
        std::fs::write(
            dir.join("bt_known.txt"),
            "# hdr\nEC:ED:73:65:AC:45;Moto;Mario\n",
        )
        .unwrap();
        let c = check_known(&ctx_in(&dir));
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
        assert!(c.detail.contains("1 dispositivo"));
    }

    #[test]
    fn known_ignora_commenti_e_header() {
        let dir = tmp_dir("known-noise");
        std::fs::write(
            dir.join("bt_known.txt"),
            "# BTMAC;Nome;Persona\n\n# altro commento\n",
        )
        .unwrap();
        let c = check_known(&ctx_in(&dir));
        // Nessun errore di parsing: è un file vuoto, non malformato.
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("non ha nessun"), "{}", c.detail);
    }

    #[test]
    fn known_segnala_le_righe_non_parseabili() {
        let dir = tmp_dir("known-junk");
        std::fs::write(
            dir.join("bt_known.txt"),
            "EC:ED:73:65:AC:45;Moto;Mario\nQUESTA RIGA NON E' UN MAC\n",
        )
        .unwrap();
        let c = check_known(&ctx_in(&dir));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("non parseabile"), "{}", c.detail);
        assert!(c.fix_hint.is_some());
    }

    #[test]
    fn names_mancante_e_un_warn_non_un_fail() {
        let dir = tmp_dir("names-missing");
        let c = check_names(&ctx_in(&dir));
        // names.txt è facoltativo: un file assente non è un guasto.
        assert_eq!(c.status, Status::Warn, "{}", c.detail);
        assert!(c.detail.contains("facoltativo"), "{}", c.detail);
    }

    #[test]
    fn names_vuoto_non_produce_una_fallita() {
        // Regressione: un file vuoto è lo stato normale, ma se fosse un Warn
        // il fix (che crea solo se manca) fallirebbe e ogni `--fix` su un
        // installazione sana riporterebbe "Fix falliti: 1".
        let dir = tmp_dir("names-empty");
        std::fs::write(dir.join("names.txt"), "\n\n").unwrap();
        let mut checks = vec![check_names(&ctx_in(&dir))];
        assert_eq!(checks[0].status, Status::Pass, "{}", checks[0].detail);
        let (a, f) = apply_fixes(&mut checks, true, false);
        assert_eq!((a, f), (0, 0), "nessun fix deve fallire su un file vuoto");
    }

    #[test]
    fn firewall_non_e_un_problema_se_la_condivisione_e_spenta() {
        let dir = tmp_dir("fw-off");
        let c = check_firewall(&ctx_in(&dir));
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
        assert!(c.detail.contains("spenta"));
    }

    #[test]
    fn firewall_chiuso_ma_nessun_fix_automatico() {
        let dir = tmp_dir("fw-on");
        let mut ctx = ctx_in(&dir);
        ctx.share_wanted = true;
        // Porta alta: di sicuro non ha una regola dedicata.
        ctx.port = 45999;
        let c = check_firewall(&ctx);
        if c.status == Status::Fail {
            assert!(
                c.fix.is_none(),
                "il doctor non deve mai aprire il firewall da solo"
            );
            assert!(c.fix_hint.as_ref().unwrap().contains("netsh"));
        }
    }

    #[test]
    fn tmp_orfani_rilevati() {
        let dir = tmp_dir("tmp");
        std::fs::write(dir.join("a.tmp"), "x").unwrap();
        std::fs::write(dir.join("b.TMP"), "x").unwrap();
        std::fs::write(dir.join("keep.txt"), "x").unwrap();
        let c = check_tmp_files(&ctx_in(&dir));
        assert_eq!(c.status, Status::Warn, "{}", c.detail);
        assert!(c.detail.contains('2'), "{}", c.detail);
    }

    #[test]
    fn nessun_tmp_e_una_passata() {
        let dir = tmp_dir("no-tmp");
        std::fs::write(dir.join("keep.txt"), "x").unwrap();
        let c = check_tmp_files(&ctx_in(&dir));
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
    }

    // --- i fix ---

    #[test]
    fn fix_crea_il_file_mancante() {
        let dir = tmp_dir("fix-create");
        let p = dir.join("bt_known.txt");
        let fix = Fix::MissingFile {
            path: p.clone(),
            header: "# hdr\n".into(),
        };
        let msg = fix.apply().unwrap();
        assert!(p.exists());
        assert!(msg.contains("creato"));
        assert!(std::fs::read_to_string(&p).unwrap().contains("# hdr"));
    }

    #[test]
    fn fix_e_idempotente_su_file_che_gia_esiste() {
        let dir = tmp_dir("fix-idem");
        let p = dir.join("bt_known.txt");
        std::fs::write(&p, "EC:ED:73:65:AC:45;Moto;Mario\n").unwrap();
        // Non deve toccare un file con dati: è qui che il danno sarebbe
        // irreversibile.
        let fix = Fix::MissingFile {
            path: p.clone(),
            header: "# hdr\n".into(),
        };
        let err = fix.apply().unwrap_err();
        assert!(err.contains("esiste gia'"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "EC:ED:73:65:AC:45;Moto;Mario\n"
        );
    }

    #[test]
    fn fix_cancella_i_tmp_e_nientaltro() {
        let dir = tmp_dir("fix-tmp");
        std::fs::write(dir.join("a.tmp"), "x").unwrap();
        std::fs::write(dir.join("b.txt"), "DATI").unwrap();
        let msg = Fix::TmpFiles { dir: dir.clone() }.apply().unwrap();
        assert!(!dir.join("a.tmp").exists());
        assert!(dir.join("b.txt").exists(), "file non-tmp cancellato");
        assert!(msg.contains("a.tmp"));
    }

    #[test]
    fn fix_cancella_i_tmp_anche_maiuscoli() {
        let dir = tmp_dir("fix-tmp-case");
        std::fs::write(dir.join("A.TMP"), "x").unwrap();
        Fix::TmpFiles { dir: dir.clone() }.apply().unwrap();
        assert!(!dir.join("A.TMP").exists());
    }

    #[test]
    fn fix_su_niente_riporta_che_non_c_e_nulla() {
        let dir = tmp_dir("fix-nothing");
        let err = Fix::TmpFiles { dir: dir.clone() }.apply().unwrap_err();
        assert!(err.contains("nessun"), "{err}");
    }

    // --- apply_fixes ---

    #[test]
    fn senza_fix_il_report_aiuta_a_farlo() {
        let dir = tmp_dir("apply-none");
        let mut checks = vec![check_known(&ctx_in(&dir))];
        let (a, f) = apply_fixes(&mut checks, false, false);
        assert_eq!((a, f), (0, 0));
        assert!(matches!(checks[0].fix_result, Some(FixOutcome::Skipped)));
        // Il fix c'era: il report deve dirlo, altrimenti l'utente non sa che
        // esiste un modo per risolvere da solo.
        assert!(format_report(&checks, a, f).contains("--doctor --fix"));
        assert!(!dir.join("bt_known.txt").exists());
    }

    #[test]
    fn con_fix_il_file_viene_creato_e_il_check_ripassa() {
        let dir = tmp_dir("apply-fix");
        let mut checks = vec![check_known(&ctx_in(&dir))];
        let (a, f) = apply_fixes(&mut checks, true, false);
        assert_eq!((a, f), (1, 0));
        assert_eq!(checks[0].status, Status::Pass);
        assert!(dir.join("bt_known.txt").exists());
    }

    #[test]
    fn dry_run_riporta_il_fix_senza_conta_applicati() {
        let dir = tmp_dir("apply-dry");
        let mut checks = vec![check_known(&ctx_in(&dir))];
        let (a, f) = apply_fixes(&mut checks, true, true);
        assert_eq!((a, f), (0, 0), "il dry-run non deve contare fix applicati");
        assert!(matches!(checks[0].fix_result, Some(FixOutcome::WouldDo(_))));
    }

    #[test]
    fn i_check_passing_non_toccano_nulla() {
        let dir = tmp_dir("apply-pass");
        std::fs::write(dir.join("bt_known.txt"), "EC:ED:73:65:AC:45;Moto;Mario\n").unwrap();
        let before = std::fs::read_to_string(dir.join("bt_known.txt")).unwrap();
        let mut checks = vec![check_known(&ctx_in(&dir))];
        let (a, f) = apply_fixes(&mut checks, true, false);
        assert_eq!((a, f), (0, 0));
        assert!(checks[0].fix_result.is_none());
        assert_eq!(
            std::fs::read_to_string(dir.join("bt_known.txt")).unwrap(),
            before
        );
    }

    #[test]
    fn un_fix_fallito_conta_come_fallito_e_non_mira_lo_stato() {
        // Un path dentro una cartella che "non esiste" come file ma il cui
        // padre e' un file (non una directory): `create_dir_all` fallisce, e
        // il fix deve riportarlo come fallito senza dichiarare risolto il
        // check. E' il caso "eseguibile in Program Files senza admin".
        let dir = tmp_dir("apply-fail");
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, "sono un file").unwrap();
        let check = Check {
            status: Status::Warn,
            title: "sintetico".into(),
            detail: "d".into(),
            fix_hint: None,
            fix: Some(Fix::MissingFile {
                path: blocker.join("figlio").join("x.txt"),
                header: String::new(),
            }),
            fix_result: None,
        };
        let mut checks = vec![check];
        let (applied, failed) = apply_fixes(&mut checks, true, false);
        assert_eq!(applied, 0, "non doveva applicare nulla");
        assert_eq!(failed, 1, "il fallimento doveva essere contato");
        // Il punto: un fix fallito NON porta il check a Pass. Dire "risolto"
        // su un fix non riuscito e' il peggior bug possibile in un doctor.
        assert_eq!(checks[0].status, Status::Warn);
        assert!(matches!(checks[0].fix_result, Some(FixOutcome::Failed(_))));
    }

    // --- format_report ---

    #[test]
    fn report_usa_i_glofi_e_indenta() {
        let checks = vec![Check {
            status: Status::Fail,
            title: "Firewall".into(),
            detail: "porta 9000 chiusa".into(),
            fix_hint: Some("netsh advfirewall ...".into()),
            fix: None,
            fix_result: None,
        }];
        let r = format_report(&checks, 0, 0);
        assert!(r.contains("GUASTO"), "{r}");
        assert!(r.contains("  Firewall"), "{r}");
        assert!(r.contains("    porta 9000 chiusa"), "{r}");
        assert!(r.contains("    → netsh"), "{r}");
        assert!(r.contains("Rimane da fare a mano: 1"), "{r}");
    }

    #[test]
    fn report_conta_solo_i_problemi_senza_fix() {
        let dir = tmp_dir("report-count");
        let mut checks = vec![check_known(&ctx_in(&dir)), check_names(&ctx_in(&dir))];
        let r = format_report(&checks, 0, 0);
        // Entrambi hanno un fix: nessuno resta "a mano".
        assert!(r.contains("Rimane da fare a mano: 0"), "{r}");
        let _ = &mut checks;
    }

    #[test]
    fn report_mostra_l_esito_del_fix() {
        let checks = vec![Check {
            status: Status::Pass,
            title: "bt_known.txt".into(),
            detail: "creato /tmp/bt_known.txt".into(),
            fix_hint: Some("vecchio hint".into()),
            fix: Some(Fix::MissingFile {
                path: PathBuf::from("x"),
                header: String::new(),
            }),
            fix_result: Some(FixOutcome::Applied("creato".into())),
        }];
        let r = format_report(&checks, 1, 0);
        assert!(r.contains("Fix applicato: creato"), "{r}");
        assert!(r.contains("Fix applicati: 1"), "{r}");
    }

    #[test]
    fn report_del_dry_run_non_dice_di_aver_applicato() {
        let checks = vec![Check {
            status: Status::Warn,
            title: "x".into(),
            detail: "d".into(),
            fix_hint: None,
            fix: Some(Fix::MissingFile {
                path: PathBuf::from("y"),
                header: String::new(),
            }),
            fix_result: Some(FixOutcome::WouldDo("(dry-run) y".into())),
        }];
        let r = format_report(&checks, 0, 0);
        assert!(r.contains("Avrebbe fatto"), "{r}");
        assert!(!r.contains("Fix applicato"), "{r}");
    }
}
