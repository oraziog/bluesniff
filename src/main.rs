// bluesniff parla direttamente con le API Win32/WinRT del Bluetooth: quasi
// ogni chiamata è un FFI, e la loro documentazione SAFETY è spesso implicita.
// Questi due lint tengono l'equivalente di un controllo di sicurezza in review:
// ogni blocco `unsafe` deve dire perché è corretto.
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::missing_safety_doc)]

mod alerts;
mod blewatcher;
mod bluetooth;
mod btclassic;
mod classify;
mod clients;
mod control;
mod correlate;
mod cves;
mod dashboard;
mod doctor;
mod fpfilter;
mod fsx;
mod gatt;
mod gattnames;
mod ignore;
mod known;
mod lan;
mod listen;
mod logging;
mod mdns;
mod mdns_register;
mod mine;
mod nbtns;
mod ops;
mod patterns;
mod presence;
mod radio;
mod radiostate;
mod rawlog;
mod report;
mod sdp;
mod share;
mod stream;
mod track;
mod vendor;

use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use logging::Logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let logger = Logger::open_default()?;

    let args: Vec<String> = std::env::args().collect();
    // In modalità JSON (--inq-json, o --json per lo streaming di --listen)
    // lo stdout è riservato alle righe JSON machine-readable: banner e radio
    // vanno solo nel log.
    let json_mode = args
        .iter()
        .skip(1)
        .any(|a| a == "--inq-json" || a == "--json");

    // Controllo di un bluesniff gia' in esecuzione: da un .bat, da Task
    // Scheduler, da uno script. Non avviano una scansione, parlano con il
    // processo che c'e' gia' tramite canale HTTP o file di controllo.
    //
    // Sta PRIMA di banner, radio e share: sono quattro righe di rumore su un
    // comando che l'utente esegue da uno script e che vuole una risposta, non
    // un banner. E non puo' passare dal dispatcher piu' in basso, perche' li' il
    // radio e' gia' stata enumerata e un `bluesniff --stop` finirebbe per
    // mettersi in ascolto lui stesso invece di fermare il processo giusto.
    let flag = |name: &str| args.iter().skip(1).any(|a| a == name);
    let do_snapshot = flag("--snapshot");
    if let Some(cmd) = control_command(
        flag("--pause"),
        flag("--resume"),
        flag("--stop"),
        flag("--status"),
    ) {
        return run_control_flag(&logger, cmd, false).await;
    }
    if do_snapshot {
        return run_control_flag(&logger, control::Control::Snapshot, true).await;
    }

    if !json_mode {
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Initializing...");
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m Log file: {}",
            logger.path().display()
        );
    }

    let radios = radio::list_radios();
    if radios.is_empty() {
        logger.log("no Bluetooth radio(s) reported by the OS");
    } else {
        logger.log(&format!(
            "{} Bluetooth radio(s) reported by the OS",
            radios.len()
        ));
        for (i, r) in radios.iter().enumerate() {
            logger.log(&format!(
                "radio[{}] name={} address={}",
                i + 1,
                r.name,
                r.address
            ));
            if !json_mode {
                crate::bn!(
                    "\x1b[34m[BLUESNIFF]\x1b[0m Radio[{}]: \x1b[33m{}\x1b[0m ({})",
                    i + 1,
                    r.address,
                    r.name
                );
            }
        }
    }

    let connect_mac = parse_connect_arg(&args);
    let do_correlate = args.iter().skip(1).any(|a| a == "--correlate");
    let do_overnight = args.iter().skip(1).any(|a| a == "--overnight");
    let do_edit_known = args.iter().skip(1).any(|a| a == "--edit-known");
    // Report HTML: il flag senza argomento e` il modo, i `--report-*` sono
    // le sue opzioni (accettate anche senza `--report`, cosi' `bluesniff
    // --report-last 1h` da solo non stampa solo l'usage).
    let do_report = args.iter().skip(1).any(|a| a == "--report")
        || args.iter().skip(1).any(|a| a.starts_with("--report-"));
    // Scelte sui dispositivi, disponibili anche da riga di comando: la
    // dashboard resta il modo principale, ma per scripting e per il caso in
    // cui la dashboard non e' accesa servono gli stessi file senza dover
    // aprire un editor.
    let ignore_mac = parse_mac_arg(&args, "--ignore");
    let unignore_mac = parse_mac_arg(&args, "--unignore");
    let do_unignore_all = args.iter().skip(1).any(|a| a == "--unignore-all");
    let do_list_ignored = args.iter().skip(1).any(|a| a == "--list-ignored");
    let follow_mac = parse_mac_arg(&args, "--follow");
    let unfollow_mac = parse_mac_arg(&args, "--unfollow");
    let do_list_followed = args.iter().skip(1).any(|a| a == "--list-followed");
    let do_doctor = args.iter().skip(1).any(|a| a == "--doctor");
    // `--fix` da solo non fa niente: `--doctor --fix` e' l'unica forma
    // sensata, e accettare `--fix` senza `--doctor` sarebbe una promessa
    // non mantenuta.
    let do_fix = args.iter().skip(1).any(|a| a == "--fix");
    let fix_dry_run = args.iter().skip(1).any(|a| a == "--fix-dry-run");
    let classify = parse_optional_arg(&args, "--classify");
    let netmonloc = parse_path_arg(&args, "--netmonloc");
    let macfile = parse_path_arg(&args, "--macfile");
    let track_secs = parse_track_arg(&args);
    let record = parse_record_arg(&args);
    // Nessun argomento = monitor continuo con dashboard. Fino a poco fa
    // faceva uno scan BLE di 5 secondi, e `--help` era l'unico modo per
    // capire cosa stesse facendo: per un utente che arriva dal README, un
    // comando che si chiude in cinque secondi e sparisce e' indistinguibile
    // da uno che non funziona. `--one-shot` conserva il comportamento vecchio,
    // con un nome che dice cosa fa.
    let senza_argomenti = args.len() <= 1;
    let do_one_shot = args.iter().skip(1).any(|a| a == "--one-shot");
    let listen = if senza_argomenti {
        Some(None)
    } else {
        parse_optional_arg(&args, "--listen")
    };
    // Streaming netmonloc: --json (NDJSON su stdout per sottoprocesso) e/o
    // --push <url> (POST HTTP per netmonloc remoto).
    let stream_json = args.iter().skip(1).any(|a| a == "--json");
    let push_url = parse_path_arg(&args, "--push");
    let push_token = parse_path_arg(&args, "--push-token");
    let do_learn = args.iter().skip(1).any(|a| a == "--learn");
    let inq_secs = parse_optional_arg(&args, "--inq");
    let inq_json = json_mode;
    let patterns_path = parse_path_arg(&args, "--patterns");
    let static_path = parse_path_arg(&args, "--static");
    let prune_days = parse_u64_arg(&args, "--prune-days");
    let prune_min = parse_u64_arg(&args, "--prune-min-sightings");
    let heartbeat = parse_heartbeat_arg(&args);
    let ntfy_topic = parse_path_arg(&args, "--ntfy");
    let ntfy_absence = parse_u64_arg(&args, "--ntfy-absence").unwrap_or(3).max(1) as usize;
    // `--ntfy-test <topic>` manda una notifica di prova ed esce: serve a
    // verificare la configurazione dalla riga di comando, senza dover mettere
    // su la dashboard e senza aspettare che un dispositivo seguito cambi stato.
    let ntfy_test_topic = parse_path_arg(&args, "--ntfy-test");
    let ntfy_server = parse_path_arg(&args, "--ntfy-server");
    let dashboard_flag = args.iter().skip(1).any(|a| a == "--dashboard");
    let no_dashboard = args.iter().skip(1).any(|a| a == "--no-dashboard");
    let dashboard_port = parse_u64_arg(&args, "--dashboard-port").unwrap_or(9000) as u16;
    // Se l'utente ha condiviso la dashboard in una sessione precedente, la
    // scelta viene riapplicata da sola: `restore()` la rilegge da share.json e
    // `bind_addr` la trasforma in 0.0.0.0. Un flag esplicito della riga di
    // comando ha sempre la precedenza su quella salvata.
    let share_remembered = share::restore();
    let dashboard_addr = share::bind_addr(share_remembered, parse_dashboard_addr(&args));
    if share_remembered {
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m dashboard condivisa in rete (scelta ripresa da share.json): 0.0.0.0:{dashboard_port}");
    }
    let passive = args.iter().skip(1).any(|a| a == "--passive");
    let radio_arg = parse_selector_arg(&args, "--radio");
    // --reset-radio [secondi]: spegne/riaccende la radio e termina.
    let reset_radio_secs = parse_optional_arg(&args, "--reset-radio");
    // --no-rawlog: disattiva il log raw per-pacchetto (default: attivo con
    // --listen/--record, rotazione 64 MB + retention 7 giorni).
    let no_rawlog = args.iter().skip(1).any(|a| a == "--no-rawlog");

    // L'ordine di questi tre check conta.
    //
    // 1. `--version` vince su tutto: e' una domanda sul binario, non un
    //    comando, e non ha effetti collaterali. Prima degli altri perche' se
    //    arrivasse dopo `--help` l'utente che scrive `bluesniff --help -V`
    //    riceverebbe l'help invece della versione.
    if args.iter().skip(1).any(|a| a == "--version" || a == "-V") {
        crate::bn!("bluesniff {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // 2. `--help` con contesto: `--listen --help` mostra le opzioni di
    //    `--listen`, non tutte. Si guarda il primo flag che precede `--help`:
    //    e' l'ordine in cui l'utente lo ha scritto, e in
    //    `--listen --dashboard --help` e' `--listen` quello che gli
    //    interessa. Se non c'e' un comando riconosciuto, help generale.
    if let Some(pos) = args.iter().skip(1).position(|a| a == "--help" || a == "-h") {
        // `pos` e' relativo a `args[1..]`, quindi la fetta giusta e' fino a
        // `pos`, non `args[1..pos]`: con `bluesniff --help` pos vale 0 e la
        // fetta sarebbe invertita.
        let contesto = args[1..=pos]
            .iter()
            .find(|a| matches!(a.as_str(), "--listen" | "--inq" | "--report"));
        crate::bn!(
            "{}",
            match contesto {
                Some(flag) => usage_for(flag),
                None => usage(),
            }
        );
        return Ok(());
    }

    // Log raw per-pacchetto: writer thread + retention. Attivo di default in
    // tutte le modalità che scansionano; --no-rawlog lo spegne del tutto.
    if no_rawlog {
        crate::rawlog::set_enabled(false);
        logger.log("rawlog: disattivato da --no-rawlog");
    } else if listen.is_some()
        || record.is_some()
        || do_overnight
        || classify.is_some()
        || track_secs.is_some()
    {
        crate::rawlog::init();
        logger.log(&format!(
            "rawlog: attivo su {} (rotazione {} MB, retention {} giorni)",
            crate::rawlog::active_path().display(),
            crate::rawlog::ROTATE_BYTES / (1024 * 1024),
            crate::rawlog::RETENTION_DAYS
        ));
    }

    // --json / --push / --push-token sono modalità di streaming di --listen.
    if (stream_json || push_url.is_some() || push_token.is_some()) && listen.is_none() {
        crate::bn!("[BLUESNIFF] --json and --push require --listen (netmonloc streaming mode)");
        return Ok(());
    }
    if push_token.is_some() && push_url.is_none() {
        crate::bn!("[BLUESNIFF] --push-token requires --push <url>");
        return Ok(());
    }
    let stream_cfg = if stream_json || push_url.is_some() {
        Some(crate::stream::StreamConfig {
            json: stream_json,
            push_url: push_url.clone(),
            push_token: push_token.clone(),
        })
    } else {
        None
    };

    // Selezione della radio (`--radio <indice|MAC|nome>`). La scelta viene
    // registrata nello stato globale e vale per l'inquiry Classic e per le
    // probe RFCOMM, che possono partire da una radio specifica.
    let selected_radio = match radio_arg.as_deref() {
        Some(sel) => match radio::resolve(sel) {
            Ok(r) => Some(r),
            Err(e) => {
                // Selettore sbagliato: mostriamo cosa c'era a disposizione
                // invece di partire in silenzio sulla radio sbagliata.
                crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m --radio {sel}: {e}");
                logger.log(&format!("radio: selettore '{sel}' non valido: {e}"));
                let available = radio::list_radios();
                if available.is_empty() {
                    crate::bn!("[BLUESNIFF] Nessuna radio Bluetooth rilevata dal sistema.");
                } else {
                    crate::bn!("[BLUESNIFF] Radio disponibili:");
                    for r in &available {
                        crate::bn!("  {}", r.label());
                    }
                }
                return Ok(());
            }
        },
        // Nessun --radio: con una sola radio la scelta è ovvia; con più di
        // una restiamo sulla predefinita di sistema (e lo diciamo).
        None => {
            if radios.len() == 1 {
                radios.first().cloned()
            } else {
                None
            }
        }
    };
    radio::set_selected(selected_radio.clone());
    match selected_radio.as_ref() {
        Some(r) if radio_arg.is_some() => {
            logger.log(&format!("radio: selezionata {} {}", r.label(), r.name));
            crate::bn!(
                "\x1b[34m[BLUESNIFF]\x1b[0m Radio selezionata: \x1b[33m{}\x1b[0m ({})",
                r.address,
                r.name
            );
        }
        Some(r) => {
            logger.log(&format!(
                "radio: unica radio disponibile {} {}",
                r.label(),
                r.name
            ));
        }
        None => {
            logger.log(&format!(
                "radio: {} radio presenti, uso la predefinita di sistema (--radio per scegliere)",
                radios.len()
            ));
            if radios.len() > 1 {
                crate::bn!(
                    "\x1b[33m[BLUESNIFF]\x1b[0m {} radio rilevate: uso la predefinita di sistema (--radio <indice|MAC|nome> per scegliere)",
                    radios.len()
                );
            }
        }
    }

    // Il watcher BLE di WinRT scansiona sempre l'adattatore predefinito e non
    // offre alcuna API per sceglierne un altro: se la radio scelta non è
    // quella che Windows usa per il LE, meglio dirlo subito invece di far
    // credere che la scansione stia usando la radio richiesta.
    if let Some(r) = selected_radio.as_ref() {
        if let Some(default_mac) = crate::blewatcher::local_adapter_mac().await {
            if !default_mac.eq_ignore_ascii_case(&r.address) {
                logger.log(&format!(
                    "radio: BLE usa l'adattatore predefinito {default_mac}, non {} ({})",
                    r.address, r.name
                ));
                crate::bn!(
                    "\x1b[33m[BLUESNIFF]\x1b[0m Nota: la scansione BLE usa l'adattatore predefinito {default_mac}, non {}: --radio vale per inquiry Classic e probe RFCOMM. Per il BLE disabilita l'altro adattatore.",
                    r.address
                );
            }
        }
    }

    let result = if let Some(topic) = ntfy_test_topic.as_deref() {
        run_ntfy_test(
            &logger,
            topic,
            ntfy_server.as_deref().unwrap_or("https://ntfy.sh"),
        )
        .await
    } else if let Some(secs) = reset_radio_secs {
        run_reset_radio(&logger, secs.unwrap_or(3)).await
    } else if let Some(p) = static_path.as_deref() {
        let path = if p.is_empty() {
            logging::exe_dir().join("presenze.csv")
        } else {
            std::path::PathBuf::from(p)
        };
        fpfilter::report_csv(&logger, &path);
        Ok(())
    } else if let Some(p) = patterns_path.as_deref() {
        let path = if p.is_empty() {
            logging::exe_dir().join("presenze.csv")
        } else {
            std::path::PathBuf::from(p)
        };
        patterns::report(&logger, &path);
        Ok(())
    } else if let Some(mac) = connect_mac.as_deref() {
        bluetooth::inspect(&logger, mac).await
    } else if let Some(secs) = track_secs {
        run_track(&logger, secs).await
    } else if let Some(secs) = record {
        run_record(&logger, secs).await
    } else if do_correlate {
        run_correlate(&logger).await
    } else if let Some(secs) = classify {
        run_classify(&logger, secs, netmonloc.as_deref(), macfile.as_deref()).await
    } else if do_doctor {
        doctor::run(&logger, do_fix, fix_dry_run).await
    } else if do_edit_known {
        run_edit_known(&logger)
    } else if do_report {
        run_report(&logger, &args)
    } else if let Some(mac) = ignore_mac.as_deref() {
        run_ignore(&logger, mac)
    } else if let Some(mac) = unignore_mac.as_deref() {
        run_unignore(&logger, mac)
    } else if do_unignore_all {
        run_unignore_all(&logger)
    } else if do_list_ignored {
        run_list_ignored(&logger)
    } else if let Some(mac) = follow_mac.as_deref() {
        run_follow(
            &logger,
            mac,
            parse_path_arg(&args, "--name").as_deref().unwrap_or(""),
        )
    } else if let Some(mac) = unfollow_mac.as_deref() {
        run_unfollow(&logger, mac)
    } else if do_list_followed {
        run_list_followed(&logger)
    } else if do_overnight {
        // --overnight: 8 ore di registrazione. E' un --record con durata
        // fissa: non aggiunge log piu' ricchi di quelli normali.
        run_record(&logger, Some(28800)).await
    } else if do_one_shot {
        // Il comportamento che era il default prima: uno scan di 5 secondi e
        // basta. Sta prima di --listen perche' `bluesniff --one-shot
        // --dashboard` non ha senso: la dashboard senza ascolto non vede
        // niente, e aprire un server HTTP per uno scan che dura cinque
        // secondi lascerebbe un socket appeso.
        bluetooth::scan(&logger).await
    } else if let Some(secs) = inq_secs {
        run_inq(&logger, secs, inq_json).await
    } else if do_learn {
        run_learn(&logger).await
    } else if let Some(secs) = listen {
        // La dashboard e' accesa da sola quando l'utente e' davanti a un
        // terminale: e' il motivo per cui si lancia `--listen`, e senza si
        // vede solo il log. In tutti gli altri casi no, e i motivi sono due:
        //
        //  - `--json` / `--push`: sono sottoprocessi di netmonloc. Accendere
        //    qui aprirebbe una porta 9000 invisibile a chi ha lanciato il
        //    comando, e se due istanze girassero insieme la seconda farebbe
        //    fallire il bind con un errore che non sa spiegare.
        //  - nessun terminale: cron, systemd, CI, `> log.txt`. Qui non c'e'
        //    nessuno che legga una dashboard, e aprire un socket e' solo
        //    rumore che puo' far fallire il bind per un motivo invisibile.
        // Senza argomenti la dashboard e' quello che l'utente vuole: viene
        // richiesta esplicitamente, cosi' funziona anche se stdout non e' un
        // terminale (da un .bat, da un collegamento). Con `--listen` scritto
        // a mano resta l'euristica di prima, che la spegne in cron.
        let (do_dashboard, auto) = should_open_dashboard(
            dashboard_flag || senza_argomenti,
            no_dashboard,
            DashboardHeuristics {
                streaming: stream_cfg.is_some(),
                tty: logging::stdout_is_tty(),
            },
        );
        if senza_argomenti {
            avvisa_cambio_default(&logger, dashboard_port);
        }
        if auto {
            crate::bn!(
                "\x1b[34m[BLUESNIFF]\x1b[0m Dashboard web attivata automaticamente su \x1b[33mhttp://localhost:{dashboard_port}\x1b[0m"
            );
            crate::bn!(
                "[BLUESNIFF] Per spegnerla: --no-dashboard. Per aprire solo i dati: --json."
            );
            logger.log("listen: dashboard attivata automaticamente (TTY, nessuno streaming)");
        }
        run_listen(
            &logger,
            secs,
            prune_days,
            prune_min,
            heartbeat.as_ref(),
            ntfy_topic.as_deref(),
            ntfy_absence,
            do_dashboard,
            auto,
            dashboard_addr,
            dashboard_port,
            stream_cfg,
            passive,
        )
        .await
    } else if dashboard_flag {
        // Dashboard senza listen: parte comunque ma senza dati (nessun radio).
        run_dashboard_only(&logger, dashboard_addr, dashboard_port).await
    } else {
        bluetooth::scan(&logger).await
    };

    match result {
        Ok(()) => {
            logger.log("done");
            if !json_mode {
                crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Done.");
            }
            Ok(())
        }
        Err(e) => {
            logger.log(&format!("FATAL: {e}"));
            Err(e)
        }
    }
}

/// Avvisa che `bluesniff` senza argomenti non fa piu' lo scan di 5 secondi.
///
/// Il messaggio compare **solo se c'e' gia' un `presenze.csv` con righe**,
/// cioe' solo per chi ha gia' usato il comando come scanner. Per chi lo
/// prova per la prima volta l'avviso sarebbe solo rumore: non ha ancora un
/// comportamento da cui sentirsi tradito.
///
/// Una volta sola, non a ogni avvio: il fatto e' gia' successo e l'utente ha
/// gia' visto la riga. Per questo non si scrive nessun file di stato — se
/// l'avviso ricomparisse ogni volta, la prima cosa che farebbe un utente
/// sarebbe imparare a ignorare tutte le righe di avviso.
fn avvisa_cambio_default(logger: &Logger, dashboard_port: u16) {
    let csv = logging::exe_dir().join("presenze.csv");
    let ha_dati = std::fs::metadata(&csv)
        .map(|m| m.len() > 200)
        .unwrap_or(false);
    if !ha_dati {
        return;
    }
    logger.log("main: avviso cambio default (scan one-shot -> monitor + dashboard)");
    crate::bn!(
        "[33m[BLUESNIFF][0mNota: `bluesniff` da solo ora avvia il monitor continuo con la dashboard su http://localhost:{dashboard_port}."
    );
    crate::bn!("[BLUESNIFF] Per lo scan di 5 secondi come prima: [33mbluesniff --one-shot[0m");
}

/// One-shot BLE + LAN side-by-side correlation report.
async fn run_correlate(logger: &Logger) -> Result<(), Box<dyn Error>> {
    let (ble, mdns) = tokio::join!(bluetooth::scan_collect(logger), mdns::listen(logger, 5));
    let mut ble = ble?;
    // Best-effort: read real device names over GATT for Samsung SmartThings
    // phones (e.g. "Galaxy A41 di Salvatore") so name/vendor matching works.
    bluetooth::enrich_names(logger, &mut ble).await;
    let lan_devices = finish_lan_discovery(logger, mdns.hostnames).await;
    correlate::report(logger, &ble, &lan_devices);
    Ok(())
}

/// Co-movement sampling: initial discovery, then repeated BLE RSSI + LAN
/// presence samples correlated over time.
async fn run_track(logger: &Logger, seconds: u64) -> Result<(), Box<dyn Error>> {
    logger.log(&format!("track: sampling for {seconds}s"));
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Tracking for {seconds}s...");

    let (ble, mdns) = tokio::join!(bluetooth::scan_collect(logger), mdns::listen(logger, 5));
    let mut ble = ble?;
    // Best-effort: read real device names over GATT for Samsung SmartThings
    // phones (e.g. "Galaxy A41 di Salvatore") so name/vendor matching works.
    bluetooth::enrich_names(logger, &mut ble).await;
    let lan_devices = finish_lan_discovery(logger, mdns.hostnames).await;
    let subnets = lan::local_subnets();

    track::run(logger, &ble, &lan_devices, seconds, &subnets).await
}

/// Persistent sampling: like `--track` but appends every sample to a CSV time
/// series (`bluesniff.csv` next to the exe) instead of computing Phi in memory.
/// `seconds` = Some(duration) or None to run until Ctrl+C.
async fn run_record(logger: &Logger, seconds: Option<u64>) -> Result<(), Box<dyn Error>> {
    match seconds {
        Some(s) => {
            logger.log(&format!("record: sampling for {s}s"));
            crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Recording for {s}s...");
        }
        None => {
            logger.log("record: sampling until Ctrl+C");
            crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Recording until Ctrl+C...");
        }
    }

    let (ble, mdns) = tokio::join!(bluetooth::scan_collect(logger), mdns::listen(logger, 5));
    let mut ble = ble?;
    // Best-effort: read real device names over GATT for Samsung SmartThings
    // phones (e.g. "Galaxy A41 di Salvatore") so name/vendor matching works.
    bluetooth::enrich_names(logger, &mut ble).await;
    let lan_devices = finish_lan_discovery(logger, mdns.hostnames).await;

    let path = logging::exe_dir().join("bluesniff.csv");
    logger.log(&format!("record: writing CSV to {}", path.display()));
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m CSV: {}", path.display());

    let subnets = lan::local_subnets();
    track::record(logger, &ble, &lan_devices, seconds, &path, &subnets).await
}

/// Real-time classifier: same sampling loop as `--record` but instead of
/// writing CSV it compares the IP timeline with the BLE timeline and prints
/// a match whenever an IP appears and a BLE fingerprint turns on (or the
/// reverse) within a +/-5 minute window, with the BLE staying in the new state.
async fn run_classify(
    logger: &Logger,
    seconds: Option<u64>,
    netmonloc: Option<&str>,
    macfile: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    match seconds {
        Some(s) => {
            logger.log(&format!("classify: sampling for {s}s"));
            crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Classifying for {s}s...");
        }
        None => {
            logger.log("classify: sampling until Ctrl+C");
            crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Classifying until Ctrl+C...");
        }
    }

    let (ble, mdns) = tokio::join!(bluetooth::scan_collect(logger), mdns::listen(logger, 5));
    let mut ble = ble?;
    // Best-effort: read real device names over GATT for Samsung SmartThings
    // phones so name/vendor matching works.
    bluetooth::enrich_names(logger, &mut ble).await;
    let lan_devices = finish_lan_discovery(logger, mdns.hostnames).await;
    let subnets = lan::local_subnets();
    // mac.txt default: next to the exe (netmonloc's inventory file).
    let mac_file = match macfile {
        Some(p) => Some(std::path::PathBuf::from(p)),
        None => {
            let p = logging::exe_dir().join("mac.txt");
            if p.exists() {
                Some(p)
            } else {
                None
            }
        }
    };
    let netmonloc_file = netmonloc.map(std::path::PathBuf::from);
    track::classify(
        logger,
        &ble,
        &lan_devices,
        seconds,
        &subnets,
        netmonloc_file.as_deref(),
        mac_file.as_deref(),
    )
    .await
}

/// LAN discovery after the mDNS listen: active ARP sweep, NetBIOS Node Status
/// sweep, ARP-table capture (attaching mDNS + NetBIOS names) and OUI vendor
/// resolution.
async fn finish_lan_discovery(
    logger: &Logger,
    mdns_hostnames: HashMap<IpAddr, Vec<String>>,
) -> Vec<lan::LanDevice> {
    let subnets = lan::local_subnets();
    logger.log(&format!("ARP sweep over {} local subnet(s)", subnets.len()));
    let alive = lan::arp_sweep(&subnets);
    logger.log(&format!(
        "ARP sweep: {} host(s) answered at layer 2",
        alive.len()
    ));

    let netbios = nbtns::sweep(&alive, 3000);
    logger.log(&format!("NetBIOS: {} host(s) named", netbios.len()));
    for (ip, names) in &netbios {
        logger.log(&format!("netbios {ip} name=\"{}\"", names.join(",")));
    }

    // Merge mDNS + NetBIOS names per IP.
    let mut hostnames = mdns_hostnames;
    for (ip, names) in netbios {
        let entry = hostnames.entry(ip).or_default();
        for name in names {
            if !entry.contains(&name) {
                entry.push(name);
            }
        }
    }

    let mut lan_devices = lan::capture(&hostnames);

    // OUI vendor for the non-randomised MACs.
    let macs: Vec<String> = lan_devices.iter().map(|d| d.mac.clone()).collect();
    let vendors = vendor::resolve_vendors(logger, &macs).await;
    for d in &mut lan_devices {
        if d.vendor.is_empty() {
            if let Some(v) = vendors.get(&d.mac) {
                if !v.is_empty() {
                    d.vendor = v.clone();
                }
            }
        }
    }

    lan_devices
}

/// Usage text printed when the exe is run with no arguments.
/// Larghezza della colonna dei comandi, in caratteri **visibili**.
///
/// Il padding si calcola qui e non sui byte della stringa colorata: `bn!`
/// toglie i codici ANSI quando stdout non e' un terminale, e un padding
/// calcolato sul testo colorato lascerebbe le colonne disallineate esattamente
/// nel caso in cui l'output finisce in un file o in una pipe — cioe' proprio
/// dove nessuno se ne accorge.
const COL_COMANDO: usize = 40;

/// Oltre questa lunghezza visibile la descrizione sfora il terminale, e
/// l'utente deve scorrere orizzontalmente per leggerla. Su un terminale da
/// 80 colonne il difetto e' invisibile finche' non lo si guarda in uno
/// stretto: meglio che sia un test a dirlo.
///
/// La usa solo il test: in produzione nessuno legge l'help da codice, e
/// tenere la costante dichiarata qui evita al test di ridefinire un numero
/// che deve restare quello vero.
#[cfg_attr(not(test), allow(dead_code))]
const COL_MAX: usize = 100;

/// Aggiunge una riga "comando + descrizione" all'help.
///
/// Se il comando e' piu' lungo della colonna la descrizione va a capo: un
/// allineamento al millimetro non vale una riga che si legge male.
fn riga_comando(out: &mut String, comando: &str, descrizione: &str) {
    out.push_str("  ");
    out.push_str(comando);
    if comando.chars().count() >= COL_COMANDO {
        out.push_str(&" ".repeat(COL_COMANDO));
        out.push('\n');
        out.push_str("    ");
        out.push_str(descrizione);
        out.push('\n');
        return;
    }
    out.push_str(&" ".repeat(COL_COMANDO - comando.chars().count()));
    out.push_str(descrizione);
    out.push('\n');
}

/// Titolo di sezione: blu e grassetto, preceduto da una riga vuota che lo
/// stacca dalla sezione precedente.
fn sezione(out: &mut String, titolo: &str) {
    out.push('\n');
    out.push_str("\x1b[34m\x1b[1m");
    out.push_str(titolo);
    out.push_str("\x1b[0m\n");
}

/// Riga di nota, grigia.
///
/// Grigio e non giallo perche' una nota non e' un'istruzione: colorata di
/// giallo sembrerebbe cliccabile, e l'utente la copierebbe come se fosse un
/// comando.
fn nota(out: &mut String, testo: &str) {
    out.push_str("  \x1b[90m");
    out.push_str(testo);
    out.push_str("\x1b[0m\n");
}

/// Riga colorata come un comando ma senza descrizione: serve per l'input da
/// stdin, che non e' un flag ma si comporta come uno.
fn riga_semplice(out: &mut String, testo: &str, descrizione: &str) {
    out.push_str("  \x1b[33m");
    out.push_str(testo);
    out.push_str("\x1b[0m");
    out.push_str(&" ".repeat(COL_COMANDO.saturating_sub(testo.chars().count())));
    out.push_str(descrizione);
    out.push('\n');
}

fn intestazione_help(out: &mut String) {
    out.push_str("\x1b[34m\x1b[1mbluesniff\x1b[0m ");
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push_str(" — chi e' vicino al tuo PC, e da quanto tempo.\n");
}

/// Le cinque righe per cui vale la pena aprire questo tool.
///
/// Fanno tre cose diverse e sono ordinate cosi': trovare, guardare, capire.
/// Chi arriva dal README e vuole "solo provarlo" non deve leggere trenta flag
/// per capire che gli basta il primo.
fn sezione_uso_rapido(out: &mut String) {
    sezione(out, "USO RAPIDO");
    riga_comando(
        out,
        "bluesniff",
        "Dashboard su localhost:9000 (monitor continuo)",
    );
    riga_comando(
        out,
        "bluesniff --one-shot",
        "Scan BLE di 5 secondi, una volta sola, poi esce",
    );
    riga_comando(
        out,
        "bluesniff --listen",
        "Monitor continuo (anche senza dashboard)",
    );
    riga_comando(
        out,
        "bluesniff --inq",
        "Diagnostica la radio (BLE + Classic)",
    );
    riga_comando(
        out,
        "bluesniff --doctor",
        "Verifica radio, firewall e file di configurazione",
    );
}

/// Help completo.
///
/// Costruisce una `String` invece di stampare riga per riga: cosi' `cargo
/// test` puo' controllarlo (che le sezioni ci siano, che nessuna riga sfori il
/// terminale) senza dover catturare stdout.
pub fn usage() -> String {
    let mut o = String::new();
    intestazione_help(&mut o);
    sezione_uso_rapido(&mut o);

    sezione(&mut o, "COMANDI PRINCIPALI");
    riga_comando(&mut o, "--one-shot", "Scan BLE di 5 secondi");
    riga_comando(&mut o, "--listen [secs]", "Monitor continuo (presenze.csv)");
    riga_comando(
        &mut o,
        "--record [secs]",
        "Serie storica BLE+LAN (bluesniff.csv)",
    );
    riga_comando(&mut o, "--overnight", "8 ore di registrazione");
    riga_comando(
        &mut o,
        "--track <secs>",
        "Report co-movimento BLE/LAN (phi)",
    );
    riga_comando(&mut o, "--correlate", "Abbinamento BLE/LAN una tantum");
    riga_comando(
        &mut o,
        "--classify [secs]",
        "Classificatore BLE/IP in tempo reale",
    );
    riga_comando(
        &mut o,
        "--inq [secs]",
        "Diagnostica radio; senza secs: continuo",
    );
    riga_comando(&mut o, "--inq-json", "Come --inq, ma in JSON (per script)");
    riga_comando(&mut o, "--learn", "Elenca i dispositivi Classic noti");
    riga_comando(&mut o, "--connect <MAC>", "Ispeziona un dispositivo (GATT)");
    riga_comando(
        &mut o,
        "--patterns [csv]",
        "Analizza i pattern da presenze.csv",
    );
    riga_comando(
        &mut o,
        "--static [csv]",
        "Falsi positivi: statici e MAC rotanti",
    );
    riga_comando(
        &mut o,
        "--reset-radio [secs]",
        "Spegne e riaccende la radio BT",
    );
    riga_comando(&mut o, "--doctor", "Diagnosi: radio, BLE, firewall, file");
    riga_comando(
        &mut o,
        "--doctor --fix",
        "Applica i rimedi automatici sicuri",
    );
    riga_comando(&mut o, "--edit-known", "Apre bt_known.txt nell'editor");

    sezione(&mut o, "SCELTA DEI DISPOSITIVI");
    riga_comando(
        &mut o,
        "--follow <MAC> [--name <nome>]",
        "Aggiungi a bt_known.txt (notifiche)",
    );
    riga_comando(&mut o, "--unfollow <MAC>", "Togli il MAC da bt_known.txt");
    riga_comando(
        &mut o,
        "--list-followed",
        "Elenca i seguiti, con nome e persona",
    );
    riga_comando(
        &mut o,
        "--ignore <MAC>",
        "Nascondi il dispositivo (ignore.txt)",
    );
    riga_comando(&mut o, "--unignore <MAC>", "Toglilo dagli ignorati");
    riga_comando(
        &mut o,
        "--unignore-all",
        "Svuota ignore.txt (i commenti restano)",
    );
    riga_comando(&mut o, "--list-ignored", "Elenca gli ignorati");

    sezione(&mut o, "CON --listen");
    riga_comando(&mut o, "--dashboard", "Accendi la dashboard web");
    riga_comando(
        &mut o,
        "--no-dashboard",
        "Spegnila (gia' accesa in un terminale)",
    );
    riga_comando(&mut o, "--dashboard-port <N>", "Porta HTTP (default 9000)");
    riga_comando(
        &mut o,
        "--dashboard-addr <IP|lan>",
        "Rete: lan = 0.0.0.0 (default 127.0.0.1)",
    );
    riga_comando(&mut o, "--passive", "Scansione passiva (nessun SCAN_REQ)");
    riga_comando(
        &mut o,
        "--radio <idx|MAC|nome>",
        "Scegli la radio (se ne hai piu' di una)",
    );
    riga_comando(&mut o, "--no-rawlog", "Spegni il log per-pacchetto");
    riga_comando(
        &mut o,
        "--prune-days <N>",
        "Cancella righe piu' vecchie di N giorni",
    );
    riga_comando(
        &mut o,
        "--prune-min-sightings <N>",
        "Cancella anche i dispositivi con < N avvistamenti",
    );
    riga_comando(
        &mut o,
        "--heartbeat <url>[,secs]",
        "POST periodico a un uptime monitor",
    );
    riga_comando(&mut o, "--netmonloc", "Dati LAN da confrontare con il BLE");

    sezione(&mut o, "NOTIFICHE (ntfy)");
    riga_comando(
        &mut o,
        "--ntfy <topic>",
        "Topic ntfy.sh per gli avvisi push",
    );
    riga_comando(
        &mut o,
        "--ntfy-absence <N>",
        "Probe assenti prima dell'avviso (default 3)",
    );
    riga_comando(
        &mut o,
        "--ntfy-test <topic>",
        "Manda una notifica di prova ed esce",
    );
    riga_comando(
        &mut o,
        "--ntfy-server <url>",
        "Server ntfy (default https://ntfy.sh)",
    );
    nota(
        &mut o,
        "Prima di fidarti, testa: --ntfy-test dice perche' una notifica non arriva.",
    );

    sezione(&mut o, "STREAMING (per script e netmonloc)");
    riga_comando(&mut o, "--json", "Una riga NDJSON per ciclo su stdout");
    riga_comando(
        &mut o,
        "--push <url>",
        "POST di ogni ciclo a un endpoint HTTP",
    );
    riga_comando(
        &mut o,
        "--push-token <tok>",
        "Header X-Api-Token per --push",
    );
    riga_comando(&mut o, "--macfile <path>", "Elenco MAC da classificare");
    nota(
        &mut o,
        "Con --json o --push presenze.csv NON viene scritto, e la dashboard no.",
    );

    sezione(&mut o, "CONTROLLO DI UN PROCESSO IN ESECUZIONE");
    riga_comando(
        &mut o,
        "--status",
        "PID, uptime, radio, cicli del processo attivo",
    );
    riga_comando(&mut o, "--pause", "Metti in pausa la sua scansione");
    riga_comando(&mut o, "--resume", "Riprendila");
    riga_comando(&mut o, "--stop", "Fermalo in modo pulito (file flushati)");
    riga_comando(
        &mut o,
        "--snapshot",
        "Stampa l'ultimo snapshot (serve --json)",
    );
    nota(
        &mut o,
        "Funzionano anche senza terminale: da un .bat, da Task Scheduler, da uno script.",
    );
    nota(
        &mut o,
        "Nessun processo attivo -> messaggio e codice 1. I file sono accanto all'eseguibile.",
    );

    sezione(&mut o, "DALLA DASHBOARD (scorciatoie da tastiera)");
    riga_semplice(&mut o, "q", "Esci");
    riga_semplice(&mut o, "stop", "Pausa la scansione");
    riga_semplice(&mut o, "start", "Riprendi la scansione");
    riga_semplice(&mut o, "snapshot", "Stampa l'ultimo snapshot (con --json)");
    riga_semplice(&mut o, "clear", "Pulisci lo schermo");
    riga_semplice(&mut o, "n", "Apre le notifiche ntfy");

    help_report(&mut o);
    pie_page(&mut o);
    o
}

/// La sezione report dentro l'help generale.
///
/// Il report ha sette flag suoi: una sezione dedicata invece di sciorliarli
/// fra le opzioni avanzate e' quello che permette a chi cerca `--report-open`
/// di arrivarci con un colpo d'occhio.
fn help_report(o: &mut String) {
    sezione(o, "REPORT HTML (un file da condividere)");
    riga_comando(o, "--report", "Genera il report di presenza e lo scrive");
    riga_comando(o, "--report-last <1h|6h|1d|1w>", "Solo gli ultimi N");
    riga_comando(o, "--report-from <RFC3339>", "Inizio intervallo");
    riga_comando(
        o,
        "--report-to <RFC3339>",
        "Fine intervallo (default: adesso)",
    );
    riga_comando(o, "--report-output <path>", "Dove scriverlo");
    riga_comando(o, "--report-anonymize", "Maschera i MAC, per condividerlo");
    riga_comando(o, "--report-no-appendix", "Esclude la tabella completa");
    riga_comando(o, "--report-open", "Apre il file nel browser");
}

fn pie_page(o: &mut String) {
    sezione(o, "ALTRO");
    riga_comando(o, "-h, --help", "Questo aiuto");
    riga_comando(o, "-V, --version", "La versione");
    riga_comando(o, "--listen --help", "Aiuto solo su --listen");
    riga_comando(o, "--inq --help", "Aiuto solo su --inq");
    riga_comando(o, "--report --help", "Aiuto solo su --report");
    o.push('\n');
    o.push_str("  Documentazione: \x1b[36mREADME.md\x1b[0m accanto all'eseguibile\n");
}

/// Help contestuale: `bluesniff --listen --help`.
///
/// Vale la pena perche' `--listen` ha un sacco di opzioni e la maggior parte
/// sono sue: chi scrive `--listen --ntfy` non vuole vedere le opizioni del
/// report. Si mostra il comando, le sue opzioni, e un rimando al resto.
pub fn usage_for(flag: &str) -> String {
    // Un flag senza sezione propria non deve lasciare l'utente senza
    // risposta: si dà l'help intero.
    if !matches!(flag, "--listen" | "--inq" | "--report") {
        return usage();
    }
    let mut o = String::new();
    match flag {
        "--listen" => {
            intestazione_help(&mut o);
            o.push_str("\x1b[34m\x1b[1mbluesniff --listen\x1b[0m — monitor continuo.\n\n");
            o.push_str("  Apre il radio BLE a intervalli e scrive ogni dispositivo\n");
            o.push_str("  in presenze.csv. Ogni 60s interroga i telefoni in bt_known.txt\n");
            o.push_str("  via Bluetooth Classic, e le notifiche scattano sui seguiti.\n");
            o.push_str("  In un terminale la dashboard si accende da sola.\n");
            sezione(&mut o, "USO");
            riga_comando(&mut o, "bluesniff --listen", "Fino a Ctrl+C (o q)");
            riga_comando(&mut o, "bluesniff --listen 3600", "Per un'ora, poi esce");
            sezione(&mut o, "OPZIONI");
            riga_comando(&mut o, "--dashboard", "Accendi la dashboard web");
            riga_comando(&mut o, "--no-dashboard", "Spegnila");
            riga_comando(&mut o, "--dashboard-port <N>", "Porta HTTP (default 9000)");
            riga_comando(&mut o, "--dashboard-addr <IP|lan>", "Rete: lan = 0.0.0.0");
            riga_comando(&mut o, "--passive", "Scansione passiva");
            riga_comando(&mut o, "--ntfy <topic>", "Topic ntfy per gli avvisi");
            riga_comando(&mut o, "--radio <idx|MAC|nome>", "Scegli la radio");
            riga_comando(&mut o, "--prune-days <N>", "Pulisci presenze.csv");
            riga_comando(&mut o, "--no-rawlog", "Spegni il log per-pacchetto");
            pie_page_breve(&mut o);
        }
        "--inq" => {
            intestazione_help(&mut o);
            o.push_str("\x1b[34m\x1b[1mbluesniff --inq\x1b[0m — la radio funziona?\n\n");
            o.push_str("  Conta i pacchetti BLE in pochi secondi e lancia un'inquiry\n");
            o.push_str("  Classic. E' il primo comando da provare quando --listen non\n");
            o.push_str("  registra niente.\n");
            sezione(&mut o, "USO");
            riga_comando(&mut o, "bluesniff --inq", "Diagnosi e esce");
            riga_comando(
                &mut o,
                "bluesniff --inq 30",
                "Inquiry Classic per 30 secondi",
            );
            riga_comando(&mut o, "bluesniff --inq-json", "In JSON, per script");
            sezione(&mut o, "COME SI LEGGE");
            nota(&mut o, "0 BLE + 0 Classic  ->  la radio non riceve");
            nota(
                &mut o,
                "0 BLE + Classic ok ->  canale LE muto: --reset-radio",
            );
            nota(&mut o, "BLE ok, 0 Classic  ->  nessun dispositivo vicino");
            pie_page_breve(&mut o);
        }
        "--report" => {
            intestazione_help(&mut o);
            o.push_str("\x1b[34m\x1b[1mbluesniff --report\x1b[0m — un file da mandare via.\n\n");
            o.push_str("  Genera un report HTML autonomo: nessuna risorsa esterna,\n");
            o.push_str("  si apre in qualsiasi browser, anche offline, e si stampa.\n");
            help_report(&mut o);
            pie_page_breve(&mut o);
        }
        _ => {}
    }
    o
}

fn pie_page_breve(o: &mut String) {
    o.push('\n');
    o.push_str("  Per il resto: \x1b[36mbluesniff --help\x1b[0m\n");
}

/// Stampa l'help. `bn!` toglie i colori se stdout non e' un terminale, e il
/// padding resta corretto perche' e' calcolato sul testo nudo.
pub fn print_usage() {
    crate::bn!("{}", usage());
}

/// Parse `--dashboard-addr <ip>` (default 127.0.0.1). The shortcut `lan`
/// (or `0.0.0.0`) binds to every interface so the dashboard is reachable
/// from the intranet.
fn parse_dashboard_addr(args: &[String]) -> std::net::IpAddr {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--dashboard-addr" {
            if let Some(v) = it.next() {
                if v.eq_ignore_ascii_case("lan") || v == "0.0.0.0" {
                    return std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
                }
                if let Ok(ip) = v.parse() {
                    return ip;
                }
            }
        }
        if let Some(v) = arg.strip_prefix("--dashboard-addr=") {
            if v.eq_ignore_ascii_case("lan") || v == "0.0.0.0" {
                return std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
            }
            if let Ok(ip) = v.parse() {
                return ip;
            }
        }
    }
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

/// Parse `--flag <u64>`.
fn parse_u64_arg(args: &[String], flag: &str) -> Option<u64> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == flag {
            return it.next().and_then(|s| s.parse().ok());
        }
        if let Some(v) = arg.strip_prefix(&format!("{flag}=")) {
            return v.parse().ok();
        }
    }
    None
}

/// Parse `--heartbeat <url>[,<interval_secs>]`.
fn parse_heartbeat_arg(args: &[String]) -> Option<(String, u64)> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--heartbeat" {
            let v = it.next()?;
            return Some(split_heartbeat(v));
        }
        if let Some(v) = arg.strip_prefix("--heartbeat=") {
            return Some(split_heartbeat(v));
        }
    }
    None
}

fn split_heartbeat(v: &str) -> (String, u64) {
    match v.split_once(',') {
        Some((url, secs)) => (url.to_string(), secs.parse().unwrap_or(300)),
        None => (v.to_string(), 300),
    }
}

/// `--listen`: pure passive/active recorder. Every 10 s the BLE radio opens
/// for 8 s and every unique device seen is appended to `presenze.csv`
/// (semicolon-delimited, RFC3339 UTC first column). Every 60 s the known
/// phones are actively paged (Bluetooth Classic). `bt_known.txt` next to the
/// exe lists the known phones (`BTMAC;Nome;Persona`); if missing it is
/// bootstrapped from the OS-remembered devices.
///
/// bluehood-ported ops: `--prune-days`/`--prune-min-sightings` trim old rows
/// before starting, `--heartbeat` pings an uptime monitor, `--ntfy` enables
/// watched-device arrival/departure push notifications.
//
// I parametri sono uno per uno i flag della riga di comando: raggrupparli in una
// struct non renderebbe la mappatura flag -> campo piu' leggibile di cosi'.
#[allow(clippy::too_many_arguments)]
async fn run_listen(
    logger: &Logger,
    seconds: Option<u64>,
    prune_days: Option<u64>,
    prune_min: Option<u64>,
    heartbeat: Option<&(String, u64)>,
    ntfy_topic: Option<&str>,
    ntfy_absence: usize,
    dashboard: bool,
    // True se la dashboard l'abbiamo accesa noi invece che l'utente: decide
    // il tono dell'errore se il bind fallisce.
    dashboard_auto: bool,
    dashboard_addr: std::net::IpAddr,
    dashboard_port: u16,
    stream: Option<crate::stream::StreamConfig>,
    passive: bool,
) -> Result<(), Box<dyn Error>> {
    // In modalità --json lo stdout è riservato all'NDJSON: i banner umani
    // vanno solo nel log.
    let quiet_json = stream.as_ref().is_some_and(|c| c.json);
    match seconds {
        Some(s) => {
            logger.log(&format!("listen: sampling for {s}s"));
            if !quiet_json {
                crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Listening for {s}s...");
            }
        }
        None => {
            logger.log("listen: sampling until Ctrl+C or 'q'");
            if !quiet_json {
                crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Listening until Ctrl+C or 'q'... (stop/start/clear)");
            }
        }
    }

    let known_path = logging::exe_dir().join("bt_known.txt");
    let mut known = btclassic::load_bt_known(&known_path);
    if known.is_empty() {
        logger.log(&format!(
            "listen: no usable bt_known.txt at {}, bootstrapping from remembered devices",
            known_path.display()
        ));
        let remembered = btclassic::remembered_devices();
        if !remembered.is_empty() {
            btclassic::write_bootstrap(&known_path, &remembered);
            logger.log(&format!(
                "listen: wrote {} remembered device(s) to {} — fill in the Persona column",
                remembered.len(),
                known_path.display()
            ));
            // Il file appena creato e' pieno di MAC senza nome, e senza questo
            // messaggio l'utente non ha modo di sapere che esiste: vede il
            // file e non capisce cosa farne. Lo diciamo a schermo, non solo
            // nel log (che scorre via e non si legge).
            if !quiet_json {
                crate::bn!();
                crate::bn!("\x1b[33m[BLUESNIFF] ═══════════════════════════════════════════════════════\x1b[0m");
                crate::bn!("\x1b[33m[BLUESNIFF]  Ho creato bt_known.txt con {} dispositivi che il PC ricorda.\x1b[0m", remembered.len());
                crate::bn!("\x1b[33m[BLUESNIFF]  Per ricevere notifiche devi scegliere chi seguire:\x1b[0m");
                // "dalla dashboard" solo se la dashboard è aperta: senza, è un
                // consiglio che rimanda a una pagina che non esiste.
                if dashboard {
                    crate::bn!("\x1b[33m[BLUESNIFF]  · dalla dashboard: clicca il dispositivo → ⭐ Segui\x1b[0m");
                }
                crate::bn!(
                    "\x1b[33m[BLUESNIFF]  · da file: apri {} e riempi la colonna Persona\x1b[0m",
                    known_path.display()
                );
                crate::bn!(
                    "\x1b[33m[BLUESNIFF]  · bluesniff --edit-known apre il file nell'editor\x1b[0m"
                );
                crate::bn!("\x1b[33m[BLUESNIFF] ═══════════════════════════════════════════════════════\x1b[0m");
                crate::bn!();
            }
        }
        known = btclassic::load_bt_known(&known_path);
        if known.is_empty() {
            logger.log("listen: no known phones to probe (active phase idle)");
        }
    } else {
        logger.log(&format!(
            "listen: {} known phone(s) loaded from {}",
            known.len(),
            known_path.display()
        ));
        for k in &known {
            logger.log(&format!(
                "listen: known {} nome=\"{}\" persona=\"{}\"",
                k.mac, k.nome, k.persona
            ));
        }
    }

    // Streaming (netmonloc): i dati passano via chiamate (stdout NDJSON e/o
    // POST HTTP), presenze.csv non viene scritto.
    let stream_handle = match &stream {
        Some(cfg) if cfg.active() => {
            let push_tx = cfg.push_url.as_ref().map(|url| {
                crate::stream::spawn_pusher(logger.clone(), url.clone(), cfg.push_token.clone())
            });
            Some(crate::stream::StreamHandle {
                cfg: cfg.clone(),
                push_tx,
            })
        }
        _ => None,
    };

    let path = logging::exe_dir().join("presenze.csv");
    if stream_handle.is_some() {
        logger.log("listen: streaming mode (netmonloc) — presenze.csv not written");
    } else {
        logger.log(&format!("listen: writing presenze to {}", path.display()));
        if !quiet_json {
            crate::bn!(
                "\x1b[34m[BLUESNIFF]\x1b[0m Presenze CSV: {}",
                path.display()
            );
        }
    }

    // Ops: prune old sightings before starting (bluehood storage rotation),
    // solo senza streaming (in streaming non esiste presenze.csv).
    if let Some(days) = prune_days {
        let known_macs: std::collections::HashSet<String> =
            known.iter().map(|k| k.mac.to_uppercase()).collect();
        if stream_handle.is_some() {
            logger.log("listen: --prune-days ignored in streaming mode (no presenze.csv)");
        } else {
            match ops::prune_presenze(
                logger,
                &path,
                days,
                prune_min.unwrap_or(0) as usize,
                &known_macs,
            ) {
                Ok((kept, dropped)) => {
                    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Pruned: kept {kept}, dropped {dropped}");
                }
                Err(e) => {
                    logger.log(&format!("listen: prune failed (non-fatal): {e}"));
                }
            }
        }
    }

    // Ops: heartbeat check-ins (bluehood heartbeat).
    if let Some((url, interval)) = heartbeat {
        // Il logger e' condiviso: il thread dedicato ne prende una copia.
        ops::spawn_heartbeat(logger.clone(), url.clone(), *interval);
        logger.log(&format!("listen: heartbeat every {}s -> {}", interval, url));
    }

    // Alerts: watched-device push notifications via ntfy.sh.
    let ntfy_cfg = match ntfy_topic {
        Some(topic) if !topic.is_empty() => Some(alerts::NtfyConfig {
            topic: topic.to_string(),
            server: "https://ntfy.sh".to_string(),
        }),
        _ => alerts::NtfyConfig::load_default(),
    };
    if let Some(cfg) = &ntfy_cfg {
        logger.log(&format!(
            "listen: ntfy alerts enabled (topic={})",
            cfg.topic
        ));
    }
    let mut alert_tracker = alerts::AlertTracker::new(ntfy_cfg, ntfy_absence, logger.clone());

    // Live dashboard: stato condiviso + server HTTP. Le impostazioni ntfy
    // sono condivise con AlertTracker: la web UI le modifica a runtime.
    let dashboard_state = if dashboard {
        let state = dashboard::new_state_with(Some(path.clone()));
        // Imposta la modalità passive se richiesta.
        state
            .passive
            .store(passive, std::sync::atomic::Ordering::Relaxed);
        if let Some(topic) = ntfy_topic.filter(|t| !t.is_empty()) {
            if let Ok(mut s) = state.ntfy.write() {
                s.topic = topic.to_string();
                s.enabled = true;
            }
        }
        alert_tracker.set_runtime_settings(state.ntfy.clone());
        match dashboard::spawn_server(logger, state.clone(), dashboard_addr, dashboard_port) {
            Ok(()) => {
                // Comodità: apri subito il browser di default sulla dashboard
                // locale. Solo se il bind è riuscito: aprire un browser su una
                // porta morta fa aprire una scheda "connessione rifiutata" e
                // sembra un bug.
                if dashboard_addr.is_loopback() || dashboard_addr.is_unspecified() {
                    open_dashboard_browser(dashboard_port);
                }
            }
            Err(e) => report_dashboard_start(logger, dashboard_port, dashboard_auto, &e),
        }
        Some(state)
    } else {
        None
    };

    // mDNS Service Discovery: annuncia la dashboard nella rete locale.
    // Il ServiceDaemon va mantenuto in vita: se viene droppato l'annuncio cessa.
    let _mdns_daemon = if dashboard {
        match mdns_register::start_mdns_responder(logger, dashboard_port) {
            Ok(daemon) => {
                // Lo segniamo: la dashboard promette "annunciato" solo se il
                // daemon e' davvero partito, e al riavvio e' l'unico posto dove
                // questa informazione si forma.
                share::set_mdns_live(true);
                crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m mDNS: servizio annunciato nella rete locale (_blusniff._tcp.local.)");
                Some(daemon)
            }
            Err(e) => {
                logger.log(&format!("mDNS register: errore non fatale: {e}"));
                None
            }
        }
    } else {
        None
    };

    // La riga di contesto del PID file: `--status` la mostra, ed e' l'unica
    // cosa che distingue "ascolto da 6 ore" da "ascolto da 6 ore con la
    // dashboard e le notifiche accese".
    let ctl_context = {
        let mut v = vec!["listen".to_string()];
        if let Some(s) = seconds {
            v.push(s.to_string());
        }
        if dashboard {
            v.push("--dashboard".to_string());
        }
        if stream.is_some() {
            v.push("--json/--push".to_string());
        }
        if passive {
            v.push("--passive".to_string());
        }
        if let Some(t) = ntfy_topic.filter(|t| !t.is_empty()) {
            v.push(format!("--ntfy {t}"));
        }
        v.join(" ")
    };

    listen::listen(
        logger,
        seconds,
        &path,
        known,
        &mut alert_tracker,
        dashboard_state,
        stream_handle,
        passive,
        &ctl_context,
    )
    .await
}

/// Apre il browser di default sulla dashboard all'avvio (best-effort).
fn open_dashboard_browser(port: u16) {
    let url = format!("http://localhost:{port}");
    #[cfg(windows)]
    {
        // `cmd /C start <url>`: apre il browser di default senza bloccare.
        use std::process::Command;
        let _ = Command::new("cmd").args(["/C", "start", "", &url]).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    }
}

/// Dashboard senza `--listen`: avvia solo il server HTTP (nessun dato BLE).
async fn run_dashboard_only(
    logger: &Logger,
    dashboard_addr: std::net::IpAddr,
    dashboard_port: u16,
) -> Result<(), Box<dyn Error>> {
    logger.log("dashboard-only: serving without listen (no BLE data)");
    let state = dashboard::new_state_with(Some(logging::exe_dir().join("presenze.csv")));
    if let Err(e) = dashboard::spawn_server(logger, state, dashboard_addr, dashboard_port) {
        // Qui la dashboard è sempre stata richiesta esplicitamente: l'errore
        // secco è quello che l'utente si aspetta.
        crate::be!("[BLUESNIFF] dashboard: {e}");
    }
    if !dashboard_addr.is_loopback() {
        let addrs = lan::local_ipv4_addrs();
        logger.log(&format!(
            "dashboard condivisa in rete su: {}",
            addrs
                .iter()
                .map(|a| format!("{a}:{dashboard_port}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Dashboard-only mode: press Ctrl+C to stop.");
    // Comodità: apri subito il browser di default sulla dashboard locale.
    open_dashboard_browser(dashboard_port);

    // mDNS Service Discovery: annuncia la dashboard nella rete locale.
    let _mdns_daemon = match mdns_register::start_mdns_responder(logger, dashboard_port) {
        Ok(daemon) => {
            share::set_mdns_live(true);
            crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m mDNS: servizio annunciato nella rete locale (_blusniff._tcp.local.)");
            Some(daemon)
        }
        Err(e) => {
            logger.log(&format!("mDNS register: errore non fatale: {e}"));
            None
        }
    };
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// `--learn`: one-shot helper to fill `bt_known.txt`. Lists the devices
/// Windows remembers (paired/authenticated) and runs an inquiry to discover
/// nearby Bluetooth Classic devices, with names when resolved.
async fn run_learn(logger: &Logger) -> Result<(), Box<dyn Error>> {
    logger.log("learn: listing remembered/paired devices");
    let remembered = btclassic::remembered_devices();
    crate::bn!(
        "\x1b[34m[BLUESNIFF]\x1b[0m Remembered/paired devices ({}):",
        remembered.len()
    );
    for d in &remembered {
        let nome = if d.nome.is_empty() {
            "<no name>".to_string()
        } else {
            d.nome.clone()
        };
        crate::bn!("  {}  {}  [{}]", d.mac, nome, d.flags);
        logger.log(&format!(
            "learn remembered {} name=\"{}\" class=0x{:06X} flags={}",
            d.mac, d.nome, d.class_of_device, d.flags
        ));
    }

    logger.log("learn: running inquiry (~7s)");
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Running inquiry (~7s)...");
    let found = btclassic::inquiry(5);
    crate::bn!(
        "\x1b[34m[BLUESNIFF]\x1b[0m Discoverable devices found ({}):",
        found.len()
    );
    for d in &found {
        let nome = if d.nome.is_empty() {
            "<no name>".to_string()
        } else {
            d.nome.clone()
        };
        crate::bn!("  {}  {}", d.mac, nome);
        logger.log(&format!(
            "learn discoverable {} name=\"{}\" class=0x{:06X}",
            d.mac, d.nome, d.class_of_device
        ));
    }
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Add the phones to bt_known.txt as BTMAC;Nome;Persona");
    Ok(())
}

/// `--inq [seconds]`: radio diagnostic. With a duration it runs one cycle
/// (radios + 5 s BLE packet window + Classic GIAC inquiry); without arguments
/// it becomes a continuous monitor that repeats the cycle and prints only
/// changes (new devices, gone devices, BLE packets) until `q` / Ctrl+C.
/// With `json` set, stdout carries one machine-readable JSON line per cycle
/// (also appended to `inq_events.jsonl` for the dashboard).
async fn run_inq(logger: &Logger, secs: Option<u64>, json: bool) -> Result<(), Box<dyn Error>> {
    match secs {
        Some(secs) => run_inq_once(logger, secs, json).await,
        None => run_inq_monitor(logger, 15, json).await,
    }
}

/// Cosa sappiamo dell'ambiente in cui gira `--listen`.
///
/// È un struct e non tre bool sciolti nella firma perché sono una terna che
/// va letta insieme: "TTY" da solo non basta a spiegare la scelta, e
/// accorparli rende illeggibile il punto in cui viene deciso.
pub struct DashboardHeuristics {
    /// `--json` o `--push` attivi: il comando gira come sottoprocesso.
    pub streaming: bool,
    /// stdout è un terminale: c'è una persona davanti.
    pub tty: bool,
}

/// Dice all'utente che la dashboard non è partita, con il tono giusto.
///
/// La distinzione è "chi ha fatto la scelta". Se l'utente ha scritto
/// `--dashboard`, un errore secco è esattamente quello che vuole leggere. Se
/// l'abbiamo accesa noi, un `cannot bind` sembrerebbe un guasto di bluesniff
/// per qualcosa che lui non ha chiesto: in quel caso la riga resta in secondo
/// piano e gli diciamo come rimediare, ricordando che la scansione continua a
/// funzionare e che può anche spegnerla del tutto.
fn report_dashboard_start(logger: &Logger, port: u16, auto: bool, err: &str) {
    if auto {
        logger.log(&format!("dashboard: non partita in automatico: {err}"));
        // Non diciamo "porta in uso": l'Err puo' essere anche un set_nonblocking
        // fallito. Riportiamo la causa vera e stiamo sul fatto importante.
        crate::bn!(
            "\x1b[33m[BLUESNIFF]\x1b[0m Dashboard non aperta: {err}. La scansione continua normalmente."
        );
        // La porta suggerita e' quella subito dopo: se l'utente ne aveva
        // scelta una a caso, dirgli "9001" sarebbe un consiglio falso.
        crate::bn!(
            "[BLUESNIFF] Per averla: --dashboard-port {}. Per non averla: --no-dashboard.",
            port as u32 + 1
        );
    } else {
        crate::be!("[BLUESNIFF] dashboard: {err}");
    }
}

/// Decide se `--listen` deve aprire la dashboard da solo.
///
/// Ritorna anche se è stata accesa **automaticamente**, perché l'utente deve
/// poter sapere che la decisione non è stata sua.
///
/// `--no-dashboard` vince sempre: se l'utente lo scrive, l'ha già deciso.
fn should_open_dashboard(
    explicit: bool,
    no_dashboard: bool,
    env: DashboardHeuristics,
) -> (bool, bool) {
    if no_dashboard {
        return (false, false);
    }
    if explicit {
        return (true, false);
    }
    if env.tty && !env.streaming {
        return (true, true);
    }
    (false, false)
}

/// `--edit-known`: apre `bt_known.txt` nell'editor predefinito di sistema.
///
/// Il file puo' stare in una cartella di Program Files o in una dir di test
/// dove l'utente non ha idea di cercarlo: dire "apri bt_known.txt" senza
/// dire dove e' costringe a mettere in pausa la scansione e andare a cercare
/// il file a mano. Qui glielo apriamo noi.
///
/// Se il file non esiste lo creiamo con l'intestazione: meglio un file vuoto
/// con le intestazioni delle colonne che un "file mancante", che l'utente
/// leggerebbe come un errore.
fn run_edit_known(logger: &Logger) -> Result<(), Box<dyn Error>> {
    let path = crate::known::path();
    if !path.exists() {
        std::fs::write(
            &path,
            "# BTMAC;Nome;Persona  (fill in the Persona column)\n",
        )?;
    }
    logger.log(&format!("edit-known: opening {}", path.display()));
    crate::bn!(
        "\x1b[34m[BLUESNIFF]\x1b[0m Apro \x1b[33m{}\x1b[0m nell'editor predefinito...",
        path.display()
    );

    #[cfg(windows)]
    {
        // `cmd /C start "" <path>` apre il file con il programma associato
        // ai .txt senza mettere in pausa bluesniff: `start` con il secondo
        // argomento vuoto e' quello che evita che il percorso venga
        // interpretato come titolo della finestra.
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &path.to_string_lossy()])
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(&path).spawn();
    }

    crate::bn!("[BLUESNIFF] Riga per riga: MAC;Nome;Persona — la Persona finisce nelle notifiche.");
    crate::bn!("[BLUESNIFF] Salva il file e riavvia --listen. Oppure usa ⭐ Segui dalla dashboard: vale subito, senza riavvio.");
    Ok(())
}

/// Parsa una durata tipo `90m`, `6h`, `1d`, `1w` in secondi.
///
/// Solo suffissi e numero: accettare anche `1 hour` o `1 giorno` sarebbe
/// tolleranza per una sintassi che nessuno scrive. Un valore non riconosciuto
/// e' un errore esplicito, non un `None` silenzioso: `--report-last 1x` deve
/// dire che `1x` non esiste, altrimenti l'utente crede di avere un report
/// dell'ultimo secondo.
fn parse_duration_secs(s: &str) -> Result<i64, String> {
    let t = s.trim().to_lowercase();
    let (num, unit) = t.split_at(t.len().saturating_sub(1));
    let n: i64 = num
        .parse()
        .map_err(|_| format!("durata non valida: \"{s}\" (esempi: 90m, 6h, 1d, 1w)"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 7 * 86_400,
        _ => {
            return Err(format!(
                "durata non valida: \"{s}\" (unita' ammesse: s m h d w)"
            ))
        }
    };
    if n <= 0 {
        return Err(format!("durata non valida: \"{s}\" (deve essere positiva)"));
    }
    Ok(n * mult)
}

/// `bluesniff --ntfy-test <topic>`: manda una notifica di prova e stampa
/// l'esito, poi esce.
///
/// Serve a risolvere il dubbio che blocca il 90% degli utenti: *ho
/// configurato tutto, ma non arriva niente*. Il motivo della mancata
/// notifica e' quasi sempre uno di tre — topic diverso nell'app (maiuscole
/// contano), notifiche del telefono silenziate, dispositivo non in
/// `bt_known.txt` — e nessuno dei tre si scopre aspettando che qualcuno
/// arrivi o se ne vada.
///
/// L'invio e' `await` sul runtime del main, diversamente da `AlertTracker`:
/// qui il comando esce subito, non c'e' nessun watcher WinRT in ascolto da
/// rallentare, e la paura documentata in `alerts.rs` (reqwest sul runtime
/// condiviso che blocca il loop di scansione) non si applica.
///
/// Quale comando di controllo richiede l'utente, se nessuno. `--snapshot` ha
/// una funzione separata perche' il suo risultato e' un JSON da stampare, non
/// una conferma.
fn control_command(
    pause: bool,
    resume: bool,
    stop: bool,
    status: bool,
) -> Option<control::Control> {
    // `--pause` vince su `--resume`: se un utente li scrive entrambi vuol
    // dire "ferma", e l'ordine delle righe sulla riga di comando non deve
    // cambiare il risultato.
    if stop {
        Some(control::Control::Stop)
    } else if pause {
        Some(control::Control::Pause)
    } else if resume {
        Some(control::Control::Resume)
    } else if status {
        Some(control::Control::Status)
    } else {
        None
    }
}

/// `--pause` / `--resume` / `--stop` / `--status`: parla con il bluesniff gia'
/// in esecuzione e esce.
///
/// Il codice di uscita e' 1 quando non c'e' nessun processo da controllare o
/// quando non risponde: uno script che lancia `--stop` deve poter fallire se
/// il fermo non e' avvenuto, altrimenti proseguirebbe convinto che il PC non
/// stia piu' osservando.
///
/// `snapshot` cambia il modo di stampare: il risultato e' il JSON, non una
/// conferma. Lo metto qui perche' i due percorsi hanno bisogno dello stesso
/// `exit(1)`.
async fn run_control_flag(
    logger: &Logger,
    cmd: control::Control,
    snapshot: bool,
) -> Result<(), Box<dyn Error>> {
    let out = if cmd == control::Control::Status {
        // `query_status` e' sincrono perche' parla con un file: non c'e' nessun
        // I/O di rete da aspettare, e in un processo che sta solo facendo
        // questo un `thread::sleep` e' equivalente a un `sleep` async.
        control::query_status(logger)
    } else if snapshot {
        control::fetch_snapshot(logger).await
    } else {
        control::send_to_running(cmd, logger, std::time::Duration::from_secs(3)).await
    };
    // Solo se il messaggio non lo dice gia': `--status` riporta il PID come
    // prima riga, e ripeterlo sopra sarebbe rumore.
    if let Some(pid) = out.pid.filter(|_| !out.message.contains("PID:")) {
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Processo trovato (PID {pid}).");
    }
    if out.ok {
        crate::bn!(
            "\x1b[32m[BLUESNIFF]\x1b[0m \u{2713} {}\u{1b}[0m",
            out.message
        );
    } else {
        crate::bn!(
            "\x1b[31m[BLUESNIFF]\x1b[0m \u{2717} {}\u{1b}[0m",
            out.message
        );
        std::process::exit(1);
    }
    Ok(())
}

async fn run_ntfy_test(logger: &Logger, topic: &str, server: &str) -> Result<(), Box<dyn Error>> {
    if let Err(e) = alerts::validate_topic(topic) {
        crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m {e}");
        return Ok(());
    }
    if let Err(e) = alerts::validate_server(server) {
        crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m {e}");
        return Ok(());
    }
    let topic = topic.trim();
    let server = server.trim();
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC".to_string());
    // Nessun MAC e nessun dato di `presenze.csv`: il messaggio dice solo che
    // e' un test e da quale stazione arriva.
    let msg = format!(
        "Test di bluesniff\nSe vedi questo messaggio sul telefono, le notifiche funzionano.\nStazione: {host}"
    );
    let url = format!("{}/{}", server.trim_end_matches('/'), topic);
    logger.log(&format!("ntfy test: invio a {url}"));
    crate::bn!(
        "\x1b[34m[BLUESNIFF]\x1b[0m Invio notifica di test a \x1b[33m{topic}\x1b[0m ({server})..."
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let esito = {
        match client
            .post(&url)
            .header("Title", "bluesniff")
            .header("Tags", "test")
            .body(msg)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => Ok(resp.status().as_u16()),
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                Err(format!(
                    "ntfy ha risposto {status}: {}",
                    body.chars().take(200).collect::<String>()
                ))
            }
            // I tre casi hanno rimedi diversi: un timeout e' quasi sempre un firewall o
            // una rete lenta, una connessione rifiutata e' un server spento o
            // un indirizzo sbagliato, il resto (DNS, TLS) e' il messaggio
            // stesso di reqwest, che dice gia' il dominio che ha fallito.
            Err(e) => Err(if e.is_timeout() {
                format!("timeout dopo 10s ({e})")
            } else if e.is_connect() {
                format!("connessione fallita ({e})")
            } else {
                e.to_string()
            }),
        }
    };
    match esito {
        Ok(code) => {
            logger.log(&format!("ntfy test: ok ({code})"));
            crate::bn!(
                "\x1b[32m[BLUESNIFF]\x1b[0m ✓ Notifica inviata (HTTP {code}). Controlla l'app ntfy sul telefono."
            );
            crate::bn!("[BLUESNIFF]   Se non la vedi, nell'ordine: sei iscritto al topic \"{topic}\" nell'app (le maiuscole contano)? Le notifiche del telefono sono attive? Il dispositivo che ti interessa è in bt_known.txt?");
        }
        Err(e) => {
            logger.log(&format!("ntfy test: errore {e}"));
            crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m ✗ Invio fallito: {e}");
            if e.starts_with("timeout") {
                crate::bn!("[BLUESNIFF]   Il server non ha risposto in 10 secondi: controlla la connessione o l'indirizzo del server.");
            } else if e.starts_with("connessione") || e.contains("refused") {
                crate::bn!("[BLUESNIFF]   Nessuno ha risposto su questo indirizzo: il server e' spento, o un firewall blocca la connessione in uscita.");
            }
        }
    }
    Ok(())
}

/// `bluesniff --report`: costruisce il report HTML e lo scrive su disco.
///
/// Il file non dipende dalla dashboard e non la tocca: si puo' generare a
/// fine giornata, a PC spento, da un'altra macchina. Tutti i dati arrivano da
/// file, quindi qui non c'e' niente di asincrono e il report di una giornata
/// intera si genera in qualche decina di millisecondi.
fn run_report(logger: &Logger, args: &[String]) -> Result<(), Box<dyn Error>> {
    let cfg_args = parse_report_args(args)?;
    let report = report::build(&cfg_args.config)?;
    let html = report::render_html(&report);
    let stamp = crate::logging::rfc3339_millis(report.generated_ms)
        .get(0..16)
        .unwrap_or("")
        .replace(['-', ':'], "")
        .replace('T', "-");
    let path = cfg_args.output.unwrap_or_else(|| {
        crate::logging::exe_dir().join(format!("bluesniff-report-{stamp}.html"))
    });
    std::fs::write(&path, &html)?;
    let size_kb = html.len() / 1024;
    logger.log(&format!(
        "report: scritto {} ({} KB, {} dispositivi, {} eventi, anonimo={})",
        path.display(),
        size_kb,
        report.all_devices.len(),
        report.events.len(),
        report.anonymize
    ));
    crate::bn!(
        "\x1b[33m[BLUESNIFF]\x1b[0m Report scritto in \x1b[1m{}\x1b[0m ({} KB).",
        path.display(),
        size_kb
    );
    crate::bn!(
        "[BLUESNIFF] {} {}",
        report.counts.total_unique,
        "dispositivi unici."
    );
    if report.empty {
        crate::bn!(
            "[BLUESNIFF] Nessun dato nell'intervallo: il report lo dice in cima, non e' un errore."
        );
    }
    if cfg_args.open {
        open_in_browser(&path);
    }
    Ok(())
}

/// Apre un file con l'associazione di sistema, senza fermare bluesniff.
fn open_in_browser(path: &std::path::Path) {
    #[cfg(windows)]
    {
        // Come `--edit-known`: il secondo argomento vuoto evita che il
        // percorso venga interpretato come titolo della finestra.
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &path.to_string_lossy()])
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

/// Opzioni di `--report`, gia' valide.
struct ReportArgs {
    config: report::ReportConfig,
    output: Option<std::path::PathBuf>,
    open: bool,
}

/// Parsa e valida i flag `--report*`.
///
/// La validazione e' tutta qui e restituisce un errore di stringa: main la
/// trasforma in un'uscita con codice 1 e un messaggio. Un `--report-last xyz`
/// silenziosamente ignorato produrrebbe un report dell'intervallo sbagliato,
/// che e' il modo piu' subdolo di sbagliare: il file si apre, sembra giusto,
/// e descrive il periodo sbagliato.
fn parse_report_args(args: &[String]) -> Result<ReportArgs, String> {
    let flag = |name: &str| -> bool { args.iter().skip(1).any(|a| a == name) };
    let value = |name: &str| -> Option<String> {
        let mut i = 1;
        while i < args.len() {
            if args[i] == name {
                return args.get(i + 1).filter(|v| !v.starts_with("--")).cloned();
            }
            if let Some(v) = args[i].strip_prefix(&format!("{name}=")) {
                return Some(v.to_string());
            }
            i += 1;
        }
        None
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let from_ms = match value("--report-from") {
        Some(v) => Some(
            logging::parse_rfc3339_millis(&v)
                .ok_or_else(|| format!("--report-from non e' un timestamp RFC3339: \"{v}\""))?,
        ),
        None => None,
    };
    let to_ms = match value("--report-to") {
        Some(v) => Some(
            logging::parse_rfc3339_millis(&v)
                .ok_or_else(|| format!("--report-to non e' un timestamp RFC3339: \"{v}\""))?,
        ),
        None => None,
    };
    // `--report-last` e' una scorciatoia: "le ultime N" significa che l'inizio
    // si calcola a ritroso dalla fine. Se l'utente ha dato anche `--report-to`,
    // e' quella la fine: altrimenti "le ultime 24 ore" diventerebbero 24 ore
    // fino a un istante sbagliato, e con `--report-to` esplicito sarebbe
    // chiaramente un fraintendimento.
    let last_secs = match value("--report-last") {
        Some(v) => Some(parse_duration_secs(&v)?),
        None => None,
    };
    let (from_ms, to_ms) = match (last_secs, to_ms) {
        (Some(secs), to) => {
            let end = to.unwrap_or(now_ms);
            (Some(end - secs * 1000), to.or(Some(end)))
        }
        (None, to) => (from_ms, to),
    };
    if from_ms.is_some() && to_ms.is_none() {
        return Err(
            "--report-from ha senso solo insieme a --report-to o --report-last: \
                    senza una fine, l'inizio da solo non definisce un intervallo."
                .to_string(),
        );
    }

    Ok(ReportArgs {
        config: report::ReportConfig {
            from_ms,
            to_ms,
            title: None,
            anonymize: flag("--report-anonymize"),
            full_appendix: !flag("--report-no-appendix"),
        },
        output: value("--report-output").map(std::path::PathBuf::from),
        open: flag("--report-open"),
    })
}

/// Errore di MAC condiviso dai comandi: il messaggio dice anche il formato
/// accettato, perche' "MAC non valido" da solo fa riscrivere il comando senza
/// capire quale dei tre formati accettati abbia sbagliato.
fn mac_arg_error(mac: &str) -> Box<dyn Error> {
    format!("MAC non valido: \"{mac}\" (atteso AA:BB:CC:DD:EE:FF)").into()
}

/// `--ignore <MAC>`: aggiunge alla lista nera.
fn run_ignore(logger: &Logger, mac: &str) -> Result<(), Box<dyn Error>> {
    if fsx::normalize_mac(mac).is_empty() {
        return Err(mac_arg_error(mac));
    }
    let path = ignore::path();
    let gia = ignore::is_ignored(&path, mac);
    ignore::ignore(&path, mac)?;
    logger.log(&format!("ignore: {mac} -> {}", path.display()));
    crate::bn!(
        "\x1b[33m[BLUESNIFF]\x1b[0m {} {} in {}",
        if gia { "Gia' ignorato:" } else { "Ignorato:" },
        fsx::normalize_mac(mac),
        path.display()
    );
    crate::bn!("[BLUESNIFF] Sparisce dalla tabella, ma le notifiche (se segue) continuano.");
    Ok(())
}

/// `--unignore <MAC>`: toglie dalla lista nera.
fn run_unignore(logger: &Logger, mac: &str) -> Result<(), Box<dyn Error>> {
    if fsx::normalize_mac(mac).is_empty() {
        return Err(mac_arg_error(mac));
    }
    let path = ignore::path();
    // `unfollow`-like: il risultato distingue "toccato" da "non c'era", e il
    // messaggio lo dice. Un no-op silenzioso sembrerebbe un comando rotto.
    let rimosso = ignore::unignore(&path, mac)?;
    logger.log(&format!("unignore: {mac} rimosso={rimosso}"));
    crate::bn!(
        "\x1b[33m[BLUESNIFF]\x1b[0m {}",
        if rimosso {
            format!("Togli l'ignore a {}", fsx::normalize_mac(mac))
        } else {
            format!("Non era ignorato: {}", fsx::normalize_mac(mac))
        }
    );
    Ok(())
}

/// `--unignore-all`: svuota `ignore.txt`, tenendo i commenti.
fn run_unignore_all(logger: &Logger) -> Result<(), Box<dyn Error>> {
    let path = ignore::path();
    let n = ignore::unignore_all(&path)?;
    logger.log(&format!("unignore-all: {n} rimossi da {}", path.display()));
    crate::bn!(
        "\x1b[33m[BLUESNIFF]\x1b[0m {n} dispositivi rimossi da {} (i commenti restano).",
        path.display()
    );
    Ok(())
}

/// `--list-ignored`: stampa la lista nera come il server la vede.
fn run_list_ignored(logger: &Logger) -> Result<(), Box<dyn Error>> {
    let path = ignore::path();
    let macs = ignore::load(&path);
    logger.log(&format!(
        "list-ignored: {} in {}",
        macs.len(),
        path.display()
    ));
    if macs.is_empty() {
        crate::bn!("[BLUESNIFF] Nessun dispositivo ignorato.");
    } else {
        crate::bn!("[BLUESNIFF] {} ignorati in {}:", macs.len(), path.display());
        for m in macs {
            crate::bn!("[BLUESNIFF]   {m}");
        }
    }
    Ok(())
}

/// `--follow <MAC> [--name <nome>]`: aggiunge a `bt_known.txt`.
fn run_follow(logger: &Logger, mac: &str, name: &str) -> Result<(), Box<dyn Error>> {
    if fsx::normalize_mac(mac).is_empty() {
        return Err(mac_arg_error(mac));
    }
    let path = known::path();
    let gia = known::is_followed(&path, mac);
    known::follow(&path, mac, name)?;
    logger.log(&format!("follow: {mac} -> {}", path.display()));
    crate::bn!(
        "\x1b[33m[BLUESNIFF]\x1b[0m {} {} in {}",
        if gia { "Gia' seguito:" } else { "Seguito:" },
        fsx::normalize_mac(mac),
        path.display()
    );
    if name.trim().is_empty() {
        crate::bn!("[BLUESNIFF] Nome vuoto: apri il file e riempi Nome e Persona (le notifiche usano il nome).");
    }
    Ok(())
}

/// `--unfollow <MAC>`: toglie la riga da `bt_known.txt`.
fn run_unfollow(logger: &Logger, mac: &str) -> Result<(), Box<dyn Error>> {
    if fsx::normalize_mac(mac).is_empty() {
        return Err(mac_arg_error(mac));
    }
    let path = known::path();
    let tolto = known::unfollow(&path, mac)?;
    logger.log(&format!("unfollow: {mac} tolto={tolto}"));
    crate::bn!(
        "\x1b[33m[BLUESNIFF]\x1b[0m {}",
        if tolto {
            format!("Non piu' seguito: {}", fsx::normalize_mac(mac))
        } else {
            format!("Non era seguito: {}", fsx::normalize_mac(mac))
        }
    );
    Ok(())
}

/// `--list-followed`: stampa `bt_known.txt` come il probe lo legge.
fn run_list_followed(logger: &Logger) -> Result<(), Box<dyn Error>> {
    let path = known::path();
    let list = known::list(&path);
    logger.log(&format!(
        "list-followed: {} in {}",
        list.len(),
        path.display()
    ));
    if list.is_empty() {
        crate::bn!("[BLUESNIFF] Nessun dispositivo seguito.");
        return Ok(());
    }
    crate::bn!("[BLUESNIFF] {} seguiti in {}:", list.len(), path.display());
    for k in list {
        // La Persona vuota e' la situazione normale dopo un follow dalla
        // dashboard: senza dirlo sembrerebbe un bug di chi non l'ha compilata.
        let persona = if k.persona.trim().is_empty() {
            "(persona non compilata)".to_string()
        } else {
            k.persona.clone()
        };
        let nome = if k.nome.trim().is_empty() {
            "(senza nome)"
        } else {
            k.nome.as_str()
        };
        crate::bn!("[BLUESNIFF]   {}  {}  {}", k.mac, nome, persona);
    }
    Ok(())
}

/// Ora corrente in formato HH:MM:SS (UTC) per il feed a colori.
fn hms_now() -> String {
    let t = crate::logging::utc_now_rfc3339();
    t.get(11..19).map(|s| s.to_string()).unwrap_or_default()
}

/// Append one event line to `inq_events.jsonl` next to the exe (capped at the
/// last 500 lines), the feed read by the dashboard's "Ultimi eventi" panel.
fn append_inq_event(line: &str) {
    use std::io::Write;
    let path = logging::exe_dir().join("inq_events.jsonl");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{line}");
    }
    if let Ok(content) = std::fs::read_to_string(&path) {
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() > 500 {
            let keep = lines[lines.len() - 500..].join("\n");
            let _ = std::fs::write(&path, format!("{keep}\n"));
        }
    }
}

/// `--reset-radio [secondi]`: spegne e riaccende la radio Bluetooth e
/// termina. È il recupero di primo soccorso quando lo scanner LE è muto
/// (0 pacchetti) ma la radio risulta accesa: il driver viene riposizionato
/// senza riavviare il PC. Funziona anche a dashboard attiva, dal pulsante
/// "Reset radio" del pannello Radio.
async fn run_reset_radio(logger: &Logger, secs: u64) -> Result<(), Box<dyn Error>> {
    let (name, on) = crate::blewatcher::radio_status().await.unwrap_or_default();
    let stato = if on { "ON" } else { "OFF" };
    logger.log(&format!(
        "reset radio: richiesto su '{name}' (stato iniziale {stato}, off per {secs}s)"
    ));
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Radio Bluetooth: {name} ({stato})");
    crate::bn!("[BLUESNIFF] Reset in corso: spengo {secs}s, poi riaccendo...");

    match crate::blewatcher::reset_radio(secs).await {
        Ok(msg) => {
            logger.log(&format!("reset radio: ok, {msg}"));
            crate::bn!("\x1b[32m[BLUESNIFF]\x1b[0m ✔ {msg}");
            crate::bn!("[BLUESNIFF] Se lo scanner LE era muto, ora `--inq` dovrebbe contare pacchetti > 0.");
        }
        Err(e) => {
            // Non è un errore fatale dell'app: la radio potrebbe semplicemente
            // essere gestita da una policy di sistema. Lo diciamo e basta.
            logger.log(&format!("reset radio: fallito: {e}"));
            crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m ✖ Reset radio non riuscito: {e}");
        }
    }
    Ok(())
}

/// One-shot cycle of the `--inq` diagnostic:
/// 1) lists the Bluetooth radios with their power state,
/// 2) counts BLE advertisement packets received in a 5 s watcher window
///    (0 packets with the radio on means the radio is not receiving),
/// 3) runs a Classic GIAC inquiry for the requested duration.
///
/// With both BLE and Classic empty, the radio is almost certainly not
/// receiving physically (e.g. broken USB passthrough).
async fn run_inq_once(logger: &Logger, secs: u64, json: bool) -> Result<(), Box<dyn Error>> {
    logger.log(&format!("inq: radio diagnostic ({secs}s classic inquiry)"));

    // 1) Radios + power state.
    let radios = radio::list_radios();
    let (rt_name, rt_on) = crate::blewatcher::radio_status().await.unwrap_or_default();
    if !json && radios.is_empty() {
        crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m No Bluetooth radio reported by the OS.");
        logger.log("inq: no Bluetooth radio reported by the OS");
    } else if !json {
        for (i, r) in radios.iter().enumerate() {
            crate::bn!(
                "\x1b[34m[BLUESNIFF]\x1b[0m Radio[{}]: \x1b[33m{}\x1b[0m ({})",
                i + 1,
                r.address,
                r.name
            );
            logger.log(&format!(
                "inq radio[{}] name={} address={}",
                i + 1,
                r.name,
                r.address
            ));
        }
        let state = if rt_on { "ON" } else { "OFF" };
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m WinRT radio state: \x1b[33m{state}\x1b[0m ({rt_name})"
        );
        logger.log(&format!("inq winrt radio state={state} name={rt_name}"));
    }

    // 2) BLE packet counter over a 5 s watcher window.
    let before = crate::blewatcher::packets_received();
    let seen = crate::blewatcher::scan_window(std::time::Duration::from_secs(5), false).await;
    let after = crate::blewatcher::packets_received();
    let packets = after.saturating_sub(before);
    logger.log(&format!(
        "inq ble 5s packets={packets} unique={}",
        seen.len()
    ));

    // 3) Classic GIAC inquiry (each timeout unit = 1.28 s).
    let mult = (((secs as u128) * 100) / 128).clamp(1, 255) as u8;
    let found = tokio::task::spawn_blocking(move || btclassic::inquiry(mult))
        .await
        .unwrap_or_default();
    logger.log(&format!("inq classic found={}", found.len()));

    if !json {
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m BLE: {packets} packet(s) in 5s, {} unique device(s)",
            seen.len()
        );
        for s in &seen {
            for c in crate::cves::match_cves(
                crate::cves::db(),
                s.model_id,
                s.name.as_deref().unwrap_or(""),
                s.vendor.as_deref().unwrap_or(""),
                s.hint.as_deref().unwrap_or(""),
                &s.mac,
            ) {
                crate::bn!(
                    "  \x1b[31m[CVE] {}\x1b[0m  {}  {}  ({})",
                    c.cve,
                    s.mac,
                    s.name.as_deref().unwrap_or("<no name>"),
                    c.model
                );
                logger.log(&format!(
                    "inq CVE ble {} name=\"{}\" cve={}",
                    s.mac,
                    s.name.as_deref().unwrap_or(""),
                    c.cve
                ));
            }
        }
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m Classic devices found: {}",
            found.len()
        );
        for d in &found {
            let nome = if d.nome.is_empty() {
                "<no name>".to_string()
            } else {
                d.nome.clone()
            };
            crate::bn!(
                "  {}  {}  class=0x{:06X} [{}]",
                d.mac,
                nome,
                d.class_of_device,
                d.flags.trim()
            );
            for c in crate::cves::match_cves(crate::cves::db(), None, &nome, "", "", &d.mac) {
                crate::bn!("  \x1b[31m[CVE] {}\x1b[0m  {}  ({})", c.cve, d.mac, c.model);
                logger.log(&format!(
                    "inq CVE classic {} name=\"{}\" cve={}",
                    d.mac, nome, c.cve
                ));
            }
        }
        if found.is_empty() && packets == 0 {
            crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m Nothing received on BLE or Classic: the radio is likely not receiving physically.");
            crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m Check the USB passthrough (Proxmox: qm set <VM> --usb0 host=<bus>:<dev>) and try Windows Settings > Bluetooth > Add device.");
        } else if found.is_empty() {
            crate::bn!("\x1b[33m[BLUESNIFF]\x1b[0m BLE traffic received but no discoverable Classic devices: normal if nothing nearby is in discoverable mode.");
        }
    } else {
        let classic: Vec<serde_json::Value> = found
            .iter()
            .map(|d| {
                serde_json::json!({
                    "type": "classic",
                    "mac": d.mac,
                    "name": d.nome,
                    "class": format!("0x{:06X}", d.class_of_device),
                })
            })
            .collect();
        let line = serde_json::json!({
            "event": "inquiry",
            "ts": crate::logging::utc_now_rfc3339(),
            "packets": packets,
            "ble_unique": seen.len(),
            "classic_found": classic,
            "radio_on": rt_on,
        });
        append_inq_event(&line.to_string());
        crate::bn!("{line}");
    }
    Ok(())
}

/// Continuous monitor: repeats BLE packet window + Classic inquiry every
/// ~`interval_secs` and prints only changes: new devices (`[+]`), devices
/// gone for 3 cycles (`[-]`) and BLE packet counts when non-zero. A silent
/// radio prints nothing — the silence is the signal. Stop with `q` / Ctrl+C.
async fn run_inq_monitor(
    logger: &Logger,
    interval_secs: u64,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    logger.log("inq: continuous monitor started");
    let radios = radio::list_radios();
    let (rt_name, rt_on) = crate::blewatcher::radio_status().await.unwrap_or_default();
    if !json {
        if radios.is_empty() {
            crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m No Bluetooth radio reported by the OS.");
        } else {
            for (i, r) in radios.iter().enumerate() {
                crate::bn!(
                    "\x1b[34m[BLUESNIFF]\x1b[0m Radio[{}]: \x1b[33m{}\x1b[0m ({})",
                    i + 1,
                    r.address,
                    r.name
                );
            }
        }
        let state_s = if rt_on { "ON" } else { "OFF" };
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m Monitor inquiry: ciclo ~{interval_secs}s · radio {state_s} ({rt_name}) · premi \x1b[33mq\x1b[0m per fermare"
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.store(true, Ordering::Relaxed);
        });
    }
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().eq_ignore_ascii_case("q") {
                    shutdown.store(true, Ordering::Relaxed);
                    break;
                }
            }
        });
    }

    let mut known: HashMap<String, String> = HashMap::new();
    let mut absent: HashMap<String, u32> = HashMap::new();
    let mut last_rssi: HashMap<String, i16> = HashMap::new();
    let mut cycle = 0u64;
    let mut total_packets = 0u64;
    let mut total_new = 0u64;

    // Feed colorato: in modalità json va su stderr (stdout resta JSON puro).
    let feed = |line: String| {
        if json {
            crate::be!("{line}");
        } else {
            crate::bn!("{line}");
        }
    };

    while !shutdown.load(Ordering::Relaxed) {
        cycle += 1;
        let ts = hms_now();
        let before = crate::blewatcher::packets_received();
        let ble = crate::blewatcher::scan_window(std::time::Duration::from_secs(5), false).await;
        let after = crate::blewatcher::packets_received();
        let packets = after.saturating_sub(before);
        total_packets += packets;

        let mult = (((interval_secs as u128) * 100) / 128).clamp(1, 255) as u8;
        let found = tokio::task::spawn_blocking(move || btclassic::inquiry(mult))
            .await
            .unwrap_or_default();

        let mut seen_now: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut new_devs: Vec<serde_json::Value> = Vec::new();
        for d in &found {
            seen_now.insert(d.mac.clone());
            if !known.contains_key(&d.mac) {
                let nome = if d.nome.is_empty() {
                    "<no name>".to_string()
                } else {
                    d.nome.clone()
                };
                known.insert(d.mac.clone(), nome.clone());
                let cves = crate::cves::match_cves(crate::cves::db(), None, &nome, "", "", &d.mac);
                if !cves.is_empty() {
                    for c in &cves {
                        feed(format!(
                            "\x1b[31m[CVE]\x1b[0m [{ts}] classic  {}  {}  — \x1b[31m{}\x1b[0m ({})",
                            d.mac, nome, c.cve, c.model
                        ));
                        logger.log(&format!(
                            "inq monitor CVE classic {} name=\"{}\" cve={}",
                            d.mac, nome, c.cve
                        ));
                    }
                }
                new_devs.push(serde_json::json!({
                    "type": "classic",
                    "mac": d.mac,
                    "name": nome,
                    "class": format!("0x{:06X}", d.class_of_device),
                    "cves": cves,
                }));
                feed(format!(
                    "\x1b[32m[+]\x1b[0m [{ts}] classic  {}  {}  class=0x{:06X}",
                    d.mac, nome, d.class_of_device
                ));
                logger.log(&format!(
                    "inq monitor new classic {} name=\"{}\" class=0x{:06X}",
                    d.mac, d.nome, d.class_of_device
                ));
                total_new += 1;
            }
        }
        let mut rssi_updates: Vec<serde_json::Value> = Vec::new();
        for s in &ble {
            seen_now.insert(s.mac.clone());
            if !known.contains_key(&s.mac) {
                let nome = s.name.clone().unwrap_or_else(|| "<no name>".to_string());
                known.insert(s.mac.clone(), nome.clone());
                let cves = crate::cves::match_cves(
                    crate::cves::db(),
                    s.model_id,
                    s.name.as_deref().unwrap_or(""),
                    s.vendor.as_deref().unwrap_or(""),
                    s.hint.as_deref().unwrap_or(""),
                    &s.mac,
                );
                if !cves.is_empty() {
                    for c in &cves {
                        feed(format!(
                            "\x1b[31m[CVE]\x1b[0m [{ts}] ble      {}  {}  — \x1b[31m{}\x1b[0m ({})",
                            s.mac, nome, c.cve, c.model
                        ));
                        logger.log(&format!(
                            "inq monitor CVE ble {} name=\"{}\" cve={}",
                            s.mac, nome, c.cve
                        ));
                    }
                }
                new_devs.push(serde_json::json!({
                    "type": "ble",
                    "mac": s.mac,
                    "name": nome,
                    "class": "",
                    "cves": cves,
                }));
                feed(format!(
                    "\x1b[32m[+]\x1b[0m [{ts}] ble      {}  {}",
                    s.mac, nome
                ));
                logger.log(&format!(
                    "inq monitor new ble {} name=\"{}\"",
                    s.mac,
                    s.name.as_deref().unwrap_or("")
                ));
                total_new += 1;
            }
            // Cambiamenti di segnale dei dispositivi già noti (≥ 5 dB):
            // finiscono nel feed e in `rssi_updates` della riga JSON.
            if let Some(r) = s.rssi {
                match last_rssi.get(&s.mac) {
                    Some(&old) if (old - r).abs() >= 5 => {
                        let nome = s.name.clone().unwrap_or_else(|| "<no name>".to_string());
                        rssi_updates.push(serde_json::json!({
                            "type": "ble",
                            "mac": s.mac,
                            "name": nome,
                            "from": old,
                            "to": r,
                        }));
                        feed(format!(
                            "\x1b[36m[~]\x1b[0m [{ts}] rssi     {}  {}  {} → {} dBm",
                            s.mac, nome, old, r
                        ));
                        logger.log(&format!("inq monitor rssi {} {}→{} dBm", s.mac, old, r));
                    }
                    _ => {}
                }
                last_rssi.insert(s.mac.clone(), r);
            }
        }
        // Rilevamento spam BLE (solo difensivo): conteggia gli annunci
        // "popup/phantom" (Apple Continuity, Swift Pair, Samsung Easy
        // Setup) nella finestra e i Model ID Fast Pair visti da più MAC
        // distinti (firma di spoof/rotazione MAC). Soglie conservative:
        // un singolo annuncio Fast Pair è normalissimo (qualsiasi earbud
        // Android), il vero spammer produce burst o ripetizioni.
        let mut phantom_by_type: std::collections::HashMap<&'static str, usize> =
            std::collections::HashMap::new();
        let mut model_macs: std::collections::HashMap<u32, Vec<String>> =
            std::collections::HashMap::new();
        for s in &ble {
            if let Some(p) = s.phantom {
                *phantom_by_type.entry(p).or_insert(0) += 1;
            }
            if let Some(mid) = s.model_id {
                model_macs.entry(mid).or_default().push(s.mac.clone());
            }
        }
        // Annunci popup "hard" (quelli che generano dialoghi su iOS/Windows/
        // Samsung, più i Find My 0x12 usati dallo spam Flipper): escludiamo
        // fast-pair preso da solo, troppo comune.
        let popup_hard: usize = [
            "apple-popup",
            "apple-findmy",
            "swift-pair",
            "samsung-easysetup",
        ]
        .iter()
        .map(|k| phantom_by_type.get(k).copied().unwrap_or(0))
        .sum();
        // Stesso Model ID da >= 3 MAC distinti nella stessa finestra.
        let mut dup_models: Vec<serde_json::Value> = Vec::new();
        for (mid, macs) in &model_macs {
            let uniq: std::collections::HashSet<&String> = macs.iter().collect();
            if uniq.len() >= 3 {
                dup_models.push(serde_json::json!({
                    "model_id": mid,
                    "mac_distinti": uniq.len(),
                    "model": crate::cves::model_name(*mid).unwrap_or_else(|| mid.to_string()),
                }));
            }
        }
        let spam_burst = popup_hard >= 5;
        let spam_spoof = !dup_models.is_empty();
        if spam_burst || spam_spoof {
            let mut desc = String::new();
            if spam_burst {
                desc.push_str(&format!(
                    "burst di {popup_hard} annunci popup/phantom ({})",
                    phantom_by_type
                        .iter()
                        .filter(|(k, _)| **k != "fast-pair" && **k != "samsung-easysetup")
                        .map(|(k, v)| format!("{k}:{v}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
            if spam_spoof {
                if !desc.is_empty() {
                    desc.push_str("; ");
                }
                desc.push_str(&format!(
                    "{} Model ID da più MAC (possibile spoof Fast Pair)",
                    dup_models.len()
                ));
            }
            feed(format!(
                "\x1b[38;5;201m[SPAM]\x1b[0m [{ts}] posible spammer BLE nelle vicinanze — {desc}"
            ));
            logger.log(&format!("inq monitor SPAM detected: {desc}"));
        }
        let spam_json = serde_json::json!({
            "detected": spam_burst || spam_spoof,
            "popup_hard": popup_hard,
            "by_type": phantom_by_type,
            "dup_model_ids": dup_models,
        });

        // Dispositivi spariti da almeno 3 cicli.
        let mut gone_devs: Vec<serde_json::Value> = Vec::new();
        for (mac, name) in known.iter() {
            if seen_now.contains(mac) {
                absent.insert(mac.clone(), 0);
            } else {
                let streak = absent.entry(mac.clone()).or_insert(0);
                *streak += 1;
                if *streak == 3 {
                    gone_devs.push(serde_json::json!({"mac": mac, "name": name}));
                    feed(format!(
                        "\x1b[33m[-]\x1b[0m [{ts}] gone     {}  {}",
                        mac, name
                    ));
                }
            }
        }
        // La linea BLE si stampa solo quando la radio riceve qualcosa.
        if packets > 0 {
            feed(format!(
                "\x1b[34mBLE\x1b[0m  [{ts}] ciclo {cycle}: {packets} pacchetto/i, {} dispositivo/i unici",
                ble.len()
            ));
            logger.log(&format!(
                "inq monitor ciclo {cycle} ble packets={packets} unique={}",
                ble.len()
            ));
        }

        // Riga JSON machine-readable: sempre su stdout in modalità json, e
        // sempre nel file `inq_events.jsonl` per il pannello della dashboard.
        let rt = crate::blewatcher::radio_status().await.unwrap_or_default();
        let line = serde_json::json!({
            "event": "cycle",
            "ts": crate::logging::utc_now_rfc3339(),
            "cycle": cycle,
            "packets": packets,
            "ble_unique": ble.len(),
            "new_devices": new_devs,
            "gone_devices": gone_devs,
            "rssi_updates": rssi_updates,
            "radio_on": rt.1,
            "spam": spam_json,
        });
        append_inq_event(&line.to_string());
        if json {
            crate::bn!("{line}");
        }

        // Pausa per rispettare l'intervallo (il ciclo dura ~5s + inquiry).
        let spent = 5 + ((mult as u64) * 128) / 100;
        let left = interval_secs.saturating_sub(spent);
        if left > 0 && !shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(std::time::Duration::from_secs(left)).await;
        }
    }

    if !json {
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m Monitor fermato: {cycle} cicli, {total_new} nuovi dispositivi, {} totali, {total_packets} pacchetti BLE",
            known.len()
        );
    } else {
        let line = serde_json::json!({
            "event": "stop",
            "ts": crate::logging::utc_now_rfc3339(),
            "cycles": cycle,
            "new_devices_total": total_new,
            "devices_total": known.len(),
            "packets_total": total_packets,
        });
        append_inq_event(&line.to_string());
        crate::bn!("{line}");
    }
    logger.log(&format!(
        "inq monitor stopped: cycles={cycle} new={total_new} total={} packets={total_packets}",
        known.len()
    ));
    Ok(())
}

/// Parse `--flag [seconds]`: `Some(Some(secs))` with a duration, `Some(None)`
/// for a bare flag (run until Ctrl+C), or `None` when the flag is absent.
/// Parse a `--flag [value]` argument where the value is optional.
///
/// L'argomento e' **facoltativo**, quindi la forma `--inq` da sola e valida.
/// Il punto delicato e' non mangiare il flag successivo: `--inq --dashboard`
/// deve attivare la dashboard, non trattare `--dashboard` come valore di
/// `--inq` (che fallirebbe il parse e perderebbe il flag). Per questo si
/// guarda il token successivo **prima** di consumarlo, e lo si accetta solo se
/// e' un numero.
fn parse_optional_arg(args: &[String], flag: &str) -> Option<Option<u64>> {
    let flag_eq = format!("{flag}=");
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].clone();
        if let Some(v) = arg.strip_prefix(&flag_eq) {
            return Some(v.parse().ok());
        }
        if arg == flag {
            // Guarda avanti senza consumare: se il token successivo non e' un
            // numero (perche' e' un altro flag, o un valore non numerico) il
            // flag resta senza argomento e il token resta per chi legge dopo.
            return match args.get(i + 1) {
                Some(next) => Some(next.parse::<u64>().ok()),
                None => Some(None),
            };
        }
        i += 1;
    }
    None
}

/// Parse `--flag <MAC>` prendendo l'argomento successivo, ma solo se non e'
/// un altro flag.
///
/// Diversamente da `parse_path_arg`, che consuma il token dopo il flag: qui il
/// token successivo potrebbe essere `--unignore-all` (cioe' l'utente ha
/// dimenticato il MAC), e consumarlo lascerebbe l'utente con un comando
/// eseguito per sbaglio invece di un errore che gli spiega cosa manca.
fn parse_mac_arg(args: &[String], flag: &str) -> Option<String> {
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].clone();
        if let Some(v) = arg.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_string());
        }
        if arg == flag {
            return match args.get(i + 1) {
                Some(next) if !next.starts_with("--") => Some(next.clone()),
                _ => None,
            };
        }
        i += 1;
    }
    None
}

/// Parse a `--flag <value>` argument (path strings).
fn parse_path_arg(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == flag {
            return it.next().cloned();
        }
    }
    None
}

/// Parse a free-text selector argument, accepted both as `<flag> <value>` and
/// `<flag>=<value>`: used for `--radio <index|MAC|name>`.
fn parse_selector_arg(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == flag {
            return it.next().cloned();
        }
        if let Some(v) = arg.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn parse_connect_arg(args: &[String]) -> Option<String> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--connect" {
            return it.next().cloned();
        }
        if let Some(mac) = arg.strip_prefix("--connect=") {
            return Some(mac.to_string());
        }
    }
    None
}

fn parse_track_arg(args: &[String]) -> Option<u64> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--track" {
            return it.next().and_then(|s| s.parse().ok());
        }
        if let Some(v) = arg.strip_prefix("--track=") {
            return v.parse().ok();
        }
    }
    None
}

/// Parse `--record [seconds]`: `Some(Some(secs))` with a duration, `Some(None)`
/// for a bare `--record` (run until Ctrl+C), or `None` when the flag is absent.
fn parse_record_arg(args: &[String]) -> Option<Option<u64>> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--record" {
            return Some(it.next().and_then(|s| s.parse().ok()));
        }
        if let Some(v) = arg.strip_prefix("--record=") {
            return Some(v.parse().ok());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flag_senza_valore_interpreta_il_flag_successivo() {
        // Il bug che questo test presidia: `--inq --dashboard` consumava
        // `--dashboard` come argomento di `--inq`, quindi la dashboard non
        // partiva. E' un errore che non si vede in un test "sembra funzionare".
        let a = args(&["bluesniff", "--inq", "--dashboard"]);
        assert_eq!(parse_optional_arg(&a, "--inq"), Some(None));
        assert!(
            a.iter().any(|x| x == "--dashboard"),
            "il token successivo non deve essere consumato"
        );
    }

    #[test]
    fn flag_con_valore_numerico_lo_legge() {
        let a = args(&["bluesniff", "--inq", "30"]);
        assert_eq!(parse_optional_arg(&a, "--inq"), Some(Some(30)));
    }

    #[test]
    fn forma_con_uguale_ancora_funziona() {
        let a = args(&["bluesniff", "--inq=45", "--dashboard"]);
        assert_eq!(parse_optional_arg(&a, "--inq"), Some(Some(45)));
    }

    #[test]
    fn flag_assente_non_inventa_nulla() {
        let a = args(&["bluesniff", "--dashboard"]);
        assert_eq!(parse_optional_arg(&a, "--inq"), None);
    }

    #[test]
    fn un_valore_non_numerico_non_e_un_numero() {
        // `--inq abc` deve valere "senza valore", non `Some(Some(0))`: il
        // chiamante distingue i due casi.
        let a = args(&["bluesniff", "--inq", "abc"]);
        assert_eq!(parse_optional_arg(&a, "--inq"), Some(None));
    }

    fn env(streaming: bool, tty: bool) -> DashboardHeuristics {
        DashboardHeuristics { streaming, tty }
    }

    #[test]
    fn la_dashboard_si_accende_da_sola_con_un_terminale() {
        // Il caso comune: un utente lancia --listen e guarda il terminale.
        assert_eq!(
            should_open_dashboard(false, false, env(false, true)),
            (true, true)
        );
    }

    #[test]
    fn lo_streaming_non_accende_mai_la_dashboard() {
        // netmonloc lancia `--listen --json` come sottoprocesso: accendere
        // aprirebbe una porta 9000 invisibile, e se due istanze girassero la
        // seconda farebbe fallire il bind con un errore incomprensibile.
        assert_eq!(
            should_open_dashboard(false, false, env(true, true)),
            (false, false)
        );
    }

    #[test]
    fn senza_terminale_la_dashboard_resta_spenta() {
        // cron, systemd, CI, `> log.txt`: nessuno guarda una dashboard e il
        // bind potrebbe fallire per un motivo che l'utente non vede.
        assert_eq!(
            should_open_dashboard(false, false, env(false, false)),
            (false, false)
        );
    }

    #[test]
    fn no_dashboard_vince_sempre() {
        // Anche con --dashboard esplicito: --no-dashboard è l'ultima parola.
        assert_eq!(
            should_open_dashboard(true, true, env(false, true)),
            (false, false)
        );
        assert_eq!(
            should_open_dashboard(false, true, env(false, true)),
            (false, false)
        );
    }

    #[test]
    fn il_flag_esplicito_e_ma_non_e_mai_uno_spoiler() {
        // Se l'utente ha scritto --dashboard, non gli si dice "attivata
        // automaticamente": la decisione è stata sua.
        assert_eq!(
            should_open_dashboard(true, false, env(true, false)),
            (true, false)
        );
    } // ---------------------------------------------------------------- help

    /// L'help e' l'unica documentazione che l'utente vede prima di decidere
    /// cosa scrivere, quindi vale un test: se domani una sezione per sbaglio
    /// l'unico sintomo sarebbe un utente che non trova `--ntfy-test`.
    #[test]
    fn help_ha_tutte_le_sezioni() {
        let s = usage();
        for sez in [
            "USO RAPIDO",
            "COMANDI PRINCIPALI",
            "SCELTA DEI DISPOSITIVI",
            "CON --listen",
            "NOTIFICHE",
            "STREAMING",
            "DALLA DASHBOARD",
            "REPORT HTML",
            "ALTRO",
        ] {
            assert!(s.contains(sez), "manca la sezione {sez}");
        }
    }

    #[test]
    fn help_apre_con_i_comandi_per_chi_arriva_da_zero() {
        // Le prime righe utili sono quelle che coprono il 90% dei casi: se
        // l'help inizia con `--prune-days`, l'utente abbandona.
        let s = usage();
        let uso = s.find("USO RAPIDO").expect("manca USO RAPIDO");
        let comandi = s.find("COMANDI PRINCIPALI").expect("manca la sezione");
        let blocco = &s[uso..comandi];
        for c in [
            "bluesniff",
            "bluesniff --one-shot",
            "bluesniff --listen",
            "bluesniff --inq",
            "bluesniff --doctor",
        ] {
            assert!(blocco.contains(c), "{c} non e' in USO RAPIDO");
        }
    }

    #[test]
    fn nessuna_riga_del_help_sfora_la_larghezza_del_terminale() {
        // Su un terminale da 80 colonne una riga piu' lunga costringe a
        // scorrere orizzontalmente, e non si nota: e' il difetto piu' comune
        // degli help lunghi, ed e' invisibile finche' non lo guardi in un
        // terminale stretto. La misura e' sui caratteri visibili: i codici
        // ANSI non occupano spazio e contarli sarebbe un falso allarme.
        for linea in usage().lines() {
            let visibile = logging::strip_ansi(linea);
            assert!(
                visibile.chars().count() <= COL_MAX,
                "riga da {} caratteri: {visibile}",
                visibile.chars().count()
            );
        }
    }

    #[test]
    fn le_descrizioni_partono_dalla_stessa_colonna() {
        // L'allineamento e' la meta' di un help a colonne: si controlla che
        // ogni riga di comando metta la descrizione alla stessa distanza dal
        // bordo. Con il padding calcolato sul testo nudo funziona anche quando
        // `bn!` ha tolto i colori.
        let mut controllate = 0;
        for linea in usage().lines() {
            let visibile = logging::strip_ansi(linea);
            if !visibile.starts_with("  ") {
                continue;
            }
            let corpo = visibile[2..].trim_start();
            // Solo le righe di comando: le note grigie e i titoli non hanno
            // una colonna delle descrizioni.
            if !corpo.starts_with("--") && !corpo.starts_with("bluesniff") {
                continue;
            }
            // La descrizione comincia dove finisce il padding, cioe' al primo
            // run di due o piu' spazi. Non si conta "il primo token": il
            // comando puo' avere argomenti (`bluesniff --listen 3600`) e il
            // primo token non finisce dove finisce il comando.
            let colonne = corpo
                .char_indices()
                .filter(|(_, c)| *c != ' ')
                .map(|(i, _)| i)
                .find(|&i| {
                    // Il primo carattere non-spazio dopo almeno due spazi.
                    i >= 2 && corpo[..i].ends_with("  ")
                });
            let inizio = colonne.unwrap_or(0);
            assert_eq!(
                2 + inizio,
                2 + COL_COMANDO,
                "descrizione fuori colonna: {visibile}"
            );
            assert!(
                !corpo[inizio..].trim().is_empty(),
                "comando senza descrizione: {visibile}"
            );
            controllate += 1;
        }
        assert!(
            controllate > 30,
            "solo {controllate} righe allineate: il test non controlla niente"
        );
    }

    #[test]
    fn help_contestuale_di_listen_mostra_solo_le_sue_opzioni() {
        let s = usage_for("--listen");
        assert!(s.contains("--dashboard"), "{s}");
        assert!(s.contains("--ntfy"), "{s}");
        // Se qui finisse tutto, il comando non servirebbe a nulla.
        assert!(
            !s.contains("--inq-json"),
            "help di --listen pulled dentro i flag di --inq"
        );
        assert!(
            !s.contains("--push <url>"),
            "help di --listen pulled dentro lo streaming"
        );
        assert!(
            s.contains("bluesniff --help"),
            "manca il rimando all'help completo"
        );
    }

    #[test]
    fn help_contestuale_di_report_ha_i_suoi_otto_flag() {
        let s = usage_for("--report");
        for f in [
            "--report-last",
            "--report-anonymize",
            "--report-open",
            "--report-no-appendix",
        ] {
            assert!(s.contains(f), "{f} manca nell'help di --report");
        }
        assert!(
            !s.contains("--prune-days"),
            "l'help di --report ha flag che non gli appartengono"
        );
    }

    #[test]
    fn help_contestuale_sconosciuto_ricade_sull_help_generale() {
        // Un flag che non ha una sezione sua non deve lasciare l'utente senza
        // risposta: si dà l'help intero.
        assert!(usage_for("--connect").contains("USO RAPIDO"));
    }

    #[test]
    fn help_non_promette_flag_che_non_esistono() {
        // Il difetto peggiore di un help e' insegnare un comando inesistente:
        // l'utente lo prova, non funziona, e conclude che il tool sia rotto.
        // Il test confronta quello che l'help promette con quello che main
        // riconosce davvero.
        let sorgente = include_str!("main.rs");
        for riga in usage().lines() {
            let v = logging::strip_ansi(riga);
            // Solo la prima parola della riga: e' il comando. Le righe che
            // cominciano con `bluesniff` sono esempi, non flag, e quelle con
            // `0 BLE` sono note.
            let prima = v.trim_start();
            if !prima.starts_with("--") {
                continue;
            }
            let flag = prima
                .trim_start_matches('-')
                .split(&[' ', '|', '<', '>'][..])
                .next()
                .unwrap_or("");
            if flag.is_empty() || !flag.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
                continue;
            }
            // I flag composti (`--dashboard-port`) contengono il prefisso di
            // uno semplice: basta controllare che la stringa compaia da
            // qualche parte in main.rs come flag o come prefisso di argomento.
            let esiste = sorgente.contains(&format!("\"--{flag}\""))
                || sorgente.contains(&format!("--{flag} <"))
                || sorgente.contains(&format!("--{flag}["))
                || sorgente.contains(&format!("--{flag}|"));
            assert!(esiste, "l'help promette --{flag}, che main non riconosce");
        }
    }
}
