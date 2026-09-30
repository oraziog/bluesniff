//! Test del canale di controllo senza stdin.
//!
//! I test usano `Paths::in_dir` con directory temporanee: scrivere
//! `bluesniff.pid` nella cartella dell'eseguibile durante un test
//! significherebbe far credere a un bluesniff in eseczione che ce n'è un
//! altro, e i test in parallelo si romperebbero a vicenda.

use super::*;

fn dir_temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bluesniff-ctl-test-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("creo la dir temporanea");
    d
}

#[test]
fn parse_accetta_gli_alias_conosciuti() {
    assert_eq!(Control::parse("pause"), Some(Control::Pause));
    assert_eq!(Control::parse("PAUSE"), Some(Control::Pause));
    assert_eq!(Control::parse("  resume\n"), Some(Control::Resume));
    assert_eq!(Control::parse("start"), Some(Control::Resume));
    assert_eq!(Control::parse("stop"), Some(Control::Stop));
    // 'q' e 'exit' erano già quello che l'utente digitava su stdin: se
    // scrivere 'q' nel file fermasse solo la scansione sarebbe una trappola.
    assert_eq!(Control::parse("q"), Some(Control::Stop));
    assert_eq!(Control::parse("quit"), Some(Control::Stop));
    assert_eq!(Control::parse("snapshot"), Some(Control::Snapshot));
    assert_eq!(Control::parse("devices"), Some(Control::Snapshot));
    assert_eq!(Control::parse("status"), Some(Control::Status));
}

#[test]
fn parse_rifiuta_il_rumore() {
    assert_eq!(Control::parse("cazzimma"), None);
    assert_eq!(Control::parse(""), None);
    assert_eq!(Control::parse("pausa"), None);
    // Una riga con piu' parole non e' un comando: meglio ignorarla che
    // interpretare la prima parola e perdere il resto.
    assert_eq!(Control::parse("pause now"), None);
}

#[test]
fn il_file_di_controllo_è_un_comando_solo_e_viene_consumato() {
    let p = Paths::in_dir(dir_temp("ctl"));
    assert!(send_command_at(&p, Control::Pause).is_ok());
    assert_eq!(take_command_at(&p), Some(Control::Pause));
    // Il secondo giro non deve rieseguire: il file è sparito.
    assert_eq!(take_command_at(&p), None);
    // Un secondo comando sovrascrive il primo: pause è idempotente e una coda
    // aggiungerebbe uno stato da mantenere senza vantaggio.
    send_command_at(&p, Control::Pause).unwrap();
    send_command_at(&p, Control::Stop).unwrap();
    assert_eq!(take_command_at(&p), Some(Control::Stop));
}

#[test]
fn un_contenuto_invalido_non_blocca_i_comandi_successivi() {
    let p = Paths::in_dir(dir_temp("ctl-bad"));
    std::fs::write(p.ctl(), "non_so_cosa_sia\n").unwrap();
    // Consumato, e senza ack: se tornasse None senza cancellare il file, ogni
    // comando successivo verrebbe scartato insieme a questo.
    assert_eq!(take_command_at(&p), None);
    send_command_at(&p, Control::Resume).unwrap();
    assert_eq!(take_command_at(&p), Some(Control::Resume));
}

#[test]
fn il_pid_file_viene_scritto_e_riletto_con_il_contesto() {
    let p = Paths::in_dir(dir_temp("pid"));
    let ctx = "listen --dashboard --ntfy mario-rossi-ufficio";
    write_pid_at(&p, ctx).unwrap();
    let info = read_pid_info_at(&p).expect("il PID file c'è");
    assert_eq!(info.pid, std::process::id());
    assert_eq!(info.context, ctx);
}

#[test]
fn scrivere_il_pid_cancella_i_comandi_orfani() {
    let p = Paths::in_dir(dir_temp("pid-orfano"));
    // Simuliamo un `--stop` arrivato mentre il vecchio processo chiudeva: se
    // sopravvivesse, il nuovo processo si fermerebbe un secondo dopo l'avvio.
    std::fs::write(p.ctl(), "stop\n").unwrap();
    std::fs::write(p.ack(), "ok\nvecchio\n").unwrap();
    write_pid_at(&p, "listen").unwrap();
    assert!(!p.ctl().exists(), "il .ctl orfano deve sparire");
    assert!(!p.ack().exists(), "l'ack del vecchio processo deve sparire");
    assert_eq!(take_command_at(&p), None);
}

#[test]
fn un_pid_morto_non_blocca_il_nuovo_avvio() {
    let p = Paths::in_dir(dir_temp("pid-morto"));
    // Un PID che non esiste: 0 è invalido per definizione su Windows, e
    // `pid_alive` lo tratta come morto.
    std::fs::write(p.pid(), "0\nlisten\n").unwrap();
    write_pid_at(&p, "listen").unwrap();
    assert_eq!(read_pid_info_at(&p).unwrap().pid, std::process::id());
}

#[test]
fn un_pid_vivo_di_un_altro_processo_blocca_lavvio() {
    // Su una macchina di sviluppo non c'e' un secondo bluesniff da trovare, e
    // mentire a `pid_alive` significherebbe testare una funzione diversa da
    // quella che gira. La decisione ("un PID vivo altrui impedisce l'avvio")
    // viene quindi provata per intero, passando la risposta come argomento.
    assert!(occupa_la_cartella(1111, 2222, true));
    // Un PID morto e' un file orfano: lo si prende.
    assert!(!occupa_la_cartella(1111, 2222, false));
    // Il proprio PID non e' un conflitto: altrimenti un riavvio nella stessa
    // istanza si bloccherebbe da solo.
    assert!(!occupa_la_cartella(2222, 2222, true));
}

#[test]
fn pid_alive_risponde_su_se_stesso() {
    assert!(pid_alive(std::process::id()));
    assert!(!pid_alive(0));
}

#[test]
fn remove_files_pulisce_solo_quello_di_questo_processo() {
    let p = Paths::in_dir(dir_temp("remove"));
    write_pid_at(&p, "listen").unwrap();
    std::fs::write(p.http(), "9000\n").unwrap();
    std::fs::write(p.status(), "{}\n").unwrap();
    remove_files_at(&p);
    assert!(!p.pid().exists());
    assert!(!p.http().exists());
    assert!(!p.status().exists());
}

#[test]
fn l_ack_riporta_esito_e_messaggio() {
    let p = Paths::in_dir(dir_temp("ack"));
    write_ack_at(&p, true, "scanner in pausa");
    let (ok, msg) = take_ack_at(&p).expect("ack presente");
    assert!(ok);
    assert_eq!(msg, "scanner in pausa");
    assert!(take_ack_at(&p).is_none(), "l'ack si consuma una volta sola");
}

#[test]
fn lo_stato_json_contiene_il_campi_che_l_utente_si_aspetta() {
    let s = ControlState::new("listen --dashboard");
    s.set_info(|i| {
        i.cycles = 42;
        i.unique = 147;
        i.radio = "ON (8C:88:2B:31:5B:74)".to_string();
    });
    let v = s.status_value(1234, Some(9000));
    assert_eq!(v["pid"], 1234);
    assert_eq!(v["mode"], "listen --dashboard");
    assert_eq!(v["cycles"], 42);
    assert_eq!(v["unique"], 147);
    assert_eq!(v["scanner"], "attivo");
    assert_eq!(v["http_port"], 9000);
    s.paused.store(true, std::sync::atomic::Ordering::Relaxed);
    let v = s.status_value(1234, None);
    assert_eq!(v["scanner"], "in-pausa");
    assert!(v["http_port"].is_null());
}

#[test]
fn il_testo_dello_stato_e_leggibile_e_italiano() {
    let s = ControlState::new("listen --ntfy mario-rossi-ufficio");
    let txt = format_status(&s.status_value(4242, Some(9100)));
    assert!(txt.contains("PID: 4242"), "{txt}");
    assert!(txt.contains("Modalità: listen"), "{txt}");
    assert!(txt.contains("scanner attivo"), "{txt}");
    assert!(txt.contains("127.0.0.1:9100"), "{txt}");
    // Nessuna chiave JSON deve comparire: l'utente legge un testo.
    assert!(!txt.contains("\"uptime_s\""), "{txt}");
}

#[test]
fn l_uptime_si_legge_a_ore_e_minuti() {
    assert_eq!(fmt_uptime_secs(5), "5s");
    assert_eq!(fmt_uptime_secs(65), "1m 5s");
    assert_eq!(fmt_uptime_secs(8040), "2h 14m");
}

#[test]
fn il_commando_ferma_il_loop_e_pausa_solo_la_scansione() {
    // La differenza è il punto della feature: `pause` sospende la scansione
    // lasciando vivo il processo (e la dashboard), `stop` lo chiude.
    let s = ControlState::new("listen");
    let port: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(None));
    let p = Paths::in_dir(dir_temp("apply"));
    apply_command(&s, &p, Control::Pause, &port);
    assert!(s.is_paused());
    assert!(
        !s.shutdown.load(Ordering::Relaxed),
        "pause non deve chiudere"
    );
    let (ok, _) = take_ack_at(&p).unwrap();
    assert!(ok);

    apply_command(&s, &p, Control::Resume, &port);
    assert!(!s.is_paused());

    apply_command(&s, &p, Control::Stop, &port);
    assert!(s.shutdown.load(Ordering::Relaxed), "stop deve chiudere");
}

#[test]
fn lo_status_viene_riscritto_a_ogni_comando() {
    // `bluesniff --status` non deve dipendere dal polling: dopo il comando il
    // file c'è, altrimenti l'utente che lo interroga proprio mentre il
    // processo è fermo legge un file vecchio.
    let s = ControlState::new("listen");
    let port: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(Some(9000)));
    let p = Paths::in_dir(dir_temp("status-file"));
    apply_command(&s, &p, Control::Status, &port);
    let text = std::fs::read_to_string(p.status()).expect("lo status è stato scritto");
    let v: serde_json::Value = serde_json::from_str(text.trim()).expect("JSON valido");
    assert_eq!(v["http_port"], 9000);
    let (ok, msg) = take_ack_at(&p).unwrap();
    assert!(ok);
    assert!(msg.contains("scanner attivo"), "{msg}");
}

#[test]
fn lo_snapshot_senza_json_risponde_con_un_errore_chiaro() {
    // Il comando deve dire *perché* non può, non tacere: un utente che
    // lancia `--snapshot` su un processo senza `--json` deve capire che il
    // motivo è la modalità, non un bug.
    let s = ControlState::new("listen");
    let port: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(None));
    let p = Paths::in_dir(dir_temp("snap-vuoto"));
    apply_command(&s, &p, Control::Snapshot, &port);
    let (ok, msg) = take_ack_at(&p).unwrap();
    assert!(!ok);
    assert!(msg.contains("--json"), "{msg}");
    assert!(!p.snapshot().exists());
}

#[test]
fn lo_snapshot_con_json_viene_scritto_su_disco() {
    let s = ControlState::new("listen --json");
    *s.latest_json.lock().unwrap() = Some(serde_json::json!({"devices": 3}));
    let port: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(None));
    let p = Paths::in_dir(dir_temp("snap-ok"));
    apply_command(&s, &p, Control::Snapshot, &port);
    let (ok, _) = take_ack_at(&p).unwrap();
    assert!(ok);
    let text = std::fs::read_to_string(p.snapshot()).unwrap();
    assert!(text.contains("\"devices\":3"), "{text}");
}

#[test]
fn la_porta_si_legge_dal_file_http() {
    let p = Paths::in_dir(dir_temp("porta"));
    assert_eq!(read_http_port(&p), None);
    std::fs::write(p.http(), "9001\n").unwrap();
    assert_eq!(read_http_port(&p), Some(9001));
    // Un file corrotto non deve far cadere il comando: si prosegue via .ctl.
    std::fs::write(p.http(), "non-e-una-porta\n").unwrap();
    assert_eq!(read_http_port(&p), None);
}

#[test]
fn senza_processo_l_outcome_e_chiaro_e_negativo() {
    let p = Paths::in_dir(dir_temp("nessuno"));
    match find_process(&p) {
        Ok(_) => panic!("non dovrebbe esserci nessun processo"),
        Err(out) => {
            assert!(!out.ok);
            assert!(out.message.contains("Nessun bluesniff"), "{}", out.message);
        }
    }
}

#[test]
fn un_pid_orphan_viene_pulito_e_riferito() {
    let p = Paths::in_dir(dir_temp("orfano"));
    std::fs::write(p.pid(), "0\nlisten\n").unwrap();
    match find_process(&p) {
        Ok(_) => panic!("il PID 0 non è vivo"),
        Err(out) => {
            assert!(!out.ok);
            assert!(out.message.contains("orfano"), "{}", out.message);
        }
    }
    assert!(!p.pid().exists(), "il file orfano deve essere rimosso");
}

#[test]
fn i_comandi_hanno_una_rotta_http_una_per_comando() {
    // Un path sbagliato qui significa che `bluesniff --pause` con la dashboard
    // attiva riceve un 404 e passa al file .ctl: funziona lo stesso ma con un
    // secondo di ritardo e un messaggio nel log che sembra un errore.
    let rotte: Vec<&str> = [
        Control::Pause,
        Control::Resume,
        Control::Stop,
        Control::Status,
        Control::Snapshot,
    ]
    .iter()
    .map(|c| c.http_route())
    .collect();
    for r in &rotte {
        assert!(r.starts_with("/api/scan/"), "{r}");
    }
    let mut unici = rotte.clone();
    unici.sort_unstable();
    unici.dedup();
    assert_eq!(unici.len(), rotte.len(), "due comandi sulla stessa rotta");
}

#[test]
fn l_ack_puo_essere_su_piu_righe() {
    // `--status` risponde con lo stato formattato, che e' multilinea. Se
    // l'ack prendesse solo la prima riga, l'utente vedrebbe "PID: 9608" e
    // nient'altro: sembrerebbe che il comando abbia risposto a metà.
    let p = Paths::in_dir(dir_temp("ack-multilinea"));
    write_ack_at(&p, true, "PID: 9608\nUptime: 2h 14m\nCicli: 41");
    let (ok, msg) = take_ack_at(&p).unwrap();
    assert!(ok);
    assert_eq!(msg.lines().count(), 3);
    assert!(msg.contains("Uptime"), "{msg}");
}
