//! Test di `report.rs`.
//!
//! Stanno in un file a parte (`#[path]`) perche' il modulo e' gia' lungo e i
//! test sono un documento diverso dal codice: leggere `build_from` senza
//! prima aver letto le fixture che lo alimentano e' piu' difficile, non
//! piu' facile.

use super::*;

/// Directory temporanea con i quattro file che il report legge.
///
/// Ogni test ha la sua: i test girano in parallelo e due che scrivessero lo
/// stesso `presenze.csv` si romperebbero a vicenda in un modo che dipende
/// dall'ordine di esecuzione, cioe' il tipo di test che fallisce una volta su
/// trenta senza che nessuno sappia spiegare perche'.
struct Fixture {
    dir: PathBuf,
    src: Sources,
}

/// Una riga di `presenze.csv` nelle otto colonne usate dai test: (ora, mac,
/// nome, persona, rssi, fingerprint, vendor, hint). Un tipo invece di una
/// tupla di otto `&str` scritta per ogni test: il nome dice cosa sono e
/// `clippy` smette di segnalare la firma come illeggibile.
type Row = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

impl Fixture {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("bluesniff-report-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = Sources {
            presenze: dir.join("presenze.csv"),
            raw_log_dir: dir.clone(),
            known: dir.join("bt_known.txt"),
            inq_events: dir.join("inq_events.jsonl"),
        };
        Self { dir, src }
    }

    /// Scrive `presenze.csv`. Ogni tupla e' (ora, mac, nome, persona, rssi,
    /// fingerprint, vendor, hint).
    fn csv(&self, rows: &[Row]) {
        let mut out =
            String::from("ora;tipo;mac;nome;persona;rssi;fingerprint;vendor;hint;stato;stazione\n");
        for (ora, mac, nome, persona, rssi, fp, vendor, hint) in rows {
            out.push_str(&format!(
                "{ora};passivo;{mac};{nome};{persona};{rssi};{fp};{vendor};{hint};visto;8C:88:2B:31:5B:74\n"
            ));
        }
        std::fs::write(&self.src.presenze, out).unwrap();
    }

    fn known(&self, rows: &[(&str, &str, &str)]) {
        let mut out = String::from("# BTMAC;Nome;Persona\n");
        for (mac, nome, persona) in rows {
            out.push_str(&format!("{mac};{nome};{persona}\n"));
        }
        std::fs::write(&self.src.known, out).unwrap();
    }

    /// Righe di `raw_log.jsonl` con l'hint e il Model ID: le due cose che il
    /// CSV non porta.
    fn raw(&self, rows: &[(&str, &str, &str, Option<u32>)]) {
        let mut out = String::new();
        for (ts, mac, hint, model_id) in rows {
            out.push_str(&format!(
                "{{\"ts\":\"{ts}\",\"mac\":\"{mac}\",\"hint\":{},\"model_id\":{},\"rssi\":-60}}\n",
                serde_json::json!(hint),
                serde_json::json!(model_id)
            ));
        }
        std::fs::write(self.dir.join("raw_log.jsonl"), out).unwrap();
    }

    fn build(&self) -> Report {
        build_from(&ReportConfig::default(), &self.src).expect("build fallita")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn cfg_full() -> ReportConfig {
    ReportConfig {
        full_appendix: true,
        ..Default::default()
    }
}

#[test]
fn report_senza_nessun_file_non_panica_e_lo_dice() {
    // Il caso limite piu' importante: nessun file. Non deve fallire (un
    // report vuoto e' una risposta utile) e non deve mentire: "nessun evento
    // notevole" sarebbe falso, perche' non abbiamo guardato nulla.
    let fx = Fixture::new("vuoto");
    let r = build_from(&ReportConfig::default(), &fx.src).unwrap();
    assert!(r.empty, "dovrebbe essere vuoto");
    assert!(r.no_source, "manca presenze.csv");
    assert_eq!(r.counts.total_unique, 0);
    assert!(r.followed.is_empty());
    assert!(r.all_devices.is_empty());
    assert!(r.summary.contains("Nessun dato"), "{}", r.summary);
    // L'HTML di un report vuoto deve comunque essere un documento valido.
    let html = render_html(&r);
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("</html>"));
    assert!(html.contains("Nessun dispositivo seguito"));
}

#[test]
fn conta_dispositivi_identified_e_unknown() {
    let fx = Fixture::new("conta");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "Moto G73",
            "",
            "-60",
            "",
            "motorola",
            "",
        ),
        (
            "2026-09-30T08:00:30Z",
            "AA:BB:CC:DD:EE:01",
            "Moto G73",
            "",
            "-61",
            "",
            "motorola",
            "",
        ),
        (
            "2026-09-30T08:01:00Z",
            "BB:BB:BB:BB:BB:01",
            "",
            "",
            "-80",
            "",
            "",
            "",
        ),
    ]);
    let r = fx.build();
    assert_eq!(r.counts.total_unique, 2, "dispositivi unici");
    assert_eq!(r.counts.sightings, 3, "avvistamenti");
    assert_eq!(r.counts.identified, 1);
    assert_eq!(r.counts.unknown, 1);
}

#[test]
fn riconosce_un_localizzatore_dal_campo_hint() {
    let fx = Fixture::new("tracker");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "CC:CC:CC:CC:CC:01",
        "",
        "",
        "-70",
        "",
        "Apple",
        "Apple Find My accessory",
    )]);
    let r = fx.build();
    assert_eq!(r.counts.tracker_count, 1, "{}", r.summary);
    assert!(
        r.events.iter().any(|e| e.kind == EventKind::Tracker),
        "manca l'evento tracker: {:?}",
        r.events
    );
}

#[test]
fn i_localizzatori_si_contano_per_fingerprint_e_non_per_mac() {
    // Il caso reale che rende sbagliato il conteggio per MAC: un solo
    // AirTag che ruota l'indirizzo. Tre righe, tre MAC, stesso fingerprint:
    // un localizzatore visto sotto tre indirizzi, non tre localizzatori.
    let fx = Fixture::new("tracker-fr");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:AA:AA:AA:AA:01",
            "",
            "",
            "-70",
            "fpT",
            "Apple",
            "Apple Find My accessory",
        ),
        (
            "2026-09-30T08:15:00Z",
            "AA:AA:AA:AA:AA:02",
            "",
            "",
            "-70",
            "fpT",
            "Apple",
            "Apple Find My accessory",
        ),
        (
            "2026-09-30T08:30:00Z",
            "AA:AA:AA:AA:AA:03",
            "",
            "",
            "-70",
            "fpT",
            "Apple",
            "Apple Find My accessory",
        ),
    ]);
    let r = fx.build();
    assert_eq!(r.counts.tracker_count, 1, "un solo dispositivo fisico");
    assert_eq!(r.counts.tracker_macs, 3, "ma visto sotto tre indirizzi");
    assert!(
        r.summary.contains("visti sotto 3 indirizzi diversi"),
        "il sommario deve dire perche' i numeri non coincidono: {}",
        r.summary
    );
}

#[test]
fn intervalli_di_presenza_uniscono_le_finestre_ma_non_le_visite() {
    // Tre avvistamenti entro 4 minuti sono una visita; il quarto, lontano, e'
    // un'altra visita. Senza questa soglia il report direbbe "presente 8 ore"
    // per un dispositivo visto due volte in una giornata.
    let base = crate::logging::parse_rfc3339_epoch("2026-09-30T08:00:00Z").unwrap() * 1000;
    let times: Vec<i64> = vec![base, base + 120_000, base + 300_000, base + 14_400_000];
    let segs = segments_of(&times);
    assert_eq!(segs.len(), 2, "segmenti: {segs:?}");
    assert_eq!(segs[0].to_ms - segs[0].from_ms, 300_000);
    assert_eq!(segs[1].to_ms - segs[1].from_ms, 0);
}

#[test]
fn i_dispositivi_seguiti_hanno_timeline_e_pattern() {
    let fx = Fixture::new("seguiti");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "Mario",
            "-55",
            "",
            "Apple",
            "",
        ),
        (
            "2026-09-30T08:10:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "Mario",
            "-57",
            "",
            "Apple",
            "",
        ),
        (
            "2026-09-30T08:20:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "Mario",
            "-56",
            "",
            "Apple",
            "",
        ),
    ]);
    fx.known(&[("AA:BB:CC:DD:EE:01", "iPhone", "Mario")]);
    let r = build_from(&cfg_full(), &fx.src).unwrap();
    assert_eq!(r.counts.followed, 1, "seguiti");
    let f = &r.followed[0];
    assert_eq!(f.persona, "Mario");
    assert_eq!(f.sightings, 3);
    // Tre avvistamenti a 10 minuti di distanza superano la soglia di 4 minuti:
    // sono tre visite, non una permanenza. Il report non deve dichiarare
    // "presente 20 minuti" perche' non lo sa.
    assert_eq!(f.visits, 3, "visite: {}", f.segments.len());
    assert_eq!(f.span_s, 1200, "finestra fra il primo e l'ultimo");
    assert!(!f.pattern.is_empty(), "pattern vuoto");
    assert!(
        !f.pattern.contains("Daily"),
        "pattern non tradotto: {}",
        f.pattern
    );
    let tot: u32 = f.grid.iter().flatten().sum();
    assert_eq!(
        tot, 3,
        "celle orarie non coerenti con gli avvistamenti: {:?}",
        f.grid
    );
    let html = render_html(&r);
    assert!(
        html.contains("<svg class=\"timeline\""),
        "manca la timeline"
    );
    assert!(
        html.contains("class=\"tl-on\""),
        "nessun segmento disegnato"
    );
}

#[test]
fn la_timeline_usa_lo_stesso_unit_system_del_report() {
    // Questo test esiste perche' il difetto c'era: i segmenti venivano dai
    // tempi in secondi del CSV e la timeline li confrontava con l'intervallo
    // in millisecondi. Il risultato era `x="-17719859.81"`: un numero
    // negativo in un `viewBox` che parte da 0, quindi **nessun segmento
    // disegnato e nessun errore**. Il controllo non puo' essere "c'e' un rect"
    // (c'era): deve essere "la coordinata e' dentro il canvas".
    let fx = Fixture::new("unita");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-55",
            "",
            "Apple",
            "",
        ),
        (
            "2026-09-30T09:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-56",
            "",
            "Apple",
            "",
        ),
    ]);
    fx.known(&[("AA:BB:CC:DD:EE:01", "iPhone", "Mario")]);
    let r = build_from(&cfg_full(), &fx.src).unwrap();
    // Il segmento deve stare nel primo quarto: il dispositivo c'e' stato nella
    // prima meta' dell'intervallo, che finisce al suo ultimo avvistamento.
    let seg = r.followed[0].segments[0].clone();
    assert!(
        seg.from_ms >= r.from_ms,
        "il segmento inizia prima dell'intervallo"
    );
    assert!(
        seg.to_ms <= r.to_ms,
        "il segmento finisce dopo dell'intervallo"
    );
    let svg = timeline_svg(r.from_ms, r.to_ms, &r.followed[0].segments);
    for x in svg
        .lines()
        .filter(|l| l.trim_start().starts_with("<rect") && l.contains("tl-on"))
    {
        let coord: f64 = x
            .split("x=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(f64::NAN);
        assert!(
            (0.0..=1000.0).contains(&coord),
            "coordinata fuori dal canvas: {x}"
        );
    }
}

#[test]
fn il_pattern_e_tradotto_italiano() {
    // "Constant, weekdays" e' la stringa che `pattern_line` produce per un
    // dispositivo molto presente: restava in inglese nel report, e in un
    // documento italiano si legge come un errore di traduzione.
    let fx = Fixture::new("pattern-it");
    let mut rows: Vec<Row> = Vec::new();
    // 12 avvistazioni in 6 ore di un giorno feriale: "Constant, Weekdays".
    for h in 8..14 {
        rows.push((
            Box::leak(format!("2026-09-30T{h:02}:00:00Z").into_boxed_str()),
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-55",
            "",
            "Apple",
            "",
        ));
    }
    for h in 8..14 {
        rows.push((
            Box::leak(format!("2026-09-29T{h:02}:00:00Z").into_boxed_str()),
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-55",
            "",
            "Apple",
            "",
        ));
    }
    fx.csv(&rows);
    fx.known(&[("AA:BB:CC:DD:EE:01", "iPhone", "Mario")]);
    let r = build_from(&cfg_full(), &fx.src).unwrap();
    let p = &r.followed[0].pattern;
    for inglese in [
        "Constant",
        "Daily",
        "Regular",
        "Occasional",
        "Weekdays",
        "Evenings",
    ] {
        assert!(
            !p.contains(inglese),
            "etichetta non tradotta ({inglese}): {p}"
        );
    }
    // Qualunque sia il pattern, la sua etichetta deve essere una parola
    // italiana con minuscola iniziale: e' il segnale che la tabella di
    // traduzione e' stata consultata.
    assert!(
        ["costante", "regolare", "occasionale", "mattina", "sera"]
            .iter()
            .any(|it| p.starts_with(it)),
        "etichetta non riconosciuta: {p}"
    );
}

#[test]
fn il_bordo_ambra_compare_solo_quando_il_numero_conta() {
    // Un bordo d'allarme su uno zero e' un'allarme a vuoto: l'occhio impara a
    // ignorarlo, e il giorno in cui il numero conta davvero non lo nota piu'.
    let fx = Fixture::new("warn");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "-60",
        "",
        "",
        "",
    )]);
    let html = render_html(&build_from(&cfg_full(), &fx.src).unwrap());
    let card = |etichetta: &str| -> String {
        let i = html.find(etichetta).unwrap();
        html[..i].rsplit("count-card").next().unwrap().to_string()
    };
    assert!(
        !card("Con CVE note").contains("warn"),
        "0 CVE ma bordo ambra"
    );
    assert!(
        !card("Localizzatori").contains("warn"),
        "0 tracker ma bordo ambra"
    );
}

#[test]
fn la_timeline_mette_il_segmento_nella_posizione_giusta() {
    // Il segmento parte a meta' dell'intervallo: deve occupare meta' della
    // larghezza, non tutta e non zero. E' il controllo che rende la barra
    // verificabile senza guardarla.
    let segs = vec![Segment {
        from_ms: 5_000,
        to_ms: 7_000,
    }];
    let svg = timeline_svg(0, 10_000, &segs);
    assert!(svg.contains("x=\"500.00\""), "x non a meta': {svg}");
    assert!(svg.contains("width=\"200.00\""), "larghezza errata: {svg}");
}

#[test]
fn anonymize_maschera_gli_ultimi_tre_byte() {
    assert_eq!(mask_mac("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:XX:XX:XX");
    assert_eq!(mask_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:XX:XX:XX");
    // Non-MAC: nessuna trasformazione silenziosa che spacci un testo casuale
    // per un indirizzo mascherato.
    assert_eq!(mask_mac("non-e-un-mac"), "non-e-un-mac");
}

#[test]
fn anonymize_non_filtra_l_html() {
    // Il test piu' importante sulla privacy: non basta che `mask_mac`
    // funzioni, l'HTML non deve contenere il MAC da nessuna parte.
    let fx = Fixture::new("anon");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "-60",
        "",
        "motorola",
        "",
    )]);
    let cfg = ReportConfig {
        anonymize: true,
        full_appendix: true,
        ..Default::default()
    };
    let html = render_html(&build_from(&cfg, &fx.src).unwrap());
    assert!(
        !html.contains("AA:BB:CC:DD:EE:01"),
        "MAC completo presente nell'HTML anonimo"
    );
    assert!(html.contains("AA:BB:CC:XX:XX:XX"), "MAC mascherato assente");
}

#[test]
fn senza_anonymize_i_mac_completi_restano() {
    let fx = Fixture::new("nonanon");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "-60",
        "",
        "motorola",
        "",
    )]);
    let html = render_html(&build_from(&cfg_full(), &fx.src).unwrap());
    assert!(
        html.contains("AA:BB:CC:DD:EE:01"),
        "il report non anonimo deve mostrare i MAC veri"
    );
}

#[test]
fn escape_html_protegge_da_un_nome_malizioso() {
    // I nomi vengono da annunci BLE di chiunque si trovi nelle vicinanze: un
    // nome con `<script>` arriva in names.txt o direttamente dal dispositivo e
    // finisce in un HTML che l'utente apre nel suo browser.
    assert_eq!(
        escape_html("<script>alert(1)</script>"),
        "&lt;script&gt;alert(1)&lt;/script&gt;"
    );
    let fx = Fixture::new("xss");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "<img src=x onerror=alert(1)>",
        "",
        "-60",
        "",
        "",
        "",
    )]);
    let html = render_html(&build_from(&cfg_full(), &fx.src).unwrap());
    assert!(!html.contains("<img src=x"), "HTML iniettato: {html}");
    assert!(html.contains("&lt;img"), "nome non escapato: {html}");
}

#[test]
fn l_html_e_autonomo() {
    // "Un file che si apre e basta": niente <script>, niente <link>, niente
    // risorse remote. Un controllo sul testo basta e fallisce se qualcuno
    // aggiunge un tag in futuro.
    let fx = Fixture::new("autonomo");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "-60",
        "",
        "motorola",
        "",
    )]);
    let html = render_html(&build_from(&cfg_full(), &fx.src).unwrap());
    let low = html.to_lowercase();
    assert!(!low.contains("<script"), "c'e' un <script>");
    assert!(!low.contains("<link"), "c'e' un <link>");
    assert!(!low.contains("src=\"http"), "risorsa remota");
    assert!(!low.contains("href=\"http"), "risorsa remota");
    assert!(html.contains("@media print"), "manca la stampa");
    assert!(low.contains("lang=\"it\""), "manca lang=it");
}

#[test]
fn il_sommario_contiene_i_numeri_e_non_inventa_giudizi() {
    let fx = Fixture::new("sommario");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-55",
            "",
            "Apple",
            "",
        ),
        (
            "2026-09-30T08:30:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-56",
            "",
            "Apple",
            "",
        ),
        (
            "2026-09-30T09:00:00Z",
            "BB:BB:BB:BB:BB:01",
            "",
            "",
            "-80",
            "",
            "",
            "",
        ),
    ]);
    fx.known(&[("AA:BB:CC:DD:EE:01", "iPhone", "Mario")]);
    let r = build_from(&cfg_full(), &fx.src).unwrap();
    let s = &r.summary;
    assert!(s.contains("2 "), "manca il numero di dispositivi: {s}");
    assert!(s.contains("iPhone"), "manca il nome del seguito: {s}");
    assert!(
        s.contains("fra le 08:00 e le 08:30"),
        "mancano gli orari: {s}"
    );
    // Il tono: niente allarme e niente falsa tranquillita'.
    for vietato in ["ATTENZIONE", "pericolo", "sei al sicuro", "ti sta seguendo"] {
        assert!(!s.contains(vietato), "trovato \"{vietato}\": {s}");
    }
}

#[test]
fn il_sommario_ammette_che_senza_raw_log_non_sappiamo() {
    let fx = Fixture::new("noraw");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "-60",
        "",
        "motorola",
        "",
    )]);
    let r = build_from(&cfg_full(), &fx.src).unwrap();
    assert!(!r.raw_available, "il raw log non esiste in questa fixture");
    assert!(
        r.summary.contains("raw_log"),
        "il sommario deve dichiarare il limite: {}",
        r.summary
    );
}

#[test]
fn il_raw_log_abilita_la_heatmap_e_il_conteggio_dei_tracker() {
    let fx = Fixture::new("conraw");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "CC:CC:CC:CC:CC:01",
        "",
        "",
        "-70",
        "",
        "Apple",
        "",
    )]);
    assert!(
        !build_from(&ReportConfig::default(), &fx.src)
            .unwrap()
            .raw_available
    );
    fx.raw(&[(
        "2026-09-30T08:00:00Z",
        "CC:CC:CC:CC:CC:01",
        "Apple Find My accessory",
        None,
    )]);
    let r = build_from(&ReportConfig::default(), &fx.src).unwrap();
    assert!(r.raw_available, "il raw log doveva essere riconosciuto");
    // Il conteggio nell'evento deve venire dal CSV: il raw log puo' non
    // coprire quel MAC, e "0 pacchetti" accanto a un localizzatore appena
    // identificato sarebbe una frase falsa.
    let html = render_html(&r);
    // Nel HTML l'apostrofo e' escaped (`nell&#39;intervallo`): il test cerca
    // il pezzo che l'escape non tocca, cosi' non dipende dal escaping.
    assert!(html.contains("1 avvistamento nell"), "{html}");
    assert!(!html.contains("0 pacchetti"), "{html}");
}

#[test]
fn intervallo_invertito_e_un_errore_chiaro() {
    let fx = Fixture::new("invertito");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "-60",
        "",
        "",
        "",
    )]);
    let cfg = ReportConfig {
        from_ms: Some(1_800_000_000_000),
        to_ms: Some(1_000_000_000_000),
        ..Default::default()
    };
    let err = build_from(&cfg, &fx.src).unwrap_err();
    assert!(
        err.contains("vuoto o invertito"),
        "errore poco utile: {err}"
    );
}

#[test]
fn l_intervallo_oltre_sette_giorni_viene_ridotto_e_dichiarato() {
    let fx = Fixture::new("troncato");
    fx.csv(&[
        (
            "2026-01-01T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "Moto",
            "",
            "-60",
            "",
            "",
            "",
        ),
        (
            "2026-01-20T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "Moto",
            "",
            "-60",
            "",
            "",
            "",
        ),
    ]);
    let r = build_from(&cfg_full(), &fx.src).unwrap();
    assert!(r.truncated, "doveva dichiarare la riduzione");
    assert!(
        (r.to_ms - r.from_ms) / 1000 <= MAX_SPAN_S,
        "span oltre il limite"
    );
    assert!(render_html(&r).contains("ridotto"), "manca l'avviso");
}

#[test]
fn durate_in_italiano() {
    assert_eq!(fmt_dur(0), "0s");
    assert_eq!(fmt_dur(47), "47s");
    assert_eq!(fmt_dur(600), "10m");
    assert_eq!(fmt_dur(3 * 3600 + 12 * 60), "3h 12m");
    assert_eq!(fmt_dur(-5), "0s", "una durata negativa e' un bug a monte");
}

#[test]
fn il_report_non_dichiara_mai_un_tempo_di_presenza() {
    // Il numero "presente per 3h 12m" e' la bugia piu' insidiosa che questo
    // report potrebbe raccontare: sembra una misura, e non lo e'. Il testo
    // deve dire "fra le X e le Y".
    let fx = Fixture::new("n temposi");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-55",
            "",
            "Apple",
            "",
        ),
        (
            "2026-09-30T09:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-55",
            "",
            "Apple",
            "",
        ),
    ]);
    fx.known(&[("AA:BB:CC:DD:EE:01", "iPhone", "Mario")]);
    let r = build_from(&cfg_full(), &fx.src).unwrap();
    assert!(!r.summary.contains("presente per"), "{}", r.summary);
    let html = render_html(&r);
    assert!(
        !html.contains("Presente <b>"),
        "la scheda dichiara ancora la presenza"
    );
    assert!(
        html.contains("Sentito fra le"),
        "manca la formulazione corretta"
    );
}

#[test]
fn le_note_metodologiche_dicono_che_non_sappiamo_dove() {
    let fx = Fixture::new("note");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "-60",
        "",
        "",
        "",
    )]);
    let html = render_html(&build_from(&cfg_full(), &fx.src).unwrap());
    assert!(
        html.contains("non sa dove"),
        "manca l'avviso sulla posizione"
    );
    assert!(html.contains("disclaimer"), "manca il disclaimer");
    assert!(
        html.contains("spento, fuori portata"),
        "manca la formula del disclaimer"
    );
}

#[test]
fn eventi_di_spam_dal_monitor_inq() {
    let fx = Fixture::new("spam");
    fx.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "-60",
        "",
        "",
        "",
    )]);
    std::fs::write(
        &fx.src.inq_events,
        "{\"event\":\"inq_cycle\",\"ts\":\"2026-09-30T08:00:00Z\",\
         \"spam\":{\"detected\":true,\"popup_hard\":7,\"dup_model_ids\":[1,2]}}\n",
    )
    .unwrap();
    let r = fx.build();
    assert_eq!(r.counts.spam_events, 1);
    let ev = r.events.iter().find(|e| e.kind == EventKind::Spam).unwrap();
    assert!(ev.detail.contains('7'), "manca il conteggio: {}", ev.detail);
    assert!(r.summary.contains("spam"), "{}", r.summary);
}

#[test]
fn i_dispositivi_ruotanti_vengono_segnalati_una_volta_solo() {
    let fx = Fixture::new("rotanti");
    // Tre MAC con lo stesso fingerprint: un dispositivo che cambia indirizzo.
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:AA:AA:AA:AA:01",
            "",
            "",
            "-70",
            "fp1",
            "",
            "",
        ),
        (
            "2026-09-30T08:20:00Z",
            "AA:AA:AA:AA:AA:02",
            "",
            "",
            "-70",
            "fp1",
            "",
            "",
        ),
        (
            "2026-09-30T08:40:00Z",
            "AA:AA:AA:AA:AA:03",
            "",
            "",
            "-70",
            "fp1",
            "",
            "",
        ),
    ]);
    let r = fx.build();
    assert_eq!(r.counts.total_unique, 3, "le righe restano tre");
    let rot = r
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Rotating)
        .count();
    assert_eq!(rot, 1, "un solo evento per fingerprint, non uno per MAC");
    assert!(
        r.events[0].detail.contains("3 indirizzi"),
        "{}",
        r.events[0].detail
    );
}

#[test]
fn l_appendice_e_una_tabella_ordinata_per_avvistamenti() {
    let fx = Fixture::new("appendice");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "Poco",
            "",
            "-60",
            "",
            "",
            "",
        ),
        (
            "2026-09-30T08:01:00Z",
            "BB:BB:BB:BB:BB:01",
            "Molto",
            "",
            "-60",
            "",
            "",
            "",
        ),
        (
            "2026-09-30T08:02:00Z",
            "BB:BB:BB:BB:BB:01",
            "Molto",
            "",
            "-61",
            "",
            "",
            "",
        ),
        (
            "2026-09-30T08:03:00Z",
            "BB:BB:BB:BB:BB:01",
            "Molto",
            "",
            "-62",
            "",
            "",
            "",
        ),
    ]);
    let senza = render_html(&build_from(&ReportConfig::default(), &fx.src).unwrap());
    assert!(
        !senza.contains("<table"),
        "appendice presente senza chiederla"
    );

    let con = render_html(&build_from(&cfg_full(), &fx.src).unwrap());
    assert!(con.contains("<table"), "appendice assente");
    // L'ordine si controlla sui MAC dentro la tabella: i nomi possono comparire
    // anche in altre sezioni del documento, e li' l'indice non significa nulla.
    let tabella = con.find("<table").unwrap();
    let i_molto = con[tabella..].find("BB:BB:BB:BB:BB:01").unwrap();
    let i_poco = con[tabella..].find("AA:BB:CC:DD:EE:01").unwrap();
    assert!(
        i_molto < i_poco,
        "la tabella non e' ordinata per avvistamenti (molto={i_molto}, poco={i_poco})"
    );
}

#[test]
fn la_heatmap_non_riplica_lo_stesso_giorno_sette_volte() {
    // Regressione: la heatmap prendeva il conteggio per ora e lo replicava su
    // tutte le righe, cosi' una sola giornata osservata sembrava una settimana
    // piena. Ogni cella deve valere il suo giorno.
    let fx = Fixture::new("heat2");
    fx.csv(&[
        (
            "2026-09-29T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-55",
            "",
            "Apple",
            "",
        ),
        (
            "2026-09-29T08:00:30Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-56",
            "",
            "Apple",
            "",
        ),
    ]);
    fx.known(&[("AA:BB:CC:DD:EE:01", "iPhone", "Mario")]);
    let html = render_html(&build_from(&cfg_full(), &fx.src).unwrap());
    assert_eq!(
        html.matches("class=\"heat-cell l0\"").count(),
        167,
        "una sola cella (08:00 di un solo giorno) deve essere piena; se le ore \
         fossero replicate su tutti i giorni le celle piene sarebbero 7"
    );
}

#[test]
fn la_heatmap_e_24x7_e_il_colore_non_e_l_unico_canale() {
    let fx = Fixture::new("heat");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-55",
            "",
            "Apple",
            "",
        ),
        (
            "2026-09-30T08:00:30Z",
            "AA:BB:CC:DD:EE:01",
            "iPhone",
            "",
            "-56",
            "",
            "Apple",
            "",
        ),
    ]);
    fx.known(&[("AA:BB:CC:DD:EE:01", "iPhone", "Mario")]);
    let html = render_html(&build_from(&cfg_full(), &fx.src).unwrap());
    assert_eq!(
        html.matches("class=\"heat-cell").count(),
        168,
        "la griglia deve essere 24x7"
    );
    assert!(
        html.contains("08:00 — 2 avvistamenti"),
        "manca il titolo leggibile della cella"
    );
    assert!(html.contains("aria-label="), "manca il testo alternativo");
}

#[test]
fn rssi_medio_su_righe_senza_rssi() {
    let fx = Fixture::new("rssi");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "Moto",
            "",
            "-60",
            "",
            "",
            "",
        ),
        (
            "2026-09-30T08:01:00Z",
            "AA:BB:CC:DD:EE:01",
            "Moto",
            "",
            "",
            "",
            "",
            "",
        ),
    ]);
    let r = build_from(&cfg_full(), &fx.src).unwrap();
    assert_eq!(r.all_devices[0].rssi_avg, Some(-60));
    let fx2 = Fixture::new("rssi2");
    fx2.csv(&[(
        "2026-09-30T08:00:00Z",
        "AA:BB:CC:DD:EE:01",
        "Moto",
        "",
        "",
        "",
        "",
        "",
    )]);
    let r2 = build_from(&cfg_full(), &fx2.src).unwrap();
    assert_eq!(r2.all_devices[0].rssi_avg, None, "media su zero valori");
}

#[test]
fn la_stazione_legge_mac_e_hostname() {
    assert_eq!(
        split_station("8C:88:2B:31:5B:74"),
        ("8C:88:2B:31:5B:74".to_string(), String::new())
    );
    assert_eq!(
        split_station("8C:88:2B:31:5B:74@PC-CASA"),
        ("8C:88:2B:31:5B:74".to_string(), "PC-CASA".to_string())
    );
}

#[test]
fn il_report_dipende_dai_file_e_non_dallo_stato_del_processo() {
    // Costruire lo stesso report due volte di fila deve dare lo stesso
    // risultato: se dipendesse da qualche stato globale (l'ultimo `refresh`,
    // una cache), un report generato dal CLI e uno dalla dashboard
    // potrebbero descrivere momenti diversi senza che nessuno lo noti.
    let fx = Fixture::new("determinismo");
    fx.csv(&[
        (
            "2026-09-30T08:00:00Z",
            "AA:BB:CC:DD:EE:01",
            "Moto",
            "",
            "-60",
            "",
            "",
            "",
        ),
        (
            "2026-09-30T08:05:00Z",
            "AA:BB:CC:DD:EE:01",
            "Moto",
            "",
            "-61",
            "",
            "",
            "",
        ),
    ]);
    let a = fx.build();
    let b = fx.build();
    assert_eq!(a.counts.total_unique, b.counts.total_unique);
    assert_eq!(a.from_ms, b.from_ms);
    assert_eq!(a.to_ms, b.to_ms);
    assert_eq!(
        render_html(&a),
        render_html(&b),
        "due report identici a byte"
    );
}
