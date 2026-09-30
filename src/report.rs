//! Report HTML autonomo: il file che l'utente manda a qualcuno.
//!
//! La dashboard è uno strumento (la usi tu, dal vivo). Il **report** è
//! l'artefatto: un solo `.html` che si apre in un browser, si legge in trenta
//! secondi e racconta chi è stato vicino al PC, quando e per quanto tempo.
//!
//! Quattro scelte che definiscono il modulo, e che valgono anche se il
//! briefing le dava per scontate:
//!
//! - **Nessun JavaScript.** Il `<details>` nativo basta per l'appendice, e un
//!   file con script è un file che alcuni client di posta lo bloccano o lo
//!   eseguono: il report deve arrivare e basta, non "funzionare forse".
//! - **Nessuna risorsa esterna.** Vuol dire anche niente font remoti e niente
//!   chiamate di rete per risolvere i vendor: se il nome non è già in
//!   `presenze.csv`, il report mostra il MAC e basta.
//! - **Niente interpretazioni che i dati non reggono.** Il report dice
//!   "visto 12 volte in 2 ore con RSSI medio -68 dBm", non "ti sta seguendo":
//!   la prima frase è un fatto ricavabile dal file, la seconda no. Lo stesso
//!   vale per le posizioni: nessuna stanza, nessun piano, "vicino al PC" e
//!   basta.
//! - **L'assenza è informazione, non un errore.** Un report senza dati è una
//!   risposta ("in quella fascia non è successo niente"), quindi `build()`
//!   non fallisce mai per un file mancante: riempi le sezioni con i loro empty
//!   state e lascia che siano loro a dirlo all'utente.
//!
//! Sul riuso: `patterns::load_sightings` legge il CSV, `cves::match_cves`
//! decide le vulnerabilità, `patterns::pattern_line` classifica l'orario. Non
//! si duplica niente di tutto questo. Le famiglie di tracker però sono
//! riconosciute sui *token* che `bluetooth::phantom_kind` usa, non chiamando
//! quella funzione: `phantom_kind` lavora sulle mappe manufacturer/service
//! grezze dei pacchetti, che in `presenze.csv` non ci sono (il CSV ha il
//! `hint`, che `blewatcher` ha gia' calcolato a valle). Il mapping e' quindi una
//! lista di token esplicita, e il suo limite e' dichiarato: dal solo CSV si
//! vedono i tracker che `classify` sa nominare (Apple Find My, Samsung
//! SmartThings Find); gli altri (Tile, Chipolo, Pebblebee) si vedono solo se
//! c'e' il `raw_log`, dove il campo `decode` riporta gli AD record.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::patterns::Sighting;

/// Limite di 7 giorni per l'intervallo.
///
/// Oltre una settimana la timeline orizzontale non racconta piu' niente: con
/// 30 giorni le barre diventano segmenti troppo stretti da leggere, e
/// schermare i dati peggiori di quanto il file non faccia. Il report lo dice,
/// cosi' il limite si vede invece di essere subito.
pub const MAX_SPAN_S: i64 = 7 * 24 * 3600;

/// Gap oltre il quale due avvistamenti non sono piu' lo stesso "stare vicino".
///
/// I BLE non annunciano in continuita': un telefono in tasca si vede, sparisce
/// per qualche secondo, si rivede. Unendo tutto si otterrebbe una barra unica
/// lunga come l'intervallo, che dice "sempre presente" anche per un dispositivo
/// visto due volte in un giorno. 4 minuti e' oltre la pausa tipica di un
/// annuncio e sotto quella che separa due visite distinte.
const PRESENCE_GAP_S: i64 = 240;

/// Cosa vuole il chiamante. I default sono "tutto quello che c'e'".
#[derive(Debug, Clone, Default)]
pub struct ReportConfig {
    /// Inizio intervallo (epoch secondi). `None` = dal primo dato disponibile.
    pub from_ms: Option<i64>,
    /// Fine intervallo (epoch secondi). `None` = adesso.
    pub to_ms: Option<i64>,
    /// Titolo personalizzato al posto del default.
    pub title: Option<String>,
    /// Maschera i MAC (`AA:BB:CC:XX:XX:XX`). Per un report destinato a terzi.
    pub anonymize: bool,
    /// Include la tabella completa di tutti i dispositivi in appendice.
    pub full_appendix: bool,
}

/// Da dove leggere. Separato da `build` perche' i test devono poter leggere da
/// una directory temporanea senza toccare i file accanto all'eseguibile.
#[derive(Debug, Clone)]
pub struct Sources {
    pub presenze: PathBuf,
    pub raw_log_dir: PathBuf,
    pub known: PathBuf,
    pub inq_events: PathBuf,
}

impl Sources {
    /// Percorsi reali, accanto all'eseguibile come tutto il resto.
    pub fn real() -> Self {
        let dir = crate::logging::exe_dir();
        Self {
            presenze: dir.join("presenze.csv"),
            raw_log_dir: dir.clone(),
            known: crate::known::path(),
            inq_events: dir.join("inq_events.jsonl"),
        }
    }
}

/// I numeri di riepilogo.
#[derive(Debug, Clone, Default)]
pub struct ReportCounts {
    pub total_unique: usize,
    pub followed: usize,
    pub identified: usize,
    pub unknown: usize,
    pub cve_count: usize,
    /// Localizzatori distinti, contati per fingerprint.
    pub tracker_count: usize,
    /// Quanti MAC diversi portano quell'etichetta: se e' molto piu' grande di
    /// `tracker_count`, vuol dire che i dispositivi ruotano l'indirizzo.
    pub tracker_macs: usize,
    pub spam_events: usize,
    pub session_duration_s: i64,
    /// Quanti avvistamenti complessivi nell'intervallo: da solo `total_unique`
    /// non dice nulla di una sessione lunga e ferma.
    pub sightings: usize,
}

/// Un segmento di presenza continua sulla timeline.
#[derive(Debug, Clone)]
pub struct Segment {
    pub from_ms: i64,
    pub to_ms: i64,
}

/// Un dispositivo seguito, con tutto quello che serve a disegnarlo.
#[derive(Debug, Clone)]
pub struct FollowedDevice {
    pub mac: String,
    pub name: String,
    pub persona: String,
    pub first_ms: i64,
    pub last_ms: i64,
    /// Finestra fra il primo e l'ultimo avvistamento, in secondi.
    ///
    /// **Non e' il tempo di presenza**, perche' il tempo di presenza non e'
    /// misurabile con questi dati: un dispositivo visto alle 08:00 e alle
    /// 08:20 non e' stato "presente 20 minuti", e' stato sentito due volte in
    /// 20 minuti. Riportare la somma come "presente per" sarebbe un numero
    /// inventato con un'etichetta che sembra misurata, quindi il report dice
    /// "fra le 08:00 e le 08:20, in 3 avvistamenti" e i segmenti (le visite
    /// separate da una pausa lunga) disegnano la timeline.
    pub span_s: i64,
    pub segments: Vec<Segment>,
    pub sightings: usize,
    pub rssi_avg: Option<i16>,
    /// Pattern in italiano (tradotto da `patterns::pattern_line`).
    pub pattern: String,
    /// Quante visite distinte (segmenti della timeline).
    pub visits: usize,
    /// Conteggio per giorno della settimana (indice 0 = lunedi').
    pub days: [u32; 7],
    /// Griglia 7 (giorno) × 24 (ora) con i conteggi: senza questa matrice una
    /// heatmap costruita sul solo vettore `hours` disegnerebbe sette copie
    /// identiche dello stesso giorno, facendo sembrare piena una giornata che
    /// non e' mai stata osservata.
    pub grid: [[u32; 24]; 7],
    pub cves: Vec<crate::cves::CveEntry>,
}

/// Un evento notevole, gia' descritto in italiano: il report non deve
/// ricostruire le frasi, deve solo ordinarle per tempo.
#[derive(Debug, Clone)]
pub struct ReportEvent {
    pub ts_ms: i64,
    pub kind: EventKind,
    pub mac: String,
    pub name: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Cve,
    Tracker,
    Spam,
    Rotating,
    NewDevice,
}

impl EventKind {
    /// Etichetta corta per il badge nella lista eventi.
    pub fn badge(self) -> &'static str {
        match self {
            EventKind::Cve => "CVE",
            EventKind::Tracker => "Tracker",
            EventKind::Spam => "Spam BLE",
            EventKind::Rotating => "MAC rotanti",
            EventKind::NewDevice => "Nuovo",
        }
    }
}

/// Una riga dell'appendice: un dispositivo, come si riassume.
#[derive(Debug, Clone)]
pub struct DeviceSummary {
    pub mac: String,
    pub name: String,
    pub vendor: String,
    pub category: String,
    pub sightings: usize,
    pub rssi_avg: Option<i16>,
    pub first_ms: i64,
    pub last_ms: i64,
    pub is_followed: bool,
    pub is_tracker: bool,
    pub cve_count: usize,
}

/// Il report completo: dati, non HTML. Chi lo rende decide come mostrarlo.
#[derive(Debug, Clone)]
pub struct Report {
    pub generated_ms: i64,
    pub from_ms: i64,
    pub to_ms: i64,
    pub station_mac: String,
    pub station_name: String,
    pub title: String,
    pub anonymize: bool,
    pub full_appendix: bool,
    /// Frase in linguaggio naturale: vedi [`summarize`].
    pub summary: String,
    /// true se l'intervallo e' stato ridotto a [`MAX_SPAN_S`].
    pub truncated: bool,
    /// true se non c'e' nessun dato nell'intervallo.
    pub empty: bool,
    pub counts: ReportCounts,
    pub followed: Vec<FollowedDevice>,
    pub events: Vec<ReportEvent>,
    pub all_devices: Vec<DeviceSummary>,
    /// true se `presenze.csv` non esiste o non e' leggibile: e' un caso diverso
    /// da "esiste ma non aveva righe in questa fascia", e il report lo dice.
    pub no_source: bool,
    /// true se il `raw_log.jsonl` ha fornito dati nell'intervallo. Se e' false,
    /// localizzatori e CVE non sono verificabili e il report lo dichiara.
    pub raw_available: bool,
}

// --- costruzione -----------------------------------------------------------

/// Costruisce il report dai file accanto all'eseguibile.
pub fn build(config: &ReportConfig) -> Result<Report, String> {
    build_from(config, &Sources::real())
}

/// Il motore vero: legge, aggrega, risolve l'intervallo.
///
/// Non fallisce per file mancanti: vedi la nota sul modulo. L'unico `Err`
/// possibile e' un intervallo vuoto o invertito, che e' un errore di chi
/// chiede (e in quel caso non c'e' nessun report da produrre).
///
/// Non riceve un `Logger` di proposito: l'unica cosa che aveva da dire era
/// "intervallo ridotto a 7 giorni", e quella e' gia' un campo del `Report`
/// (`truncated`) che il chiamante puo' loggare come meglio crede. Cosi' il
/// report si puo' costruire anche dall'endpoint HTTP, dove non c'e' un logger
/// di mano, senza doverne inventare uno.
pub fn build_from(config: &ReportConfig, src: &Sources) -> Result<Report, String> {
    let all = crate::patterns::load_sightings(&src.presenze);
    let no_source = !src.presenze.exists();

    // Intervallo: quello chiesto, o (default) tutto quello che c'e'.
    //
    // Le tre regole, in quest'ordine:
    //  1. `to` di default e' l'ultimo dato, non "adesso": se il file si
    //     ferma a ieri, un report che dicesse "fino ad adesso" mostrerebbe
    //     un vuoto in coda che non e' un dato mancante, e' solo che il PC ha
    //     smesso di registrare.
    //  2. `from` di default e' il primo dato. Se l'utente chiede una fascia
    //     che comincia prima dei dati, parte dal primo dato: mostrare una
    //     parte vuota a sinistra e' rumore, non informazione.
    //  3. il limite di 7 giorni morde sempre, e quando morde lo dichiariamo.
    let now = now_s();
    let data_from = all.iter().map(|s| s.epoch).min().unwrap_or(now);
    let data_to = all.iter().map(|s| s.epoch).max().unwrap_or(now);
    let mut to_s = config.to_ms.map(|ms| ms / 1000).unwrap_or(data_to);
    let mut from_s = config
        .from_ms
        .map(|ms| ms / 1000)
        .unwrap_or(data_from)
        .max(data_from);
    if to_s < from_s {
        return Err(format!(
            "intervallo vuoto o invertito: '{}' e' dopo '{}'",
            crate::logging::rfc3339_millis(to_s * 1000),
            crate::logging::rfc3339_millis(from_s * 1000)
        ));
    }
    let mut truncated = false;
    if to_s - from_s > MAX_SPAN_S {
        from_s = to_s - MAX_SPAN_S;
        truncated = true;
    }
    // Un solo avvistamento in tutto il file darebbe un intervallo di un
    // istante, e ogni cosa successiva a quell'istante (un pacchetto del raw
    // log un secondo dopo, un evento del monitor) cadrebbe fuori per arrotondamento
    // invece che per un motivo vero. Un secondo di finestra minima e' la
    // correzione piu' piccola che non cambia nessun conteggio.
    if to_s <= from_s {
        to_s = from_s + 1;
    }

    let in_range: Vec<&Sighting> = all
        .iter()
        .filter(|s| s.epoch >= from_s && s.epoch <= to_s)
        .collect();

    // Raggruppo per MAC: tutto il resto nasce da qui.
    let mut per_mac: BTreeMap<String, Vec<&Sighting>> = BTreeMap::new();
    for s in &in_range {
        per_mac.entry(s.mac.to_uppercase()).or_default().push(s);
    }

    let known: HashSet<String> = crate::known::list(&src.known)
        .iter()
        .map(|k| k.mac.to_uppercase())
        .collect();
    let known_by_mac: HashMap<String, crate::btclassic::KnownBt> = crate::known::list(&src.known)
        .into_iter()
        .map(|k| (k.mac.to_uppercase(), k))
        .collect();

    let cve_db = crate::cves::db();
    let mut all_devices: Vec<DeviceSummary> = Vec::new();
    // `presenze.csv` non porta il campo `hint` (l'etichetta con cui
    // `blewatcher` riconosce i localizzatori) ne' il Model ID Fast Pair: le sue
    // colonne sono nome, persona, RSSI, fingerprint, vendor, stato. Quindi
    // **tracker e CVE si ricavano dal `raw_log`**, che ha entrambi. Se il raw
    // log non c'e' (perche' la registrazione per-pacchetto era spenta) il
    // report lo dichiara invece di far finta di aver guardato: contare zero
    // localizzatori quando non abbiamo guardato sarebbe un'affermazione
    // falsa, e il report esiste per essere mandato a qualcun altro.
    let extra = RawExtra::read(&src.raw_log_dir, from_s * 1000, to_s * 1000);

    let mut counts = ReportCounts {
        sightings: in_range.len(),
        ..Default::default()
    };
    let mut events: Vec<ReportEvent> = Vec::new();
    let mut cve_devices = 0usize;
    // I localizzatori si contano per **fingerprint**, non per MAC. Su una
    // cattura reale un solo AirTag puo' comparire sotto 100 indirizzi diversi
    // (ruota ogni 15 minuti), e dire "108 localizzatori" sarebbe sbagliato
    // per un ordine di grandezza. Il numero di MAC resta disponibile per
    // capire quanto e' stato frammentato.
    let mut tracker_fps: HashSet<String> = HashSet::new();
    let mut tracker_macs = 0usize;

    for (mac, rows) in &per_mac {
        let first = rows.first().map(|s| s.epoch).unwrap_or(from_s);
        let last = rows.last().map(|s| s.epoch).unwrap_or(from_s);
        let name = best_name(rows);
        let vendor = best_vendor(rows);
        let category = crate::classify::classify_device(
            Some(&name),
            if vendor.is_empty() {
                None
            } else {
                Some(&vendor)
            },
            None,
        )
        .label()
        .to_string();
        // Dal CSV arrivano nome, vendor e l'etichetta dell'annuncio; dal raw
        // log (se c'e') il Model ID Fast Pair, che rende il match delle CVE
        // molto piu' preciso del solo nome. La seconda fonte e' un
        // miglioramento, non un requisito: senza raw log i localizzatori si
        // vedono lo stesso, cambia solo la precisione delle CVE.
        let x = extra.by_mac.get(mac);
        // L'hint e' una classificazione dell'annuncio. Se il CSV non lo
        // contiene, quello del raw log serve lo stesso: perdere un
        // localizzatore riconosciuto perche' la colonna era vuota sarebbe
        // una perdita
        // gratuita di informazione.
        let hint = {
            let dal_csv = hint_of(rows);
            if dal_csv.is_empty() {
                x.map(|x| x.hint.as_str()).unwrap_or("")
            } else {
                dal_csv
            }
        };
        let model_id = x.and_then(|x| x.model_id);
        let cves = crate::cves::match_cves(cve_db, model_id, &name, &vendor, hint, mac);
        let family = tracker_family(hint);
        let is_tracker = family.is_some();
        let identified = !name.is_empty() || !vendor.is_empty();
        if identified {
            counts.identified += 1;
        } else {
            counts.unknown += 1;
        }
        if is_tracker {
            tracker_macs += 1;
            tracker_fps.insert(fp_of(rows, mac));
        }
        if !cves.is_empty() {
            cve_devices += 1;
        }
        if let Some(fam) = family {
            events.push(ReportEvent {
                ts_ms: first * 1000,
                kind: EventKind::Tracker,
                mac: mac.clone(),
                name: name.clone(),
                // Il conteggio viene dal CSV delle presenze, non dal raw log: `packets`
                // vale 0 quando il raw log non copre quel MAC, e un "0
                // pacchetti" accanto a un dispositivo appena classificato
                // come localizzatore sarebbe una frase falsa.
                detail: format!(
                    "{} — {} avvistament{} nell'intervallo{}",
                    fam,
                    rows.len(),
                    if rows.len() == 1 { "o" } else { "i" },
                    rssi_suffix(rows)
                ),
            });
        }
        if let Some(c) = cves.first() {
            events.push(ReportEvent {
                ts_ms: first * 1000,
                kind: EventKind::Cve,
                mac: mac.clone(),
                name: name.clone(),
                // `CveEntry` non implementa `Display` (la dashboard compone la
                // riga a pezzi): qui la compongo allo stesso modo, con
                // vendor+modello, identificativo e descrizione.
                detail: format!("{} — {}: {}", c.cve, c.model, c.description),
            });
        }
        all_devices.push(DeviceSummary {
            mac: mac.clone(),
            name: name.clone(),
            vendor: vendor.clone(),
            category,
            sightings: rows.len(),
            rssi_avg: avg_rssi(rows),
            first_ms: first * 1000,
            last_ms: last * 1000,
            is_followed: known.contains(mac),
            is_tracker,
            cve_count: cves.len(),
        });
    }
    counts.total_unique = per_mac.len();
    counts.cve_count = cve_devices;
    counts.tracker_count = tracker_fps.len();
    counts.tracker_macs = tracker_macs;
    counts.session_duration_s = (to_s - from_s).max(0);

    // Dispositivi seguiti: solo quelli che ci sono davvero nell'intervallo.
    let mut followed: Vec<FollowedDevice> = Vec::new();
    for (mac, rows) in &per_mac {
        if !known.contains(mac) {
            continue;
        }
        let times: Vec<i64> = rows.iter().map(|s| s.epoch).collect();
        // I segmenti vanno in **millisecondi**, come `first_ms`/`last_ms` e
        // come l'intervallo del report: `epoch` del CSV e' in secondi, e la
        // timeline calcola le coordinate in funzione dei millisecondi. Mescolare
        // le due unita' non dà un errore ( entrambi sono interi), dà `x` a
        // milioni di unita' e una barra completamente vuota: un difetto che si
        // vede solo guardando il file generato.
        let times_ms: Vec<i64> = times.iter().map(|t| t * 1000).collect();
        let (days, grid) = hour_day_grid(rows);
        let k = known_by_mac.get(mac);
        let segments = segments_of(&times_ms);
        followed.push(FollowedDevice {
            mac: mac.clone(),
            name: k.map(|k| k.nome.clone()).unwrap_or_else(|| best_name(rows)),
            // `bt_known.txt` e' la fonte primaria; il CSV tiene la persona
            // per i dispositivi noti e fa da piano B se il file e' stato
            // spostato o cancellato dopo la registrazione.
            persona: k
                .map(|k| k.persona.clone())
                .filter(|p| !p.trim().is_empty())
                .unwrap_or_else(|| best_persona(rows)),
            first_ms: times.first().copied().unwrap_or(from_s) * 1000,
            last_ms: times.last().copied().unwrap_or(from_s) * 1000,
            span_s: (times.last().copied().unwrap_or(from_s)
                - times.first().copied().unwrap_or(from_s))
            .max(0),
            segments,
            sightings: rows.len(),
            rssi_avg: avg_rssi(rows),
            visits: 0,
            pattern: pattern_it(&times),
            days,
            grid,
            cves: crate::cves::match_cves(
                cve_db,
                extra.by_mac.get(mac).and_then(|x| x.model_id),
                &best_name(rows),
                &best_vendor(rows),
                hint_of(rows),
                mac,
            ),
        });
    }
    // I piu' presenti in cima: se il report si legge in 30 secondi, la prima
    // cosa che conta e' chi c'era di piu'. La finestra e' il dato che ci
    // avvicina di piu' a "chi era qui", senza fingere di sapere quanto.
    followed.sort_by(|a, b| {
        b.span_s
            .cmp(&a.span_s)
            .then(b.sightings.cmp(&a.sightings))
            .then(a.mac.cmp(&b.mac))
    });
    for f in followed.iter_mut() {
        f.visits = f.segments.len();
    }
    counts.followed = followed.len();

    // Eventi dai dati aggregati: rotazione dei MAC e comparse.
    events.extend(rotation_events(&per_mac));
    events.extend(new_device_events(&per_mac, &all, from_s));
    events.extend(spam_events(&src.inq_events, from_s, to_s));
    events.sort_by_key(|e| e.ts_ms);
    // I conteggi per tipo di evento si derivano dagli eventi invece di
    // essere incrementati sul posto: altrimenti basta dimenticarsi un
    // `counts.spam_events += 1` (che e' esattamente quello che era successo)
    // perche' il riepilogo dica "nessuno spam" mentre la lista eventi ne
    // elenca uno. Un solo posto dove il numero puo' nascere.
    counts.spam_events = events.iter().filter(|e| e.kind == EventKind::Spam).count();

    // Stazione: la colonna `stazione` del CSV la scrive chi ha registrato,
    // quindi e' un dato e non una deduzione. Se manca, non si inventa.
    let station = per_mac
        .values()
        .flatten()
        .find_map(|s| non_empty(&s.station))
        .unwrap_or_default();
    let (station_mac, station_name) = split_station(station);

    let mut report = Report {
        generated_ms: now_ms(),
        from_ms: from_s * 1000,
        to_ms: to_s * 1000,
        station_mac,
        station_name,
        title: config
            .title
            .clone()
            .unwrap_or_else(|| "Report di presenza".to_string()),
        anonymize: config.anonymize,
        full_appendix: config.full_appendix,
        summary: String::new(),
        truncated,
        empty: in_range.is_empty(),
        counts,
        followed,
        events,
        all_devices,
        no_source,
        raw_available: extra.available,
    };
    report.summary = summarize(&report);
    Ok(report)
}

// --- il riassunto in linguaggio naturale ------------------------------------

/// Compone la frase di apertura del report.
///
/// Logica condizionale, non un modello: il punto e' che la frase sia sempre
/// ricavabile dai numeri, e che non dica piu' di quello che i dati mostrano.
/// "Nessun evento notevole rilevato" non viene seguito da "sei al sicuro",
/// perche' un assenza di eventi e' un fatto su un intervallo, non un verdetto.
pub fn summarize(r: &Report) -> String {
    if r.empty {
        return if r.no_source {
            "Nessun dato disponibile: presenze.csv non e' presente accanto all'eseguibile. \
             Il report e' vuoto perche' non c'e' niente da cui leggerlo, non perche' non sia \
             successo nulla."
                .to_string()
        } else {
            "Nessun dato nell'intervallo richiesto. Il file c'e', ma non contiene righe in \
             questa fascia oraria: nessun dispositivo e' stato osservato in quel periodo."
                .to_string()
        };
    }
    let dur = fmt_dur(r.counts.session_duration_s);
    let mut s = format!(
        "Nella sessione di {dur} del {} sono stati osservati {} dispositivi unici ({} avvistamenti).",
        fmt_day(r.from_ms),
        r.counts.total_unique,
        r.counts.sightings
    );

    // Il dispositivo seguito piu' a lungo: e' l'unica riga che riguarda
    // direttamente l'utente, e per un report di trenta secondi viene prima
    // dei numeri. Se ha un nome, il nome e' dell'utente (l'ha messo lui in
    // `bt_known.txt`): non lo deduciamo.
    if let Some(top) = r.followed.first() {
        s.push_str(&format!(
            " Il dispositivo seguito piu' a lungo ({}) e' stato sentito fra le {} e le {}, \
             in {} avvistament{} e {}.",
            if top.name.is_empty() {
                top.mac.clone()
            } else {
                top.name.clone()
            },
            fmt_time(top.first_ms),
            fmt_time(top.last_ms),
            top.sightings,
            if top.sightings == 1 { "o" } else { "i" },
            if top.visits <= 1 {
                "un'unica visita".to_string()
            } else {
                format!("{} visite", top.visits)
            }
        ));
    }

    if r.counts.tracker_count > 0 {
        s.push_str(&format!(
            " Sono stati rilevati {} localizzatori noti (AirTag, SmartTag, Tile e simili){}. \
             Sono dispositivi come altri: se non sono tuoi, possono stare su oggetti smarriti \
             o su veicoli nelle vicinanze.",
            r.counts.tracker_count,
            if r.counts.tracker_macs > r.counts.tracker_count {
                format!(
                    ", visti sotto {} indirizzi diversi: gli accessori e i telefoni recenti \
                     cambiano MAC per privacy, quindi alcuni sono quasi certamente lo stesso \
                     oggetto",
                    r.counts.tracker_macs
                )
            } else {
                String::new()
            }
        ));
    }
    if r.counts.cve_count > 0 {
        s.push_str(&format!(
            " {} dispositivi hanno un profilo che matcha una vulnerabilita' nota.",
            r.counts.cve_count
        ));
    }
    if r.counts.spam_events > 0 {
        s.push_str(&format!(
            " Sono stati registrati {} eventi di spam BLE (annunci popup ripetuti).",
            r.counts.spam_events
        ));
    }
    if r.counts.tracker_count == 0 && r.counts.cve_count == 0 && r.counts.spam_events == 0 {
        s.push_str(if r.raw_available {
            " Nessun evento notevole e' stato registrato in questo intervallo."
        } else {
            // La frase normale sarebbe falsa: senza il raw log non abbiamo
            // guardato abbastanza per dire che non c'era niente.
            " Nessun evento notevole fra quelli ricavabili dal CSV di presenze, ma la \
             registrazione per-pacchetto (raw_log) non copre questo intervallo: senza di \
             questa i localizzatori e le vulnerabilita' non sono verificabili."
        });
    }
    if r.counts.session_duration_s < 3600 {
        s.push_str(
            " Sessione breve: sotto un'ora l'osservazione dice poco, \
                    un intervallo di qualche ora rende i confronti leggibili.",
        );
    }
    s
}

// --- rendering -------------------------------------------------------------

/// Rende il `Report` in HTML autonomo.
///
/// Nessun JavaScript, nessuna risorsa esterna: tutto dentro. La timeline e' un
/// `<svg>` inline perche' in stampa scala come nel browser e perche' le
/// coordinate sono verificabili da un test, mentre un `div` con percentuali
///finirebbe per essere verificato solo guardandolo.
pub fn render_html(r: &Report) -> String {
    let mac = |m: &str| -> String {
        if r.anonymize {
            mask_mac(m)
        } else {
            m.to_string()
        }
    };
    let mut out = String::with_capacity(32_768);
    out.push_str("<!DOCTYPE html>\n<html lang=\"it\">\n<head>\n");
    out.push_str("<meta charset=\"UTF-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    out.push_str(&format!(
        "<title>bluesniff — {}</title>\n<style>\n{}\n</style>\n</head>\n<body>\n",
        escape_html(&r.title),
        CSS
    ));

    // A. Intestazione
    out.push_str("<header class=\"report-header\">\n");
    out.push_str(&format!(
        "<h1>bluesniff <span class=\"accent\">— {}</span></h1>\n",
        escape_html(&r.title)
    ));
    out.push_str(&format!(
        "<p class=\"subtitle\">{} → {}</p>\n",
        escape_html(&fmt_datetime(r.from_ms)),
        escape_html(&fmt_datetime(r.to_ms))
    ));
    out.push_str(&format!(
        "<p class=\"meta\">Stazione: <code>{}</code>{} · Report generato il {} (UTC)</p>\n",
        escape_html(&mac(&r.station_mac)),
        if r.station_name.is_empty() {
            String::new()
        } else {
            format!(" su <strong>{}</strong>", escape_html(&r.station_name))
        },
        escape_html(&fmt_datetime(r.generated_ms))
    ));
    if r.anonymize {
        out.push_str(
            "<p class=\"meta anon\">MAC parzialmente mascherati (ultimi 3 byte): \
             <code>AA:BB:CC:XX:XX:XX</code>.</p>\n",
        );
    }
    out.push_str("</header>\n");

    if r.truncated {
        out.push_str(
            "<p class=\"notice\">⚠ L'intervallo richiesto e' piu' lungo di 7 giorni ed e' stato \
             ridotto. Per periodi piu' lunghi conviene generare un report per volta.</p>\n",
        );
    }
    if !r.raw_available && !r.empty {
        out.push_str(
            "<p class=\"notice\">⚠ La registrazione per-pacchetto (<code>raw_log</code>) non \
             copre questo intervallo. I dati di presenza sono completi, ma i localizzatori \
             (AirTag, SmartTag, Tile) e il confronto con le CVE note non sono verificabili: \
             senza quel file bluesniff vede solo che un dispositivo si e' annunciato, non \
             *che cosa* e'.</p>\n",
        );
    }

    // Sommario
    out.push_str(&format!(
        "<section class=\"summary\"><p class=\"lead\">{}</p></section>\n",
        escape_html(&r.summary)
    ));

    // B. Conteggi
    out.push_str("<section class=\"counts\">\n");
    for (v, label, warn_if_nonzero) in [
        (r.counts.total_unique, "Dispositivi unici", false),
        (r.counts.followed, "Seguiti", false),
        (r.counts.cve_count, "Con CVE note", true),
        (r.counts.tracker_count, "Localizzatori", true),
        (r.counts.identified, "Identificati", false),
        (r.counts.unknown, "Anonimi", false),
    ] {
        // Il bordo ambra segnala "guarda qui". Su uno zero e' un allarme a
        // vuoto: il lettore impara a ignorare il colore, e il giorno che il
        // numero conta davvero non lo vede piu'.
        let cls = if warn_if_nonzero && v > 0 {
            " warn"
        } else {
            ""
        };
        out.push_str(&format!(
            "<div class=\"count-card{cls}\"><div class=\"count-value\">{v}</div>\
             <div class=\"count-label\">{label}</div></div>\n"
        ));
    }
    out.push_str("</section>\n");

    // C. Dispositivi seguiti con timeline
    out.push_str("<section class=\"followed\">\n<h2>Dispositivi seguiti</h2>\n");
    if r.followed.is_empty() {
        out.push_str(
            "<p class=\"empty\">Nessun dispositivo seguito in questo intervallo. \
             Nella dashboard si segue un dispositivo con <b>⭐ Segui</b>; da riga di comando \
             con <code>bluesniff --follow &lt;MAC&gt;</code>. I dispositivi seguiti sono quelli \
             per cui bluesniff interroga attivamente il telefono e avvisa quando arriva o parte.</p>\n",
        );
    } else {
        out.push_str(
            "<p class=\"note\">Le barre dicono <b>quando</b> il dispositivo e' stato vicino al PC, \
             non <b>dove</b>: la radio conosce la forza del segnale, non la posizione.</p>\n",
        );
        for f in &r.followed {
            out.push_str(&render_followed(r, f, &mac));
        }
    }
    out.push_str("</section>\n");

    // D. Heatmap dei seguiti
    if !r.followed.is_empty() {
        out.push_str("<section class=\"heatmap\"><h2>Quando sono stati visti</h2>\n");
        for f in &r.followed {
            out.push_str(&render_heatmap(f, &mac(&f.mac)));
        }
        out.push_str("</section>\n");
    }

    // E. Eventi notevoli
    out.push_str("<section class=\"events\"><h2>Eventi notevoli</h2>\n");
    if r.events.is_empty() {
        out.push_str(
            "<p class=\"empty\">Nessun evento notevole in questo intervallo. \
             Vuol dire che non e' stata registrata nessuna vulnerabilita' nota, nessun \
             localizzatore riconosciuto, nessun cambio di MAC sospetto e nessun spam BLE: \
             non che la zona sia sicura.</p>\n",
        );
    } else {
        out.push_str("<ul class=\"event-list\">\n");
        // 50 eventi sono gia' piu' di quanti se ne leggano: oltre, il report
        // smette di essere un riassunto e diventa un dump, che e' il ruolo
        // dell'appendice.
        let shown = r.events.len().min(50);
        for e in &r.events[..shown] {
            out.push_str(&format!(
                "<li class=\"event event-{}\"><span class=\"event-time\">{}</span>\
                 <span class=\"event-badge\">{}</span>\
                 <span class=\"event-desc\"><b>{}</b> <code>{}</code> — {}</span></li>\n",
                event_class(e.kind),
                escape_html(&fmt_time(e.ts_ms)),
                e.kind.badge(),
                escape_html(&e.name),
                escape_html(&mac(&e.mac)),
                escape_html(&e.detail)
            ));
        }
        out.push_str("</ul>\n");
        if r.events.len() > shown {
            out.push_str(&format!(
                "<p class=\"note\">e altri {} eventi non mostrati: l'elenco completo e' in appendice.</p>\n",
                r.events.len() - shown
            ));
        }
    }
    out.push_str("</section>\n");

    // Appendice
    if r.full_appendix {
        out.push_str(&render_appendix(r, &mac));
    }
    out.push_str(&render_notes(r));

    out.push_str(
        "<footer><p>Report generato da <strong>bluesniff</strong>.</p>\
         <p class=\"disclaimer\">I dati rappresentano solo cio' che la radio Bluetooth ha \
         ricevuto. Un dispositivo assente dal report puo' essere spento, fuori portata, \
         in tasca, o aver cambiato MAC.</p></footer>\n</body>\n</html>\n",
    );
    out
}

fn event_class(k: EventKind) -> &'static str {
    match k {
        EventKind::Cve => "cve",
        EventKind::Tracker => "tracker",
        EventKind::Spam => "spam",
        EventKind::Rotating => "rotating",
        EventKind::NewDevice => "new",
    }
}

fn render_followed(r: &Report, f: &FollowedDevice, mac: &dyn Fn(&str) -> String) -> String {
    let mut s = String::new();
    s.push_str("<article class=\"device\">\n<div class=\"device-header\">");
    s.push_str(&format!(
        "<span class=\"device-name\">{}</span>",
        escape_html(&f.name)
    ));
    if !f.persona.is_empty() {
        s.push_str(&format!(
            "<span class=\"device-persona\">di {}</span>",
            escape_html(&f.persona)
        ));
    }
    s.push_str(&format!(
        "<code class=\"device-mac\">{}</code>",
        escape_html(&mac(&f.mac))
    ));
    s.push_str("</div>\n");
    s.push_str(&timeline_svg(r.from_ms, r.to_ms, &f.segments));
    s.push_str(&format!(
        "<p class=\"device-stats\">Sentito fra le <b>{}</b> e le <b>{}</b> · finestra {} · \
         {} avvistament{} · {} visita{} · RSSI medio {}{} · pattern: {}</p>\n",
        escape_html(&fmt_time(f.first_ms)),
        escape_html(&fmt_time(f.last_ms)),
        fmt_dur(f.span_s),
        f.sightings,
        if f.sightings == 1 { "o" } else { "i" },
        f.visits,
        if f.visits == 1 { "" } else { "e" },
        rssi_avg_text(f.rssi_avg),
        if f.cves.is_empty() {
            String::new()
        } else {
            format!(" · {} CVE note", f.cves.len())
        },
        escape_html(&f.pattern)
    ));
    s.push_str("</article>\n");
    s
}

/// La timeline in `<svg>`.
///
/// Coordinate in un `viewBox` fisso di 1000 unita' e `preserveAspectRatio`
/// deformante: cosi' la barra occupa sempre tutta la larghezza disponibile
/// senza dover calcolare pixel, e in stampa si comporta come in schermo.
fn timeline_svg(from_ms: i64, to_ms: i64, segments: &[Segment]) -> String {
    const W: f64 = 1000.0;
    let span = (to_ms - from_ms).max(1) as f64;
    let mut s = String::from("<svg class=\"timeline\" viewBox=\"0 0 1000 46\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"Periodi di presenza\">\n");
    s.push_str("<rect x=\"0\" y=\"4\" width=\"1000\" height=\"16\" class=\"tl-bg\"/>\n");
    for seg in segments {
        let x = (seg.from_ms - from_ms) as f64 / span * W;
        let w = ((seg.to_ms - seg.from_ms) as f64 / span * W).max(0.8);
        s.push_str(&format!(
            "<rect x=\"{x:.2}\" y=\"4\" width=\"{w:.2}\" height=\"16\" class=\"tl-on\"/>\n"
        ));
    }
    s.push_str(&format!(
        "<text x=\"0\" y=\"38\" class=\"tl-tick\">{}</text>\n\
         <text x=\"1000\" y=\"38\" text-anchor=\"end\" class=\"tl-tick\">{}</text>\n\
         </svg>\n",
        escape_html(&fmt_time(from_ms)),
        escape_html(&fmt_time(to_ms))
    ));
    s
}

/// Heatmap 24×7 in CSS grid: cinque livelli di intensita'.
///
/// Cinque e non continuum perche' una sfumatura continua su una cella di 12px
/// e' indistinguibile, e l'occhio deve poter contare le celle "piene" senza
/// dover indovinarlo. Il livello e' sempre accompagnato dal numero nel
/// `title`, cosi' l'informazione non e' solo nel colore (accessibilita').
fn render_heatmap(f: &FollowedDevice, mac_label: &str) -> String {
    const DAY_IT: [&str; 7] = ["Lun", "Mar", "Mer", "Gio", "Ven", "Sab", "Dom"];
    let max = f.grid.iter().flatten().copied().max().unwrap_or(0).max(1);
    let mut s = String::new();
    s.push_str(&format!(
        "<div class=\"heat\"><div class=\"heat-title\">{} <code>{}</code></div>\n<div class=\"heat-grid\">",
        escape_html(&f.name),
        escape_html(mac_label)
    ));
    s.push_str("<div class=\"heat-corner\"></div>");
    for h in 0..24 {
        // Un'etichetta ogni tre ore: 24 numeri su una griglia stretta (su un
        // telefono la cella e' di pochi pixel) si sovrapporrebbero, e il
        // risultato sarebbe illeggibile proprio sul dispositivo dove serve di
        // piu'.
        s.push_str(&format!(
            "<div class=\"heat-hour\">{}</div>",
            if h % 3 == 0 {
                format!("{h:02}")
            } else {
                String::new()
            }
        ));
    }
    for (d, day) in DAY_IT.iter().enumerate() {
        s.push_str(&format!("<div class=\"heat-day\">{day}</div>"));
        for h in 0..24 {
            let n = f.grid[d][h];
            let lvl = if n == 0 {
                0
            } else {
                ((n as f32 / max as f32) * 4.0).round().clamp(1.0, 4.0) as u8
            };
            // Il livello non e' l'unica informazione: il numero e' nel `title`
            // e in un `aria-label`, cosi' chi non distingue i colori (o legge con
            // uno screen reader) ottiene lo stesso dato.
            s.push_str(&format!(
                "<div class=\"heat-cell l{lvl}\" title=\"{day} {h:02}:00 — {n} avvistament{} ({})\" \
                 aria-label=\"{day} {h:02}:00: {n}\"></div>",
                if n == 1 { "o" } else { "i" },
                if f.days[d] > 0 {
                    "giornata attiva"
                } else {
                    "giornata senza dati"
                }
            ));
        }
    }
    s.push_str("</div></div>\n");
    s
}

fn render_appendix(r: &Report, mac: &dyn Fn(&str) -> String) -> String {
    let mut s = String::from("<details class=\"appendix\">\n<summary>");
    s.push_str(&format!(
        "Tutti i dispositivi osservati ({})</summary>\n<table>\n\
         <thead><tr><th>Nome</th><th>MAC</th><th>Vendor</th><th>Classe</th>\
         <th>Avv.</th><th>RSSI medio</th><th>Primo</th><th>Ultimo</th><th>Note</th></tr></thead>\n<tbody>\n",
        r.all_devices.len()
    ));
    let mut rows: Vec<&DeviceSummary> = r.all_devices.iter().collect();
    rows.sort_by(|a, b| b.sightings.cmp(&a.sightings).then(a.mac.cmp(&b.mac)));
    for d in rows.iter().take(300) {
        let mut note: Vec<String> = Vec::new();
        if d.is_followed {
            note.push("seguito".to_string());
        }
        if d.is_tracker {
            note.push("localizzatore".to_string());
        }
        if d.cve_count > 0 {
            note.push(format!("{} CVE", d.cve_count));
        }
        s.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape_html(&d.name),
            escape_html(&mac(&d.mac)),
            escape_html(&d.vendor),
            escape_html(&d.category),
            d.sightings,
            rssi_avg_text(d.rssi_avg),
            escape_html(&fmt_time(d.first_ms)),
            escape_html(&fmt_time(d.last_ms)),
            escape_html(&note.join(", "))
        ));
    }
    s.push_str("</tbody>\n</table>\n");
    if r.all_devices.len() > 300 {
        s.push_str(&format!(
            "<p class=\"note\">Mostrati i primi 300 di {} dispositivi, in ordine di avvistamenti. \
             L'elenco completo e' in <code>presenze.csv</code>.</p>\n",
            r.all_devices.len()
        ));
    }
    s.push_str("</details>\n");
    s
}

/// Le note metodologiche: la sezione che impedisce le letture sbagliate.
///
/// Sta in un `<details>` chiuso perche' nessuno la legge, ma e' esattamente il
/// posto dove vanno le risposte alle domande che il grafico non puo' fare
/// ("perche' questo dispositivo compare tre volte?").
fn render_notes(r: &Report) -> String {
    let mut s = String::from(
        "<details class=\"appendix\">\n<summary>Come leggere questo report (note metodologiche)</summary>\n<div class=\"notes\">\n",
    );
    s.push_str(
        "<p><b>Cosa significa la barra di ogni dispositivo.</b> La barra mostra <b>quando</b> \
         lo abbiamo sentito: ogni segmento e' una visita, e due segmenti sono due visite quando \
         fra loro c'e' stata una pausa di almeno 4 minuti. Il tempo di presenza vero non e' \
         misurabile con questi dati — un dispositivo sentito alle 08:00 e alle 08:20 non e' stato \
         \"presente 20 minuti\", e' stato sentito due volte. Per questo il report parla di \
         \"finestra\" e di \"avvistamenti\", non di presenza.</p>\n\
         <p><b>Cosa NON significa.</b> Il report non sa dove siete state. \"Vicino al PC\" e' tutto \
         cio' che i dati permettono di dire: man mano, piano e stanza non esistono in nessun \
         annuncio Bluetooth.</p>\n\
         <p><b>Perche' lo stesso dispositivo compare piu' volte.</b> Molti telefoni e accessori \
         ruotano il MAC ogni 15 minuti per privacy. Sono lo stesso dispositivo fisico con \
         indirizzi diversi, e bluesniff non puo' dimostrarlo con certezza: lo segnala come \
         \"fingerprint su piu' MAC\" quando succede piu' di due volte.</p>\n\
         <p><b>Perche' alcuni indirizzi sono casuali.</b> Se un indirizzo cambia nel tempo non e' \
         un difetto: e' il funzionamento normale del Bluetooth moderno. Un indirizzo casuale non \
         e' pero' utilizzabile per le notifiche di presenza, che cercano il telefono con un \
         indirizzo Classic stabile.</p>\n\
         <p><b>Cosa e' un \"localizzatore\".</b> Un dispositivo che annuncia una rete di \
         localizzazione (Apple Find My, Samsung SmartTag, Tile e simili). Sono oggetti comuni: \
         chiavi, zaini, auto. Trovarli non e' un allarme, e il report non li collega a nessuna \
         persona.</p>\n\
         <p><b>Cosa e' una CVE.</b> Il profilo del dispositivo (modello, vendor, Model ID) combacia \
         con una voce del database. E' un'abbinamento di nomi, non un test di sicurezza: \
         significa \"potrebbe esserci questo problema noto\", non \"e' compromesso\".</p>\n",
    );
    if r.anonymize {
        s.push_str(
            "<p><b>Anonimizzazione.</b> In questo report gli ultimi 3 byte di ogni MAC sono \
             sostituiti. I file su disco non sono stati toccati: e' una vista per la \
             condivisione, non una cancellazione.</p>\n",
        );
    }
    s.push_str("</div>\n</details>\n");
    s
}

/// Quello che il solo `presenze.csv` non puo' dire.
///
/// Il CSV ha colonne e RSSI, ma non l'etichetta `hint` con cui il
/// `blewatcher` riconosce un localizzatore, ne' il Model ID Fast Pair con cui
/// il database delle CVE fa il match piu' preciso. Entrambi stanno nel
/// `raw_log.jsonl`, quindi il report lo legge come seconda fonte.
///
/// Se il raw log non c'e' il report **non puo'** concludere che non ci siano
/// tracker o vulnerabilita': lo dichiara con `raw_available = false`, e il
/// sommario lo dice. Un report che dicesse "nessun localizzatore" perche' non
/// ha guardato sarebbe peggio di un report che non dice niente.
struct RawExtra {
    by_mac: HashMap<String, RawDevice>,
    /// true se il raw log esisteva e aveva righe nell'intervallo.
    available: bool,
}

#[derive(Default)]
struct RawDevice {
    hint: String,
    model_id: Option<u32>,
}

impl RawExtra {
    fn read(dir: &Path, from_ms: i64, to_ms: i64) -> Self {
        let lines = crate::rawlog::iter_lines_in_dir(dir, from_ms, to_ms);
        let available = !lines.is_empty();
        let mut by_mac: HashMap<String, RawDevice> = HashMap::new();
        for line in &lines {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(mac) = v.get("mac").and_then(|x| x.as_str()) else {
                continue;
            };
            let e = by_mac.entry(mac.to_uppercase()).or_default();
            // L'ultimo hint visto vale: e' una classificazione, non una
            // misura, e la piu' recente e' quella calcolata con piu' contesto.
            if let Some(h) = v.get("hint").and_then(|x| x.as_str()) {
                if !h.trim().is_empty() {
                    e.hint = h.trim().to_string();
                }
            }
            if let Some(m) = v.get("model_id").and_then(|x| x.as_u64()) {
                e.model_id = Some(m as u32);
            }
        }
        Self { by_mac, available }
    }
}

// --- helper ----------------------------------------------------------------

fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_ms() -> i64 {
    now_s() * 1000
}

fn non_empty(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// Il nome migliore disponibile: quello pubblicizzato, o quello che
/// `bt_known.txt` ha scritto a mano. Il CSV puo' avere righe con il nome vuoto
/// (annunci senza nome) e righe con il nome: si prende quello, perche' il
/// report non deve mostrare un dispositivo senza nome quando il nome c'era.
fn best_name(rows: &[&Sighting]) -> String {
    rows.iter()
        .find_map(|s| non_empty(&s.name))
        .unwrap_or("")
        .to_string()
}

/// La chiave che identifica un dispositivo fisico: il fingerprint BLE se c'e',
/// altrimenti il MAC (un dispositivo classico non ruota l'indirizzo, quindi il
/// MAC basta e non c'e' niente da fondere).
fn fp_of(rows: &[&Sighting], mac: &str) -> String {
    rows.iter()
        .find_map(|s| non_empty(s.fingerprint.as_str()))
        .map(|f| format!("fp:{f}"))
        .unwrap_or_else(|| format!("mac:{mac}"))
}

/// La prima persona non vuota registrata nel CSV (colonna 4).
fn best_persona(rows: &[&Sighting]) -> String {
    rows.iter()
        .find_map(|s| non_empty(s.persona.as_str()))
        .unwrap_or("")
        .to_string()
}

fn best_vendor(rows: &[&Sighting]) -> String {
    rows.iter()
        .find_map(|s| non_empty(&s.vendor))
        .unwrap_or("")
        .to_string()
}

/// L'etichetta di classe dell'annuncio, se presente.
///
/// Si prende la **prima** rigola non vuota e non l'ultima: nel CSV l'hint e'
/// un'etichetta costante per dispositivo, e prendere l'ultima significherebbe
/// dipendere dall'ordine di scrittura delle righe per un dato che non cambia.
fn hint_of<'a>(rows: &[&'a Sighting]) -> &'a str {
    rows.iter()
        .find_map(|s| non_empty(s.hint.as_str()))
        .unwrap_or("")
}

fn avg_rssi(rows: &[&Sighting]) -> Option<i16> {
    let vals: Vec<i16> = rows.iter().filter_map(|s| s.rssi).collect();
    if vals.is_empty() {
        return None;
    }
    Some((vals.iter().map(|v| *v as i64).sum::<i64>() / vals.len() as i64) as i16)
}

fn rssi_suffix(rows: &[&Sighting]) -> String {
    match avg_rssi(rows) {
        Some(v) => format!(", RSSI medio {v} dBm"),
        None => String::new(),
    }
}

fn rssi_avg_text(v: Option<i16>) -> String {
    match v {
        Some(v) => format!("{v} dBm"),
        None => "—".to_string(),
    }
}

/// Griglia 24×7: quante volte il dispositivo e' stato visto in ogni ora e in
/// ogni giorno della settimana.
///
/// La stessa formula di `/api/heatmap`, con l'offset che il 1970-01-01 fosse
/// un giovedi' (lunedi' = 0 => offset 3). Riusare la formula invece di
/// copiarla vale poco da solo, ma vale molto se in futuro la griglia cambia
/// significato: due copie divergerebbero e i due report direbbero cose diverse.
fn hour_day_grid(rows: &[&Sighting]) -> ([u32; 7], [[u32; 24]; 7]) {
    let mut days = [0u32; 7];
    let mut grid = [[0u32; 24]; 7];
    for s in rows {
        let h = ((s.epoch.rem_euclid(86_400)) / 3600) as usize;
        // L'epoca Unix parte da un giovedi': +3 porta il giovedi' su indice 3
        // e il lunedi' su 0, che e' l'ordine in cui sono etichettate le righe.
        let d = ((s.epoch.div_euclid(86_400) + 3).rem_euclid(7)) as usize;
        if h < 24 && d < 7 {
            days[d] += 1;
            grid[d][h] += 1;
        }
    }
    (days, grid)
}

/// Segmenti di presenza continua: un nuovo segmento dove il gap supera
/// [`PRESENCE_GAP_S`].
///
/// Riceve e restituisce **millisecondi**: i tempi del CSV sono in secondi e la
/// timeline ragiona in millisecondi, quindi la conversione va fatta una volta
/// sola e in un posto solo.
///
/// Ogni segmento parte e finisce su un avvistamento reale, quindi la sua
/// durata non e' il tempo di presenza ma l'intervallo fra due pacchetti
/// consecutivi: e' quello che si disegna, non quello che si dichiara.
fn segments_of(times_ms: &[i64]) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    for &t in times_ms {
        match out.last_mut() {
            Some(last) if t - last.to_ms <= PRESENCE_GAP_S * 1000 => last.to_ms = t,
            _ => out.push(Segment {
                from_ms: t,
                to_ms: t,
            }),
        }
    }
    out
}

///
/// I nomi sono gli stessi che produce `bluetooth::phantom_kind` e che la
/// dashboard chiama `TRACKER_FAMILIES`, cosi' i due sistemi parlano la stessa
/// lingua. Il riconoscimento e' per *etichetta* e non per ricalcolare il
/// phantom: `phantom_kind` vuole le mappe manufacturer grezze, che nel CSV non
/// ci sono. Il limite e' dichiarato anche nelle note: dal solo `presenze.csv`
/// arrivano i tracker che `classify` sa nominare.
fn tracker_family(hint: &str) -> Option<&'static str> {
    let h = hint.to_lowercase();
    if h.contains("find my") {
        Some("Localizzatore rete Apple Find My")
    } else if h.contains("smarttag") || h.contains("smartthings find") {
        Some("Localizzatore rete Samsung SmartThings Find")
    } else if h.contains("tile") {
        Some("Localizzatore rete Tile")
    } else if h.contains("chipolo") {
        Some("Localizzatore rete Chipolo")
    } else if h.contains("pebblebee") {
        Some("Localizzatore rete Pebblebee")
    } else {
        None
    }
}

/// Traduce in italiano l'etichetta di `patterns::pattern_line`.
///
/// La funzione resta in inglese perche' e' usata anche nei report da riga di
/// comando, dove l'inglese e' coerente con il resto dell'output. Tradurla
/// li' avrebbe rotto la coerenza di quel canale; qui il report e' un documento
/// per una persona, e una frase inglese in mezzo a un testo italiano si legge
/// come un errore.
///
/// La traduzione e' una coppia di tabelle e non una catena di `replace`: con
/// la catena, un'etichetta nuova ("Constant") restava in inglese senza che
/// niente lo segnalasse — e infatti e' successo. Con le tabelle, un'etichetta
/// non tradotta resta inglese ma `pattern_it` restituisce comunque qualcosa di
/// comprensibile, e il test sotto puo' elencarle tutte.
fn pattern_it(times: &[i64]) -> String {
    let raw = crate::patterns::pattern_line(times);
    let mut out = raw.clone();
    // Frequenza.
    for (en, it) in [
        ("Constant", "costante"),
        ("Daily", "ogni giorno"),
        ("Regular", "regolare"),
        ("Occasional", "occasionale"),
        ("Rare", "raro"),
        ("rare (too few sightings)", "troppo pochi avvistamenti"),
    ] {
        out = out.replace(en, it);
    }
    // Giorni.
    for (en, it) in [
        ("Weekdays", "giorni feriali"),
        ("Weekends", "weekend"),
        ("Every day", "ogni giorno"),
    ] {
        out = out.replace(en, it);
    }
    // Fasce orarie ("evenings (5PM-9PM)").
    for (en, it) in [
        ("mornings", "mattina"),
        ("afternoons", "pomeriggio"),
        ("evenings", "sera"),
        ("overnights", "notte"),
        ("nights", "notte"),
    ] {
        out = out.replace(en, it);
    }
    out.replace("AM", "").replace("PM", "")
}

fn split_station(station: &str) -> (String, String) {
    // La colonna puo' essere "MAC" o "MAC@hostname" (una postazione che
    // raccoglie per altri). Non si inventa un nome host se non c'e'.
    match station.split_once('@') {
        Some((mac, name)) => (mac.trim().to_string(), name.trim().to_string()),
        None => (station.trim().to_string(), String::new()),
    }
}

fn rotation_events(per_mac: &BTreeMap<String, Vec<&Sighting>>) -> Vec<ReportEvent> {
    let mut per_fp: HashMap<String, Vec<&Sighting>> = HashMap::new();
    for rows in per_mac.values() {
        if let Some(fp) = rows.iter().find_map(|s| non_empty(&s.fingerprint)) {
            per_fp
                .entry(fp.to_string())
                .or_default()
                .extend(rows.iter());
        }
    }
    let mut out = Vec::new();
    for (_fp, rows) in per_fp {
        let macs: HashSet<&str> = rows.iter().map(|s| s.mac.as_str()).collect();
        // Tre indirizzi non consecutivi e non spiegati da una sola visita: la
        // soglia e' volutamente sopra il caso normale (un dispositivo che
        // ruota due volte produce tre MAC ed e' gia' un evento, non un
        // allarme).
        if macs.len() >= 3 {
            let first = rows.iter().map(|s| s.epoch).min().unwrap_or(0);
            out.push(ReportEvent {
                ts_ms: first * 1000,
                kind: EventKind::Rotating,
                mac: macs.iter().next().copied().unwrap_or("").to_string(),
                name: best_name(&rows),
                detail: format!(
                    "stesso fingerprint BLE sotto {} indirizzi diversi nell'intervallo: \
                     probabilmente un solo dispositivo che cambia MAC (la rotazione e' \
                     il comportamento normale dei telefoni recenti)",
                    macs.len()
                ),
            });
        }
    }
    out
}

/// Dispositivi comparsi per la prima volta.
///
/// "Nuovo" e' definito sul file, non sul mondo: il primo avvistamento *mai
/// registrato* cade dentro l'intervallo e il dispositivo e' comparso poche
/// volte. Senza il secondo criterio, in una sessione unica ogni dispositivo
/// sarebbe "nuovo" e l'evento non direbbe niente. Se il file copre piu'
/// sessioni, il filtro tiene fuori chi era gia' noto prima: e' la differenza
/// fra "e' comparso adesso" e "l'abbiamo notato adesso".
fn new_device_events(
    per_mac: &BTreeMap<String, Vec<&Sighting>>,
    all: &[Sighting],
    from_s: i64,
) -> Vec<ReportEvent> {
    let mut out = Vec::new();
    for (mac, rows) in per_mac {
        let first = rows.first().map(|s| s.epoch).unwrap_or(from_s);
        let first_global = all.iter().filter(|s| s.mac == *mac).map(|s| s.epoch).min();
        let is_first_ever = first_global.map(|t| t == first).unwrap_or(true);
        if is_first_ever && first >= from_s && rows.len() <= 3 {
            out.push(ReportEvent {
                ts_ms: first * 1000,
                kind: EventKind::NewDevice,
                mac: mac.clone(),
                name: best_name(rows),
                detail: "primo avvistamento registrato in questo intervallo".to_string(),
            });
        }
    }
    out
}

/// Eventi di spam BLE dai cicli del monitor `--inq`, se il monitor era attivo.
///
/// Il file e' facoltativo e ruotato a 500 righe: se non c'e', non c'e' stato
/// monitorato e il report non lo nomina. Dire "nessuno spam" quando il monitor
/// non era acceso sarebbe falso, quindi in quel caso la sezione semplicemente
/// non parla di spam.
fn spam_events(path: &Path, from_s: i64, to_s: i64) -> Vec<ReportEvent> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(detected) = v.get("spam").and_then(|s| s.get("detected")) else {
            continue;
        };
        if detected != &serde_json::Value::Bool(true) {
            continue;
        }
        let Some(ts) = v.get("ts").and_then(|s| s.as_str()) else {
            continue;
        };
        let Some(epoch) = crate::logging::parse_rfc3339_epoch(ts) else {
            continue;
        };
        if epoch < from_s || epoch > to_s {
            continue;
        }
        let popup = v
            .get("spam")
            .and_then(|s| s.get("popup_hard"))
            .and_then(|s| s.as_u64())
            .unwrap_or(0);
        let dup = v
            .get("spam")
            .and_then(|s| s.get("dup_model_ids"))
            .and_then(|s| s.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let mut detail = String::new();
        if popup > 0 {
            detail.push_str(&format!("burst di {popup} annunci popup/phantom"));
        }
        if dup > 0 {
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str(&format!(
                "{dup} Model ID Fast Pair da MAC diversi (possibile spoof)"
            ));
        }
        out.push(ReportEvent {
            ts_ms: epoch * 1000,
            kind: EventKind::Spam,
            mac: String::new(),
            name: "Monitor radio".to_string(),
            detail,
        });
    }
    out
}

/// Maschera gli ultimi 3 byte: `AA:BB:CC:DD:EE:FF` -> `AA:BB:CC:XX:XX:XX`.
///
/// Si tiene il prefisso perche' e' la parte che identifica il vendor (quindi
/// il tipo di dispositivo) e rimuoverlo renderebbe il report illeggibile.
/// I tre byte finali sono l'unica parte che identifica l'utente.
pub fn mask_mac(mac: &str) -> String {
    let norm = crate::fsx::normalize_mac(mac);
    if norm.is_empty() {
        return mac.to_string();
    }
    let parts: Vec<&str> = norm.split(':').collect();
    format!("{}:{}:{}:XX:XX:XX", parts[0], parts[1], parts[2])
}

/// Durata in italiano leggibile: `3h 12m`, `47m`, `20s`.
///
/// La forma `3h 12m` e' quella che l'utente scrive a voce. `pt` (minuti
/// precisi) aggiungerebbe casino a un documento pensato per essere letto in
/// trenta secondi.
pub fn fmt_dur(secs: i64) -> String {
    let s = secs.max(0);
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{sec}s")
    }
}

fn fmt_time(ms: i64) -> String {
    let s = crate::logging::rfc3339_millis(ms);
    s.get(11..16).unwrap_or(&s).to_string()
}

fn fmt_datetime(ms: i64) -> String {
    let s = crate::logging::rfc3339_millis(ms);
    s.get(0..16).unwrap_or(&s).replace('T', " ")
}

fn fmt_day(ms: i64) -> String {
    let s = crate::logging::rfc3339_millis(ms);
    s.get(0..10).unwrap_or("").to_string()
}

/// Escape HTML per testo.
///
/// Obbligatorio e non opzionale: i nomi dei dispositivi vengono dalle
/// stringhe BLE annunciate da chiunque si trovi nelle vicinanze, e chiunque puo'
/// annunciare un nome con `<script>` dentro. Il report viene aperto nel browser
/// di un utente: questo e' il posto dove una stringa non fidata incontra
/// l'HTML.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// CSS inline.
///
/// Palette ripresa da quella della dashboard perche' sono lo stesso prodotto e
/// un report con colori diversi sembrerebbe un documento di un'altra
/// applicazione. Il blocco `@media print` non e' un extra: il report esiste
/// anche per essere stampato o allegato a un PDF, e stampare un tema scuro
/// consuma inchiostro e rende illeggibile il testo chiaro su fondo nero.
const CSS: &str = r#"
:root {
  --bg-primary: #0d0d0d; --bg-secondary: #141414; --bg-tertiary: #1a1a1a;
  --text-primary: #e0e0e0; --text-secondary: #9a9a9a; --text-muted: #6b6b6b;
  --accent-red: #dc2626; --accent-amber: #d97706; --accent-green: #16a34a;
  --accent-blue: #2563eb; --border-color: #2a2a2a;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 1.5rem 1rem 3rem; background: var(--bg-primary);
  color: var(--text-primary); font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI",
  Roboto, Helvetica, Arial, sans-serif; max-width: 60rem; margin-inline: auto;
}
code, .device-mac { font-family: Consolas, "SF Mono", Menlo, monospace; font-size: 0.85em; }
h1 { font-size: 1.5rem; margin: 0 0 0.2rem; font-weight: 700; }
h2 { font-size: 1.05rem; margin: 0 0 0.8rem; padding-bottom: 0.35rem;
     border-bottom: 1px solid var(--border-color); text-transform: uppercase;
     letter-spacing: 0.06em; color: var(--text-secondary); }
.accent { color: var(--accent-blue); }
.report-header { border-bottom: 2px solid var(--border-color); padding-bottom: 0.8rem; margin-bottom: 1.2rem; }
.subtitle { margin: 0.2rem 0; font-size: 1.05rem; color: var(--text-secondary); }
.meta { margin: 0.15rem 0; font-size: 0.78rem; color: var(--text-muted); }
.meta code { color: var(--text-secondary); }
.meta.anon { color: var(--accent-amber); }
.notice { background: rgba(217,119,6,0.12); border-left: 3px solid var(--accent-amber);
          padding: 0.6rem 0.8rem; font-size: 0.82rem; border-radius: 0 4px 4px 0; }
section { margin-bottom: 2rem; }
.summary .lead { margin: 0; font-size: 1.02rem; line-height: 1.7; }
.counts { display: flex; flex-wrap: wrap; gap: 0.6rem; }
.count-card { flex: 1 1 8rem; background: var(--bg-tertiary); border: 1px solid var(--border-color);
              border-radius: 6px; padding: 0.7rem 0.5rem; text-align: center; }
.count-card.warn { border-color: var(--accent-amber); }
.count-value { font-size: 1.7rem; font-weight: 700; line-height: 1.1; }
.count-label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.05em;
               color: var(--text-muted); margin-top: 0.2rem; }
.empty { background: var(--bg-secondary); border: 1px dashed var(--border-color);
         border-radius: 6px; padding: 0.9rem; font-size: 0.85rem; color: var(--text-secondary); }
.note { font-size: 0.78rem; color: var(--text-muted); }
.device { background: var(--bg-tertiary); border: 1px solid var(--border-color);
          border-radius: 6px; padding: 0.8rem; margin-bottom: 0.7rem; }
.device-header { display: flex; align-items: baseline; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
.device-name { font-weight: 600; }
.device-persona { font-size: 0.75rem; color: var(--accent-blue); }
.device-mac { color: var(--text-muted); }
.device-stats { margin: 0.4rem 0 0; font-size: 0.76rem; color: var(--text-secondary); }
.timeline { width: 100%; height: 46px; display: block; }
.tl-bg { fill: var(--bg-secondary); }
.tl-on { fill: var(--accent-green); }
.tl-tick { fill: var(--text-muted); font-size: 11px; font-family: Consolas, monospace; }
.heat { margin-bottom: 0.9rem; }
.heat-title { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.25rem; }
.heat-grid { display: grid; grid-template-columns: 2.6rem repeat(24, 1fr); gap: 2px; }
.heat-corner, .heat-hour { font-size: 0.55rem; color: var(--text-muted); text-align: center; }
.heat-day { font-size: 0.6rem; color: var(--text-muted); align-self: center; }
.heat-cell { aspect-ratio: 1; border-radius: 2px; background: var(--bg-secondary); }
.heat-cell.l1 { background: #14532d; }
.heat-cell.l2 { background: #166534; }
.heat-cell.l3 { background: #16a34a; }
.heat-cell.l4 { background: #4ade80; }
.event-list { list-style: none; margin: 0; padding: 0; }
.event { display: flex; gap: 0.6rem; align-items: baseline; padding: 0.45rem 0;
         border-bottom: 1px solid var(--border-color); font-size: 0.82rem; flex-wrap: wrap; }
.event-time { color: var(--text-muted); font-family: Consolas, monospace; font-size: 0.75rem; }
.event-badge { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.05em;
               padding: 0.1rem 0.4rem; border-radius: 3px; background: var(--bg-tertiary);
               border: 1px solid var(--border-color); color: var(--text-secondary); }
.event-cve .event-badge { border-color: var(--accent-red); color: var(--accent-red); }
.event-tracker .event-badge { border-color: var(--accent-amber); color: var(--accent-amber); }
.event-spam .event-badge { border-color: var(--accent-red); color: var(--accent-red); }
.event-rotating .event-badge, .event-new .event-badge { border-color: var(--accent-blue); color: var(--accent-blue); }
.event-desc { flex: 1; min-width: 14rem; color: var(--text-secondary); }
.appendix { background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 6px; padding: 0.6rem 0.8rem; margin-bottom: 1.2rem; }
.appendix summary { cursor: pointer; font-size: 0.85rem; color: var(--text-secondary); }
.appendix table { width: 100%; border-collapse: collapse; margin-top: 0.7rem; font-size: 0.72rem; }
.appendix th, .appendix td { text-align: left; padding: 0.3rem 0.4rem;
                             border-bottom: 1px solid var(--border-color); }
.appendix th { color: var(--text-muted); text-transform: uppercase; font-size: 0.62rem; }
.notes p { font-size: 0.8rem; color: var(--text-secondary); margin: 0.6rem 0; }
footer { border-top: 1px solid var(--border-color); padding-top: 0.8rem; margin-top: 1.5rem; }
footer p { margin: 0.2rem 0; font-size: 0.75rem; color: var(--text-muted); }
.disclaimer { max-width: 44rem; }
@media (max-width: 640px) {
  body { padding: 1rem 0.7rem 2rem; }
  .heat-grid { gap: 1px; }
  .appendix table { font-size: 0.62rem; }
  .event { flex-direction: column; gap: 0.2rem; }
}
@media print {
  :root {
    --bg-primary: #ffffff; --bg-secondary: #f5f5f5; --bg-tertiary: #f0f0f0;
    --text-primary: #1a1a1a; --text-secondary: #444444; --text-muted: #666666;
    --border-color: #cccccc;
  }
  body { font-size: 10.5pt; max-width: none; padding: 0; }
  /* L'appendice in stampa e' un muro di numeri: la tabella completa sta nel
     file, in questa carta ci sta solo quello che si legge. */
  .appendix { display: none; }
  section { page-break-inside: avoid; }
  .device, .count-card { page-break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
"#;

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
