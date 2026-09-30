//! Filtro falsi positivi ambientali: dispositivi STATICI e MAC ROTANTI.
//!
//! Algoritmo portato dalla logica "prep per Gemini" (analisi locale: NON si
//! invia nulla a servizi esterni):
//!
//! 1. Stabilita statistica (varianza): un dispositivo fisso (Smart-Tag dietro
//!    il muro, PC/TV fisso, antenna) risponde con RSSI quasi costanti. Con
//!    >= 5 campioni e varianza < 4.0 il segnale e matematicamente immobile ->
//!    > falso positivo ambientale (marcatore statico).
//! 2. Stabilita del fingerprint: stesso test sul fingerprint dell'annuncio:
//!    se lo Smart-Tag ruota il MAC ma payload/fingerprint restano identici e
//!    con RSSI stabile, la famiglia e statica.
//! 3. Accorpamento MAC rotanti: MAC diversi con lo stesso fingerprint nello
//!    stesso minuto vengono uniti in un'unica riga (active_macs): un solo
//!    dispositivo fisico che ruota il MAC.
//!
//! Funzioni pure e testate; la dashboard usa is_static_rssi/rotating_families
//! sui dati live, il CLI --static analizza presenze.csv offline.

use std::collections::HashMap;

/// Campioni minimi prima di dichiarare un segnale statico (dall'algoritmo
/// originale: serve un minimo di storia).
pub const MIN_SAMPLES: usize = 5;
/// Varianza sotto cui il segnale e considerato immobile (es. < 4.0).
pub const VARIANCE_THRESHOLD: f64 = 4.0;

/// Media e varianza (popolazione) di un campione di RSSI.
pub fn rssi_mean_var(samples: &[i16]) -> Option<(f64, f64)> {
    if samples.is_empty() {
        return None;
    }
    let count = samples.len() as f64;
    let mean = samples.iter().map(|&x| x as f64).sum::<f64>() / count;
    let var = samples
        .iter()
        .map(|&x| {
            let d = x as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / count;
    Some((mean, var))
}

/// Vero quando il campione e abbastanza lungo e la varianza e sotto soglia.
pub fn is_static_rssi(samples: &[i16], min_samples: usize, var_threshold: f64) -> bool {
    if samples.len() < min_samples {
        return false;
    }
    match rssi_mean_var(samples) {
        Some((_, var)) => var < var_threshold,
        None => false,
    }
}

/// Una riga di input (da presenze.csv o dal flusso live).
#[derive(Debug, Clone)]
pub struct Sight {
    pub ts: String,
    pub mac: String,
    pub fingerprint: String,
    pub vendor: String,
    pub hint: String,
    pub rssi: i16,
}

/// Un dispositivo/fingerprint dichiarato statico.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StaticHit {
    /// MAC o fingerprint (troncata) dell'entita statica.
    pub id: String,
    /// "mac" o "fingerprint".
    pub kind: &'static str,
    pub samples: usize,
    pub avg_rssi: f64,
    pub variance: f64,
    pub reason: String,
}

/// Un evento aggregato: stesso fingerprint nello stesso minuto = un solo
/// dispositivo fisico con piu MAC temporanei.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AggregatedEvent {
    /// Bucket "HH:MM".
    pub time_bucket: String,
    pub vendor: String,
    pub hint: String,
    pub fingerprint: String,
    pub active_macs: Vec<String>,
    pub max_rssi: i16,
}

/// Estrae il bucket "HH:MM" da un timestamp RFC3339 ("2026-09-03T09:41:43Z").
pub fn minute_bucket(ts: &str) -> String {
    ts.get(11..16).map(|s| s.to_string()).unwrap_or_default()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}

/// Analisi completa (stessa semantica di process_ble_logs_for_ai): rileva i
/// falsi positivi statici (per MAC e per fingerprint) e accorpa i MAC rotanti
/// in bucket di un minuto. Gli id (mac/fingerprint) statici sono esclusi
/// dall'aggregazione.
pub fn analyze(
    sights: &[Sight],
    min_samples: usize,
    var_threshold: f64,
) -> (Vec<StaticHit>, Vec<AggregatedEvent>) {
    let mut mac_rssis: HashMap<&str, Vec<i16>> = HashMap::new();
    let mut fp_rssis: HashMap<&str, Vec<i16>> = HashMap::new();
    for s in sights {
        mac_rssis.entry(s.mac.as_str()).or_default().push(s.rssi);
        if !s.fingerprint.is_empty() && s.fingerprint != "-" {
            fp_rssis
                .entry(s.fingerprint.as_str())
                .or_default()
                .push(s.rssi);
        }
    }

    let mut hits: Vec<StaticHit> = Vec::new();
    let mut whitelist: Vec<String> = Vec::new();

    for (mac, rssis) in &mac_rssis {
        if rssis.len() < min_samples {
            continue;
        }
        if let Some((avg, var)) = rssi_mean_var(rssis) {
            if var < var_threshold {
                hits.push(StaticHit {
                    id: (*mac).to_string(),
                    kind: "mac",
                    samples: rssis.len(),
                    avg_rssi: avg,
                    variance: var,
                    reason: format!(
                        "Segnale statico rilevato (MAC fisso). Campioni: {}",
                        rssis.len()
                    ),
                });
                whitelist.push((*mac).to_string());
            }
        }
    }
    for (fp, rssis) in &fp_rssis {
        if rssis.len() < min_samples {
            continue;
        }
        if let Some((avg, var)) = rssi_mean_var(rssis) {
            if var < var_threshold {
                hits.push(StaticHit {
                    id: truncate(fp, 30),
                    kind: "fingerprint",
                    samples: rssis.len(),
                    avg_rssi: avg,
                    variance: var,
                    reason: format!(
                        "Smart-Tag o IoT fisso rilevato tramite fingerprint stabile. Campioni: {}",
                        rssis.len()
                    ),
                });
                whitelist.push((*fp).to_string());
            }
        }
    }

    // Accorpamento per (minuto, fingerprint): MAC diversi con lo stesso
    // fingerprint sono un solo device che ruota il MAC.
    let mut buckets: HashMap<(String, String), AggregatedEvent> = HashMap::new();
    for s in sights {
        if whitelist
            .iter()
            .any(|id| id == &s.mac || id == &s.fingerprint)
        {
            continue; // escluso: falso positivo statico
        }
        let bucket = minute_bucket(&s.ts);
        let key = if s.fingerprint.is_empty() || s.fingerprint == "-" {
            s.mac.clone()
        } else {
            s.fingerprint.clone()
        };
        let ev = buckets
            .entry((bucket.clone(), key.clone()))
            .or_insert_with(|| AggregatedEvent {
                time_bucket: bucket,
                vendor: s.vendor.clone(),
                hint: s.hint.clone(),
                fingerprint: truncate(&s.fingerprint, 20),
                active_macs: Vec::new(),
                max_rssi: i16::MIN,
            });
        if !ev.active_macs.contains(&s.mac) {
            ev.active_macs.push(s.mac.clone());
        }
        if s.rssi > ev.max_rssi {
            ev.max_rssi = s.rssi;
        }
    }

    let mut events: Vec<AggregatedEvent> = buckets.into_values().collect();
    events.sort_by(|a, b| a.time_bucket.cmp(&b.time_bucket));

    (hits, events)
}

/// Famiglie di MAC rotanti nel set live corrente: per ogni fingerprint
/// presente, i MAC che la condividono. Solo le famiglie con >= 2 MAC sono
/// "rotazione"; il primo MAC della famiglia (ordine alfabetico) e il capo.
pub fn rotating_families(devices: &[(&str, &str)]) -> Vec<(String, Vec<String>)> {
    let mut by_fp: HashMap<&str, Vec<String>> = HashMap::new();
    for (mac, fp) in devices {
        if !fp.is_empty() && *fp != "-" {
            by_fp.entry(fp).or_default().push(mac.to_string());
        }
    }
    let mut out: Vec<(String, Vec<String>)> = by_fp
        .into_iter()
        .filter(|(_, macs)| macs.len() >= 2)
        .map(|(fp, mut macs)| {
            macs.sort();
            (fp.to_string(), macs)
        })
        .collect();
    out.sort();
    out
}

/// Legge presenze.csv (formato del progetto: ; , header in riga 1) e produce
/// righe Sight con RSSI valido (righe "passivo").
pub fn load_sights(path: &std::path::Path) -> Vec<Sight> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue; // header o riga vuota
        }
        let f: Vec<&str> = line.split(';').collect();
        if f.len() < 8 {
            continue;
        }
        let Ok(rssi) = f[5].trim().parse::<i16>() else {
            continue; // righe "attivo"/"sdp" senza RSSI
        };
        out.push(Sight {
            ts: f[0].trim().to_string(),
            mac: f[2].trim().to_string(),
            fingerprint: f[6].trim().to_string(),
            vendor: f[7].trim().to_string(),
            hint: f.get(8).map(|s| s.trim().to_string()).unwrap_or_default(),
            rssi,
        });
    }
    out
}

/// Report offline `--static`: stampa i falsi positivi ambientali (statici per
/// MAC/fingerprint) e l'accorpamento dei MAC rotanti in bucket di un minuto.
/// Nessun dato esce dal PC: e l'analisi locale "prep" per un eventuale futuro
/// invio a servizi esterni.
pub fn report_csv(logger: &crate::logging::Logger, path: &std::path::Path) {
    let sights = load_sights(path);
    if sights.is_empty() {
        let msg = format!("static: no usable rows in {}", path.display());
        logger.log(&msg);
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m {msg}");
        return;
    }
    let (hits, events) = analyze(&sights, MIN_SAMPLES, VARIANCE_THRESHOLD);
    crate::bn!(
        "\x1b[34m[BLUESNIFF]\x1b[0m === Falsi positivi ambientali ({}) ===",
        path.display()
    );
    logger.log(&format!(
        "static: {} rows, {} static hits, {} aggregated events",
        sights.len(),
        hits.len(),
        events.len()
    ));

    crate::bn!("  \x1b[33mFalsi positivi statici: {}\x1b[0m", hits.len());
    for h in &hits {
        crate::bn!(
            "  \x1b[31m\u{1F4CC}\x1b[0m [{}] {} campioni={} avg={:.1}dBm var={:.2}",
            h.kind,
            h.id,
            h.samples,
            h.avg_rssi,
            h.variance
        );
        crate::bn!("       motivo: {}", h.reason);
    }

    let rotating: Vec<&AggregatedEvent> =
        events.iter().filter(|e| e.active_macs.len() >= 2).collect();
    crate::bn!(
        "  \x1b[33mMAC rotanti accorpati per fingerprint/minuto: {}\x1b[0m",
        rotating.len()
    );
    for e in &rotating {
        crate::bn!(
            "  \u{1F504} {} fp={} rssi_max={}dBm -> {}",
            e.time_bucket,
            if e.fingerprint.is_empty() {
                "-"
            } else {
                &e.fingerprint
            },
            e.max_rssi,
            e.active_macs.join(", ")
        );
    }
    if rotating.is_empty() && hits.is_empty() {
        crate::bn!("  nessun falso positivo ambientale rilevato (servono >= {} campioni con varianza < {:.0})", MIN_SAMPLES, VARIANCE_THRESHOLD);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sight(ts: &str, mac: &str, fp: &str, rssi: i16) -> Sight {
        Sight {
            ts: ts.to_string(),
            mac: mac.to_string(),
            fingerprint: fp.to_string(),
            vendor: "V".to_string(),
            hint: "H".to_string(),
            rssi,
        }
    }

    #[test]
    fn variance_flags_static_device() {
        // Segnale immobile: -70, -70, -71, -70, -70 -> varianza ~0.16
        let s = vec![-70i16, -70, -71, -70, -70];
        assert!(is_static_rssi(&s, MIN_SAMPLES, VARIANCE_THRESHOLD));
        // Segnale che si muove: fluttuazioni forti
        let m = vec![-55i16, -70, -62, -80, -65];
        assert!(!is_static_rssi(&m, MIN_SAMPLES, VARIANCE_THRESHOLD));
        // Troppi pochi campioni: mai statico
        assert!(!is_static_rssi(
            &[-70i16, -70],
            MIN_SAMPLES,
            VARIANCE_THRESHOLD
        ));
    }

    #[test]
    fn analyze_marks_mac_and_fingerprint_static() {
        let rows: Vec<Sight> = (0..6)
            .map(|i| {
                sight(
                    &format!("2026-09-03T09:{:02}:00Z", i),
                    "AA:BB:CC:DD:EE:01",
                    "FP-SMARTTAG",
                    -80,
                )
            })
            .collect();
        let (hits, _) = analyze(&rows, MIN_SAMPLES, VARIANCE_THRESHOLD);
        let kinds: Vec<&str> = hits.iter().map(|h| h.kind).collect();
        assert!(kinds.contains(&"mac"));
        assert!(kinds.contains(&"fingerprint"));
        for h in &hits {
            assert!(h.variance < VARIANCE_THRESHOLD);
        }
    }

    #[test]
    fn analyze_groups_rotating_macs_by_fingerprint() {
        // Due MAC diversi con lo stesso fingerprint, stesso minuto -> un solo evento.
        let rows = vec![
            sight("2026-09-03T09:41:10Z", "AA:BB:CC:DD:EE:01", "FP-X", -70),
            sight("2026-09-03T09:41:40Z", "AA:BB:CC:DD:EE:02", "FP-X", -68),
            sight("2026-09-03T09:42:05Z", "AA:BB:CC:DD:EE:01", "FP-X", -69),
        ];
        let (_, events) = analyze(&rows, MIN_SAMPLES, VARIANCE_THRESHOLD);
        let b41 = events.iter().find(|e| e.time_bucket == "09:41").unwrap();
        assert_eq!(b41.active_macs.len(), 2);
        let b42 = events.iter().find(|e| e.time_bucket == "09:42").unwrap();
        assert_eq!(b42.active_macs.len(), 1);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn rotating_families_finds_shared_fingerprint() {
        let devs = vec![
            ("AA:BB:CC:DD:EE:01", "FP-TAG"),
            ("AA:BB:CC:DD:EE:02", "FP-TAG"),
            ("AA:BB:CC:DD:EE:03", "FP-ALTRO"),
        ];
        let fam = rotating_families(&devs);
        assert_eq!(fam.len(), 1);
        assert_eq!(fam[0].0, "FP-TAG");
        assert_eq!(fam[0].1.len(), 2);
    }

    #[test]
    fn minute_bucket_extracts_hhmm() {
        assert_eq!(minute_bucket("2026-09-03T09:41:43Z"), "09:41");
        assert_eq!(minute_bucket(""), "");
    }
}
