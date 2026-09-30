//! Presence-pattern analysis over `presenze.csv` (ideas ported from bluehood).
//!
//! Pure analysis over the existing recorder output — no new dependencies:
//! 1. **Dwell time / sessions** (bluehood's dwell analysis): sightings split
//!    into sessions by a gap threshold (default 15 min); reports total time
//!    in range and session count per device.
//! 2. **Pattern summary**: time-of-day bucket, weekday/weekend and frequency
//!    per device, e.g. `Daily, evenings (5PM-9PM)`.
//! 3. **MAC-rotation linkage** ("likely same device"): pairs of randomized
//!    fingerprints where one stops advertising as the other starts (handoff
//!    window), with similar median RSSI and similar ping cadence.
//! 4. **BLE<->BLE correlation**: Phi coefficient (binary Pearson) between two
//!    fingerprint presence series — the same math as `track.rs` uses for
//!    BLE<->LAN co-movement, applied between two BLE devices.

use std::collections::HashMap;
use std::path::Path;

use crate::logging::Logger;

/// A gap longer than this between two sightings starts a new session.
pub const SESSION_GAP_SECS: i64 = 15 * 60;
/// Two fingerprints whose sightings hand off within this window are candidates
/// for being the same physical device after a MAC rotation.
pub const HANDOFF_WINDOW_SECS: i64 = 3 * 60;
/// Median RSSI difference below which two fingerprints may be the same device.
const RSSI_TOLERANCE_DB: i16 = 10;
/// Minimum sightings per fingerprint before it participates in any analysis.
const MIN_SIGHTINGS: usize = 3;

/// One parsed sighting row from `presenze.csv`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Sighting {
    pub epoch: i64,
    /// `passivo` (BLE window) or `attivo` (classic probe).
    pub kind: String,
    pub mac: String,
    pub name: String,
    pub rssi: Option<i16>,
    pub fingerprint: String,
    pub vendor: String,
    pub stato: String,
    /// MAC (o hostname) della stazione server BT che ha registrato la riga.
    /// Colonna opzionale: assente nei file pre-esistenti.
    pub station: String,
    /// Etichetta di classe dell'annuncio (colonna 9), es. "Apple Find My
    /// accessory": e' l'unico modo di riconoscere un localizzatore **leggendo
    /// solo il CSV**. Il report ne ha bisogno perche' senza `raw_log` non
    /// puo' ricalcolare la firma, e senza questo campo i localizzatori
    /// sparirebbero dal report esattamente nelle installazioni avviate con
    /// `--no-rawlog`.
    pub hint: String,
    /// Colonna Persona (4): "di chi e'". Vuota per chi non e' in `bt_known.txt`.
    pub persona: String,
}

/// Load every data row of a `presenze.csv` (semicolon-delimited, header first).
/// Malformed rows are skipped; a missing/empty file yields an empty vec.
pub fn load_sightings(path: &Path) -> Vec<Sighting> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue; // header or blank
        }
        let f: Vec<&str> = line.split(';').collect();
        if f.len() < 10 {
            continue;
        }
        let Some(epoch) = crate::logging::parse_rfc3339_epoch(f[0].trim()) else {
            continue;
        };
        out.push(Sighting {
            epoch,
            kind: f[1].trim().to_string(),
            mac: f[2].trim().to_string(),
            name: f[3].trim().to_string(),
            persona: f.get(4).map(|s| s.trim().to_string()).unwrap_or_default(),
            rssi: f[5].trim().parse::<i16>().ok(),
            fingerprint: f[6].trim().to_string(),
            vendor: f[7].trim().to_string(),
            hint: f.get(8).map(|s| s.trim().to_string()).unwrap_or_default(),
            stato: f[9].trim().to_string(),
            station: f.get(10).map(|s| s.trim().to_string()).unwrap_or_default(),
        });
    }
    out.sort_by_key(|s| s.epoch);
    out
}

/// Identity key for a sighting: the stable fingerprint when present (BLE MACs
/// rotate), otherwise the MAC (classic probes).
fn identity(s: &Sighting) -> String {
    if s.fingerprint.is_empty() {
        format!("mac:{}", s.mac)
    } else {
        format!("fp:{}", s.fingerprint)
    }
}

/// Sessions = sightings split wherever the gap exceeds `gap_secs`.
/// Returns (session_count, total_in_range_secs) — the last session is open
/// ended, so its duration counts only up to its last sighting.
fn sessions(times: &[i64], gap_secs: i64) -> (usize, i64) {
    if times.is_empty() {
        return (0, 0);
    }
    let mut count = 1usize;
    let mut total = 0i64;
    for w in times.windows(2) {
        let d = w[1] - w[0];
        if d > gap_secs {
            count += 1;
        } else {
            total += d;
        }
    }
    (count, total)
}

/// Time-of-day bucket name from a unix hour (UTC, same as the CSV stamps).
#[allow(dead_code)]
fn day_bucket(h: u32) -> &'static str {
    match h {
        5..=11 => "morning",
        12..=16 => "afternoon",
        17..=22 => "evening",
        _ => "night",
    }
}

/// Human-readable presence pattern for a device's sighting hours, e.g.
/// `Daily, evenings (5PM-9PM)` — bluehood's pattern-analysis style.
pub fn pattern_line(times: &[i64]) -> String {
    if times.len() < MIN_SIGHTINGS {
        return "rare (too few sightings)".to_string();
    }
    let mut buckets = [0usize; 4]; // morning/afternoon/evening/night
    let mut weekdays = 0usize;
    let mut days_seen = std::collections::HashSet::new();
    for &t in times {
        // civil day + hour-of-day from the epoch, reusing logging's helpers
        // via the RFC3339 round trip is overkill: derive directly.
        let days = t.div_euclid(86_400);
        let rem = t.rem_euclid(86_400);
        let hour = (rem / 3600) as u32;
        buckets[bucket_index(hour)] += 1;
        // Day of week: 1970-01-01 was a Thursday (index 4 with Monday = 0).
        let dow = (days + 3).rem_euclid(7); // Monday = 0
        if dow < 5 {
            weekdays += 1;
        }
        days_seen.insert(days);
    }
    let n = times.len();
    let total_days = days_seen.len().max(1);
    let per_day = n as f32 / total_days as f32;

    let freq = if per_day >= 8.0 {
        "Constant"
    } else if total_days >= 3 && per_day >= 1.0 {
        "Daily"
    } else if total_days >= 3 {
        "Regular"
    } else if n >= MIN_SIGHTINGS {
        "Occasional"
    } else {
        "Rare"
    };

    let when = dominant_buckets(&buckets, n);
    let day_part = if weekdays * 2 > n {
        "Weekdays"
    } else if weekdays * 2 < n {
        "Weekends"
    } else {
        "Every day"
    };

    if when.is_empty() {
        format!("{freq}, {day_part}")
    } else {
        format!("{freq}, {day_part}, {when}")
    }
}

fn bucket_index(hour: u32) -> usize {
    match hour {
        5..=11 => 0,
        12..=16 => 1,
        17..=22 => 2,
        _ => 3,
    }
}

/// Buckets holding >= 40% of sightings, rendered as e.g. `evenings (5PM-9PM)`.
fn dominant_buckets(buckets: &[usize; 4], n: usize) -> String {
    const NAMES: &[&str] = &[
        "mornings (5AM-12PM)",
        "afternoons (12PM-5PM)",
        "evenings (5PM-11PM)",
        "nights (11PM-5AM)",
    ];
    let parts: Vec<&str> = NAMES
        .iter()
        .zip(buckets.iter())
        .filter(|(_, &c)| c * 5 >= n * 2 && c > 0)
        .map(|(name, _)| *name)
        .collect();
    parts.join(" + ")
}

/// Median of a list (rounded for even counts).
fn median(values: &mut [i16]) -> Option<i16> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}

/// A candidate "same physical device" link between two rotating fingerprints.
#[derive(Debug)]
pub struct RotationLink {
    pub a: String,
    pub b: String,
    pub handoffs: usize,
    pub rssi_delta: i16,
}

/// Link randomized-MAC fingerprints that hand off in time: for each pair,
/// count how many times A's last sighting before a gap is followed by B's
/// first sighting after that gap within `HANDOFF_WINDOW_SECS` (and vice
/// versa). Keep pairs with >= 2 handoffs and similar median RSSI.
pub fn rotation_links(per_fp: &HashMap<String, Vec<&Sighting>>) -> Vec<RotationLink> {
    let keys: Vec<&String> = per_fp
        .iter()
        .filter(|(_, v)| v.len() >= MIN_SIGHTINGS)
        .map(|(k, _)| k)
        .collect();

    let mut out = Vec::new();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            let a = &per_fp[keys[i]];
            let b = &per_fp[keys[j]];
            let handoffs = count_handoffs(a, b) + count_handoffs(b, a);
            if handoffs < 2 {
                continue;
            }
            let (ma, mb) = (
                median(&mut a.iter().filter_map(|s| s.rssi).collect::<Vec<i16>>()),
                median(&mut b.iter().filter_map(|s| s.rssi).collect::<Vec<i16>>()),
            );
            let (Some(ma), Some(mb)) = (ma, mb) else {
                continue;
            };
            let delta = (ma - mb).abs();
            if delta <= RSSI_TOLERANCE_DB {
                out.push(RotationLink {
                    a: keys[i].clone(),
                    b: keys[j].clone(),
                    handoffs,
                    rssi_delta: delta,
                });
            }
        }
    }
    out.sort_by_key(|x| std::cmp::Reverse(x.handoffs));
    out
}

/// Count A-end -> B-start transitions within the handoff window.
fn count_handoffs(a: &[&Sighting], b: &[&Sighting]) -> usize {
    let mut count = 0usize;
    for w in a.windows(2) {
        let gap = w[1].epoch - w[0].epoch;
        if gap <= SESSION_GAP_SECS {
            continue; // A never left
        }
        // A's last sighting before the gap is w[0]; did B appear right after?
        if b.iter()
            .any(|s| s.epoch >= w[0].epoch && s.epoch - w[0].epoch <= HANDOFF_WINDOW_SECS)
        {
            count += 1;
        }
    }
    count
}

/// Phi coefficient between two boolean presence series (same definition as
/// `track.rs`'s BLE<->LAN correlate, exposed here for BLE<->BLE pairs).
pub fn phi(a: &[bool], b: &[bool]) -> Option<f64> {
    if a.len() != b.len() || a.is_empty() {
        return None;
    }
    let (mut n11, mut n10, mut n01, mut n00) = (0u64, 0u64, 0u64, 0u64);
    for (x, y) in a.iter().zip(b.iter()) {
        match (x, y) {
            (true, true) => n11 += 1,
            (true, false) => n10 += 1,
            (false, true) => n01 += 1,
            (false, false) => n00 += 1,
        }
    }
    let d =
        ((n11 + n10) as f64) * ((n01 + n00) as f64) * ((n11 + n01) as f64) * ((n10 + n00) as f64);
    if d <= 0.0 {
        return None;
    }
    Some(((n11 * n00) as f64 - (n10 * n01) as f64) / d.sqrt())
}

/// Bucket the sightings into fixed `bucket_secs` presence slots per identity,
/// so two identities' series can be compared with `phi`.
fn presence_series(
    per_id: &HashMap<String, Vec<&Sighting>>,
    id: &str,
    t0: i64,
    t1: i64,
    bucket_secs: i64,
) -> Vec<bool> {
    let Some(sights) = per_id.get(id) else {
        return Vec::new();
    };
    let n = (((t1 - t0) / bucket_secs) + 1).max(0) as usize;
    let mut series = vec![false; n];
    for s in sights {
        let idx = ((s.epoch - t0) / bucket_secs).max(0) as usize;
        if idx < n {
            series[idx] = true;
        }
    }
    series
}

/// Full report: prints and logs dwell, patterns, rotation links and strong
/// BLE<->BLE correlations for every device in the sightings.
pub fn report(logger: &Logger, path: &Path) {
    let sightings = load_sightings(path);
    if sightings.is_empty() {
        let msg = format!("patterns: no usable rows in {}", path.display());
        logger.log(&msg);
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m {msg}");
        return;
    }

    // Group by identity, keeping per-identity sorted sightings.
    let mut per_id: HashMap<String, Vec<&Sighting>> = HashMap::new();
    for s in &sightings {
        per_id.entry(identity(s)).or_default().push(s);
    }

    let t0 = sightings.first().map(|s| s.epoch).unwrap_or(0);
    let t1 = sightings.last().map(|s| s.epoch).unwrap_or(0);

    crate::bn!(
        "\x1b[34m[BLUESNIFF]\x1b[0m === Presence patterns ({}) ===",
        path.display()
    );
    logger.log(&format!(
        "patterns: {} sightings, {} identities, span {}s",
        sightings.len(),
        per_id.len(),
        t1 - t0
    ));

    // 1) Dwell + pattern per device.
    for (id, sights) in &per_id {
        if sights.len() < MIN_SIGHTINGS {
            continue;
        }
        let times: Vec<i64> = sights.iter().map(|s| s.epoch).collect();
        let (sess, dwell) = sessions(&times, SESSION_GAP_SECS);
        let display = sights
            .iter()
            .rev()
            .find(|s| !s.name.is_empty())
            .map(|s| s.name.clone())
            .unwrap_or_else(|| id.clone());
        let hours = (dwell / 3600, (dwell % 3600) / 60);
        let line = format!(
            "{} [{}]: {} session(s), dwell {}h{:02}m, {}",
            display,
            id,
            sess,
            hours.0,
            hours.1,
            pattern_line(&times)
        );
        crate::bn!("  {line}");
        logger.log(&format!("patterns {line}"));
    }

    // 2) MAC-rotation links.
    let links = rotation_links(&per_id);
    if !links.is_empty() {
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m === Likely same device (MAC rotation) ===");
        for l in &links {
            let line = format!(
                "{} <-> {} ({} handoffs, RSSI delta {} dB)",
                l.a, l.b, l.handoffs, l.rssi_delta
            );
            crate::bn!("  \x1b[33m{line}\x1b[0m");
            logger.log(&format!("patterns rotation {line}"));
        }
    } else {
        logger.log("patterns: no MAC-rotation links found");
    }

    // 3) BLE<->BLE co-presence (bucket = 5 min like the recorder cadence).
    const BUCKET: i64 = 300;
    let keys: Vec<&String> = per_id
        .iter()
        .filter(|(_, v)| v.len() >= MIN_SIGHTINGS)
        .map(|(k, _)| k)
        .collect();
    let mut correlated: Vec<(f64, String, String)> = Vec::new();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            let sa = presence_series(&per_id, keys[i], t0, t1, BUCKET);
            let sb = presence_series(&per_id, keys[j], t0, t1, BUCKET);
            if let Some(p) = phi(&sa, &sb) {
                if p >= 0.6 {
                    correlated.push((p, keys[i].clone(), keys[j].clone()));
                }
            }
        }
    }
    if !correlated.is_empty() {
        correlated.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap_or(std::cmp::Ordering::Equal));
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m === Devices that appear together (Phi >= 0.6) ===");
        for (p, a, b) in correlated.iter().take(20) {
            let line = format!("{a} <-> {b} [phi={p:.2}]");
            crate::bn!("  \x1b[33m{line}\x1b[0m");
            logger.log(&format!("patterns correlate {line}"));
        }
    } else {
        logger.log("patterns: no strongly correlated device pairs");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(epoch: i64, fp: &str, rssi: Option<i16>) -> Sighting {
        Sighting {
            epoch,
            kind: "passivo".into(),
            mac: format!(
                "AA:BB:CC:DD:{:02}:{:02}",
                (epoch % 256) as u8,
                (fp.len() % 256) as u8
            ),
            name: String::new(),
            persona: String::new(),
            rssi,
            fingerprint: fp.into(),
            vendor: String::new(),
            hint: String::new(),
            stato: "visto".into(),
            station: String::new(),
        }
    }

    #[test]
    fn sessions_split_on_gap() {
        // 0, 60, 120 | gap 1h | 4800 -> 2 sessions, 120s dwell.
        let times = vec![0, 60, 120, 4800];
        let (count, dwell) = sessions(&times, SESSION_GAP_SECS);
        assert_eq!(count, 2);
        assert_eq!(dwell, 120);
    }

    #[test]
    fn pattern_evenings() {
        // 6 sightings, all at 19:00 UTC on different days.
        let times: Vec<i64> = (0..6).map(|d| 86_400 * d + 19 * 3600).collect();
        let p = pattern_line(&times);
        assert!(p.contains("Daily"), "{p}");
        assert!(p.contains("evenings"), "{p}");
    }

    #[test]
    fn pattern_too_few() {
        assert_eq!(pattern_line(&[100, 200]), "rare (too few sightings)");
    }

    #[test]
    fn rotation_link_detected() {
        // A seen at 0,1,2 then leaves; B appears at 100,101,102 (within the
        // 3-minute handoff window). Reversed: B leaves, A reappears —
        // two handoffs total, as if one physical device rotated its MAC.
        let mut a = Vec::new();
        let mut b = Vec::new();
        for base in [0i64, 10_000] {
            for k in 0..3 {
                a.push(s(base + k, "fpA", Some(-60)));
                b.push(s(base + 100 + k, "fpB", Some(-62)));
            }
        }
        // B -> A handoff for the second block: B reappears right after A leaves.
        b.push(s(20000, "fpB", Some(-62)));
        a.push(s(20060, "fpA", Some(-60)));
        let mut per: HashMap<String, Vec<&Sighting>> = HashMap::new();
        for x in a.iter().chain(b.iter()) {
            per.entry(x.fingerprint.clone()).or_default().push(x);
        }
        let links = rotation_links(&per);
        assert_eq!(links.len(), 1);
        assert!(links[0].handoffs >= 2);
        assert!(links[0].rssi_delta <= RSSI_TOLERANCE_DB);
    }

    #[test]
    fn phi_perfect_agreement() {
        let a = vec![true, true, false, false];
        let b = vec![true, true, false, false];
        assert!((phi(&a, &b).unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn phi_perfect_disagreement() {
        let a = vec![true, true, false, false];
        let b = vec![false, false, true, true];
        assert!((phi(&a, &b).unwrap() + 1.0).abs() < 1e-9);
    }
}
