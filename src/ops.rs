//! Operations ported from bluehood: storage pruning + heartbeat check-ins.
//!
//! - `prune_presenze`: rewrites `presenze.csv` dropping sighting rows older
//!   than `days` (header preserved). With `min_sightings > 0`, whole stale
//!   devices (older than the cutoff AND with fewer than that many total
//!   sightings) are dropped entirely; rows of known phones (`bt_known.txt`)
//!   are always kept. A `.bak` copy is written before rewriting.
//! - `spawn_heartbeat`: periodic POST to an uptime-monitoring URL (Uptime
//!   Kuma / Healthchecks.io style) spawned alongside listen/record.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::logging::Logger;

/// Rewrite `presenze.csv` keeping only rows newer than `days` days.
/// Returns (rows_kept, rows_dropped). Header and rows of known phones are
/// always preserved. A `.bak` copy is written before the rewrite.
pub fn prune_presenze(
    logger: &Logger,
    path: &Path,
    days: u64,
    min_sightings: usize,
    known_macs: &HashSet<String>,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut lines = content.lines();
    let header = lines.next().unwrap_or_default().to_string();

    let cutoff = now_epoch() - (days.max(1) as i64) * 86_400;

    // First pass: count sightings per device identity (MAC, or fingerprint
    // when present) to support whole-device pruning.
    let rows: Vec<Vec<String>> = lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            l.split(';')
                .map(|c| c.trim().to_string())
                .collect::<Vec<String>>()
        })
        .filter(|f: &Vec<String>| f.len() >= 10)
        .collect();

    let mut counts: HashMap<String, usize> = HashMap::new();
    for f in &rows {
        let id = if f[6].is_empty() {
            f[2].clone()
        } else {
            f[6].clone()
        };
        *counts.entry(id).or_default() += 1;
    }

    let bak = path.with_extension("csv.bak");
    std::fs::copy(path, &bak)?;
    logger.log(&format!("prune: backup written to {}", bak.display()));

    use std::io::Write;
    let file = std::fs::File::create(path)?;
    let mut wtr = std::io::BufWriter::new(file);
    writeln!(wtr, "{header}")?;

    let mut kept = 0usize;
    let mut dropped = 0usize;
    for f in &rows {
        let epoch = crate::logging::parse_rfc3339_epoch(&f[0]).unwrap_or(i64::MAX);
        let mac = &f[2];
        let fp = &f[6];
        let id = if fp.is_empty() { mac } else { fp };

        let is_known = known_macs.contains(&mac.to_uppercase());
        let too_old = epoch < cutoff;
        let device_stale =
            min_sightings > 0 && counts.get(id).copied().unwrap_or(0) < min_sightings && too_old;

        if is_known || (!too_old && !device_stale) {
            writeln!(wtr, "{}", f.join(";"))?;
            kept += 1;
        } else {
            dropped += 1;
        }
    }
    wtr.flush()?;

    logger.log(&format!(
        "prune: kept {kept} row(s), dropped {dropped} row(s) (cutoff {days}d, min_sightings {min_sightings})"
    ));
    Ok((kept, dropped))
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Spawn a heartbeat task: POST an empty body to `url` every `interval_secs`
/// until the process exits. Failures are logged, never fatal.
///
/// IMPORTANT (this VM): gira su un **thread OS dedicato con il proprio runtime
/// tokio**, non sul runtime condiviso. Lo stesso ragionamento di
/// `stream::spawn_pusher`: quando reqwest condivideva il runtime principale,
/// l'attivita' di worker/timer bloccava il loop di ascolto e il processo
/// finiva in STATUS_HEAP_CORRUPTION (0xC0000374). Non e' una precaution
/// teorica: e' un crash osservato.
pub fn spawn_heartbeat(logger: Logger, url: String, interval_secs: u64) {
    let _ = std::thread::Builder::new()
        .name("bt-heartbeat".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    logger.log(&format!("heartbeat: cannot start dedicated runtime: {e}"));
                    return;
                }
            };
            rt.block_on(heartbeat_loop(logger, url, interval_secs));
        });
}

async fn heartbeat_loop(logger: Logger, url: String, interval_secs: u64) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let interval = std::time::Duration::from_secs(interval_secs.max(30));
    loop {
        match client.post(&url).send().await {
            Ok(resp) => {
                logger.log(&format!("heartbeat: {} -> {}", url, resp.status()));
            }
            Err(e) => {
                logger.log(&format!("heartbeat: {url} failed: {e}"));
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_keeps_header_and_known() {
        let dir = std::env::temp_dir().join(format!("bluesniff-prune-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("presenze.csv");
        let old = "2020-01-01T00:00:00Z";
        let new = "2099-01-01T00:00:00Z";
        let header = "ora;tipo;mac;nome;persona;rssi;fingerprint;vendor;hint;stato";
        std::fs::write(
            &path,
            format!(
                "{header}\n{old};passivo;AA:BB:CC:DD:EE:01;;;;;;;visto\n{new};passivo;AA:BB:CC:DD:EE:02;;;;;;;visto\n{old};attivo;AA:BB:CC:DD:EE:03;Phone;Mario;;;;;presente\n"
            ),
        )
        .unwrap();

        let mut known = HashSet::new();
        known.insert("AA:BB:CC:DD:EE:03".to_string());

        let logger = crate::logging::Logger::open(dir.join("t.log")).unwrap();
        let (kept, dropped) = prune_presenze(&logger, &path, 30, 0, &known).unwrap();
        assert_eq!(kept, 2, "new row + known phone row");
        assert_eq!(dropped, 1, "old anonymous row");

        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.starts_with(header));
        assert!(out.contains("EE:02"));
        assert!(out.contains("EE:03"), "known phone must survive");
        assert!(!out.contains("EE:01"));
        assert!(dir.join("presenze.csv.bak").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
