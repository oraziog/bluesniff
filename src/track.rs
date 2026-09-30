use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;

use crate::bluetooth::{stable_fingerprint, BleDevice};
use crate::lan::LanDevice;
use crate::logging::Logger;

/// Seconds of active scanning per sample and total seconds per sample
/// (scan + small gap). A short fresh scan per sample is used on purpose:
/// btleplug's `peripherals()` is cumulative, so a fresh scan is the only
/// reliable way to observe a device DISAPPEARING (otherwise a departed device
/// would keep its last RSSI and look "present" forever).
const SCAN_WINDOW_SECS: u64 = 4;
const SAMPLE_SECS: u64 = 5;

/// Re-run the full ARP sweep every N samples so hosts that join the network
/// after startup (e.g. a phone arriving home) get discovered and tracked.
/// Without this the tracked host list stays frozen at the first sweep and
/// late-arriving IPs never appear in the CSV/log.
const DISCOVERY_EVERY: usize = 5;

/// Open a fresh BLE scan window and return the current
/// stable-fingerprint -> RSSI map.
async fn scan_once(adapters: &[btleplug::platform::Adapter]) -> HashMap<String, Option<i16>> {
    for a in adapters {
        let _ = a.start_scan(ScanFilter::default()).await;
    }
    tokio::time::sleep(Duration::from_secs(SCAN_WINDOW_SECS)).await;
    let seen = collect_fingerprints(adapters).await;
    for a in adapters {
        let _ = a.stop_scan().await;
    }
    seen
}

/// Run a co-movement sampling session: repeatedly snapshot BLE RSSI (keyed by
/// the stable advertisement fingerprint) and LAN presence (ARP reachable), then
/// correlate the two sides with the Phi coefficient (binary Pearson).
pub async fn run(
    logger: &Logger,
    initial: &[BleDevice],
    lan: &[LanDevice],
    seconds: u64,
    subnets: &[ipnet::IpNet],
) -> Result<(), Box<dyn Error>> {
    let manager = Manager::new().await.map_err(|e| {
        logger.log(&format!("track: creating manager: {e}"));
        e.to_string()
    })?;
    let adapters = manager.adapters().await.map_err(|e| {
        logger.log(&format!("track: listing adapters: {e}"));
        e.to_string()
    })?;
    if adapters.is_empty() {
        logger.log("track: no Bluetooth adapter, cannot sample BLE");
        return Ok(());
    }

    // Series keyed by stable fingerprint (BLE) and IP (LAN).
    let mut ble_series: HashMap<String, Vec<Option<i16>>> = HashMap::new();
    for d in initial {
        if let Some(f) = &d.fingerprint {
            ble_series.entry(f.clone()).or_default();
        }
    }

    let mut known_ips: Vec<IpAddr> = Vec::new();
    let mut lan_series: HashMap<IpAddr, Vec<bool>> = HashMap::new();
    let mut lan_rtt_series: HashMap<IpAddr, Vec<Option<u32>>> = HashMap::new();
    for d in lan {
        if let Ok(ip) = d.ip.parse::<IpAddr>() {
            lan_series.entry(ip).or_default();
            lan_rtt_series.entry(ip).or_default();
            known_ips.push(ip);
        }
    }

    let start = Instant::now();
    let mut n = 0usize;

    while start.elapsed() < Duration::from_secs(seconds) {
        let seen = scan_once(&adapters).await;
        let online = crate::lan::probe_alive(&known_ips);
        let rtts = crate::lan::ping_rtt(&known_ips);

        // Periodically re-sweep the subnets and merge hosts that joined the
        // network after startup, so the tracked set is not frozen.
        if n > 0 && n.is_multiple_of(DISCOVERY_EVERY) {
            for ip in crate::lan::arp_sweep(subnets) {
                if !known_ips.contains(&ip) {
                    known_ips.push(ip);
                    lan_series.entry(ip).or_insert_with(|| vec![false; n]);
                    lan_rtt_series.entry(ip).or_insert_with(|| vec![None; n]);
                    logger.log(&format!("track: new LAN host discovered: {ip}"));
                }
            }
        }

        // Any fingerprint never seen before gets a padded series (None so far).
        for f in seen.keys() {
            ble_series.entry(f.clone()).or_insert_with(|| vec![None; n]);
        }
        for (f, series) in ble_series.iter_mut() {
            series.push(seen.get(f).copied().flatten());
        }
        for (ip, series) in lan_series.iter_mut() {
            series.push(online.contains(ip));
        }
        for (ip, series) in lan_rtt_series.iter_mut() {
            series.push(rtts.get(ip).copied().flatten());
        }

        n += 1;
        logger.log(&format!(
            "track sample {n}: {} BLE fingerprint(s) seen, {}/{} known LAN host(s) online",
            seen.len(),
            online.len(),
            known_ips.len()
        ));
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m sample {n}: {} BLE, {}/{} LAN online",
            seen.len(),
            online.len(),
            known_ips.len()
        );

        // Sleep until the next sample boundary (best-effort; the loop guard
        // handles the final partial interval).
        let elapsed = start.elapsed().as_secs();
        if elapsed < seconds {
            tokio::time::sleep(Duration::from_secs(SAMPLE_SECS.min(seconds - elapsed))).await;
        }
    }

    report(
        logger,
        initial,
        lan,
        &ble_series,
        &lan_series,
        &lan_rtt_series,
        n,
    );
    Ok(())
}

/// Continuously sample BLE RSSI + LAN presence and append one CSV row per
/// (sample, entity) to `path`. Runs for `seconds` if `Some`, otherwise until
/// Ctrl+C. The file is flushed after every sample, so partial data survives a
/// kill. One tidy row per entity:
///
/// `sample,elapsed_s,kind,key,label,value`
/// - kind=ble : key=fingerprint, label=device hint, value=RSSI (empty = absent)
/// - kind=lan : key=IP, label=hostname(s), value=1/0 (online/offline)
pub async fn record(
    logger: &Logger,
    initial: &[BleDevice],
    lan: &[LanDevice],
    seconds: Option<u64>,
    path: &Path,
    subnets: &[ipnet::IpNet],
) -> Result<(), Box<dyn Error>> {
    let manager = Manager::new().await.map_err(|e| {
        logger.log(&format!("record: creating manager: {e}"));
        e.to_string()
    })?;
    let adapters = manager.adapters().await.map_err(|e| {
        logger.log(&format!("record: listing adapters: {e}"));
        e.to_string()
    })?;
    if adapters.is_empty() {
        logger.log("record: no Bluetooth adapter — recording LAN presence only");
    }

    // Fingerprint -> readable label.
    let ble_label: HashMap<String, String> = initial
        .iter()
        .filter_map(|d| {
            d.fingerprint.clone().map(|f| {
                let label = d
                    .name
                    .clone()
                    .or_else(|| d.hint.clone())
                    .unwrap_or_else(|| "<unnamed>".to_string());
                (f, label)
            })
        })
        .collect();

    // IP -> readable label.
    let mut lan_label: HashMap<IpAddr, String> = lan
        .iter()
        .filter_map(|d| {
            d.ip.parse::<IpAddr>().ok().map(|ip| {
                let label = if d.hostnames.is_empty() {
                    d.ip.clone()
                } else {
                    d.hostnames.join(",")
                };
                (ip, label)
            })
        })
        .collect();

    let mut known_ips: Vec<IpAddr> = lan.iter().filter_map(|d| d.ip.parse().ok()).collect();

    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record([
        "sample",
        "elapsed_s",
        "utc",
        "kind",
        "key",
        "label",
        "value",
    ])?;

    let start = Instant::now();
    let mut n = 0usize;

    // Ctrl+C handler
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.store(true, Ordering::Relaxed);
        });
    }

    let snapshot_interval = std::time::Duration::from_secs(600);
    let mut last_snapshot = Instant::now();

    loop {
        if let Some(secs) = seconds {
            if start.elapsed() >= Duration::from_secs(secs) {
                break;
            }
        }
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let seen = scan_once(&adapters).await;
        let online = crate::lan::probe_alive(&known_ips);
        let rtts = crate::lan::ping_rtt(&known_ips);

        // Periodically re-sweep the subnets and merge hosts that joined the
        // network after startup (e.g. 192.168.1.42 arriving at 06:01). The
        // full sweep is slow (~13-19s on a /24), so it runs every few samples.
        if n > 0 && n.is_multiple_of(DISCOVERY_EVERY) {
            for ip in crate::lan::arp_sweep(subnets) {
                if !known_ips.contains(&ip) {
                    known_ips.push(ip);
                    lan_label.entry(ip).or_insert_with(|| ip.to_string());
                    logger.log(&format!("record: new LAN host discovered: {ip}"));
                }
            }
        }

        n += 1;
        let elapsed = format!("{:.3}", start.elapsed().as_secs_f64());
        let utc = crate::logging::utc_now_rfc3339();

        // BLE rows: every fingerprint known or currently seen (absent = empty
        // RSSI cell, which downstream analysis reads as "not present").
        let mut fps: Vec<&String> = ble_label.keys().chain(seen.keys()).collect();
        fps.sort();
        fps.dedup();
        for f in &fps {
            let label = ble_label.get(*f).map(String::as_str).unwrap_or("");
            let value = match seen.get(*f).copied().flatten() {
                Some(rssi) => rssi.to_string(),
                None => String::new(),
            };
            wtr.write_record(&[
                n.to_string(),
                elapsed.clone(),
                utc.clone(),
                "ble".to_string(),
                (*f).clone(),
                label.to_string(),
                value,
            ])?;
        }

        // LAN rows.
        for ip in &known_ips {
            let label = lan_label.get(ip).map(String::as_str).unwrap_or("");
            wtr.write_record(&[
                n.to_string(),
                elapsed.clone(),
                utc.clone(),
                "lan".to_string(),
                ip.to_string(),
                label.to_string(),
                if online.contains(ip) {
                    "1".to_string()
                } else {
                    "0".to_string()
                },
            ])?;
        }

        // LAN RTT rows (continuous signal to correlate with BLE RSSI).
        for ip in &known_ips {
            let label = lan_label.get(ip).map(String::as_str).unwrap_or("");
            let value = match rtts.get(ip).copied().flatten() {
                Some(ms) => ms.to_string(),
                None => String::new(),
            };
            wtr.write_record(&[
                n.to_string(),
                elapsed.clone(),
                utc.clone(),
                "lan_rtt".to_string(),
                ip.to_string(),
                label.to_string(),
                value,
            ])?;
        }

        wtr.flush()?;

        logger.log(&format!(
            "record sample {n}: {} BLE, {}/{} LAN online",
            seen.len(),
            online.len(),
            known_ips.len()
        ));
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m record sample {n}: {} BLE, {}/{} LAN online",
            seen.len(),
            online.len(),
            known_ips.len()
        );

        // Elapsed time display
        let elapsed_h = start.elapsed().as_secs() / 3600;
        let elapsed_m = (start.elapsed().as_secs() % 3600) / 60;
        let elapsed_s = start.elapsed().as_secs() % 60;
        logger.log(&format!(
            "record sample {n}: {} BLE, {}/{} LAN [{:02}h{:02}m{:02}s elapsed]",
            seen.len(),
            online.len(),
            known_ips.len(),
            elapsed_h,
            elapsed_m,
            elapsed_s
        ));

        // Periodic snapshot: dump all known devices to log every 10 minutes.
        if last_snapshot.elapsed() >= snapshot_interval {
            last_snapshot = Instant::now();
            logger.log(&format!(
                "=== snapshot at sample {n} ({:02}h{:02}m elapsed) ===",
                elapsed_h, elapsed_m
            ));
            for f in &fps {
                let label = ble_label.get(*f).map(String::as_str).unwrap_or("");
                let rssi_str = match seen.get(*f).copied().flatten() {
                    Some(r) => format!("{r} dBm"),
                    None => "absent".to_string(),
                };
                logger.log(&format!("  ble {f} label=\"{label}\" rssi={rssi_str}"));
            }
            for ip in &known_ips {
                let label = lan_label.get(ip).map(String::as_str).unwrap_or("");
                let status = if online.contains(ip) {
                    "ONLINE"
                } else {
                    "offline"
                };
                let rtt_str = match rtts.get(ip).copied().flatten() {
                    Some(ms) => format!("rtt={ms}ms"),
                    None => String::new(),
                };
                logger.log(&format!("  lan {ip} label=\"{label}\" {status} {rtt_str}"));
            }
            logger.log("=== end snapshot ===");
        }

        if let Some(secs) = seconds {
            let secs_elapsed = start.elapsed().as_secs();
            if secs_elapsed < secs {
                tokio::time::sleep(Duration::from_secs(SAMPLE_SECS.min(secs - secs_elapsed))).await;
            }
        } else {
            tokio::time::sleep(Duration::from_secs(SAMPLE_SECS)).await;
        }
    }

    wtr.flush()?;
    Ok(())
}

/// Window (each side) used to pair an IP appearing/leaving with a BLE
/// fingerprint turning on/off: the two events must fall within +/-5 minutes.
const CLASSIFY_WINDOW: Duration = Duration::from_secs(300);

/// A transition (IP appear/leave, BLE on/off) only counts after the new state
/// has been observed for this many consecutive samples (~13s each): a single
/// missed ARP probe or a weak BLE beacon is NOT a real join/leave.
const CLASSIFY_CONFIRM: u32 = 3;

/// First N samples are warm-up: states are recorded but no events are emitted,
/// so hosts already online at boot or devices already on-air don't produce
/// spurious "appeared" events.
const CLASSIFY_WARMUP: usize = 5;

/// Real-time classifier: at every sample (~13s) compares the LAN IP timeline
/// with the BLE fingerprint timeline. When an IP appears (offline -> online)
/// and a BLE fingerprint turns on and stays on within +/-5 minutes, the pair
/// is printed as a match. The reverse direction (IP leaving + BLE turning off
/// and staying off) is matched the same way.
pub async fn classify(
    logger: &Logger,
    initial: &[BleDevice],
    lan: &[LanDevice],
    seconds: Option<u64>,
    subnets: &[ipnet::IpNet],
    netmonloc_path: Option<&Path>,
    mac_file: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let manager = Manager::new().await.map_err(|e| {
        logger.log(&format!("classify: creating manager: {e}"));
        e.to_string()
    })?;
    let adapters = manager.adapters().await.map_err(|e| {
        logger.log(&format!("classify: listing adapters: {e}"));
        e.to_string()
    })?;
    if adapters.is_empty() {
        logger.log("classify: no Bluetooth adapter — classifying LAN presence only");
    }

    // Fingerprint -> readable label.
    let ble_label: HashMap<String, String> = initial
        .iter()
        .filter_map(|d| {
            d.fingerprint.clone().map(|f| {
                let label = d
                    .name
                    .clone()
                    .or_else(|| d.hint.clone())
                    .unwrap_or_else(|| "<unnamed>".to_string());
                (f, label)
            })
        })
        .collect();

    // IP -> readable label.
    let mut lan_label: HashMap<IpAddr, String> = lan
        .iter()
        .filter_map(|d| {
            d.ip.parse::<IpAddr>().ok().map(|ip| {
                let label = if d.hostnames.is_empty() {
                    d.ip.clone()
                } else {
                    d.hostnames.join(",")
                };
                (ip, label)
            })
        })
        .collect();

    // Optional mac.txt enrichment (netmonloc inventory: MAC;Descrizione;Persona;...;IP).
    let mut mac_names: HashMap<IpAddr, (String, String, String)> = HashMap::new();
    if let Some(path) = mac_file {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let f: Vec<&str> = line.split(';').collect();
                if f.len() >= 7 {
                    if let Ok(ip) = f[6].trim().parse::<IpAddr>() {
                        mac_names.insert(
                            ip,
                            (
                                f[0].trim().to_string(),
                                f[1].trim().to_string(),
                                f[2].trim().to_string(),
                            ),
                        );
                    }
                }
            }
            logger.log(&format!(
                "classify: {} entries loaded from mac inventory {}",
                mac_names.len(),
                path.display()
            ));
        } else {
            logger.log(&format!(
                "classify: cannot read mac inventory {}",
                path.display()
            ));
        }
    }

    let mut known_ips: Vec<IpAddr> = lan.iter().filter_map(|d| d.ip.parse().ok()).collect();
    let mut known_fps: HashSet<String> = initial
        .iter()
        .filter_map(|d| d.fingerprint.clone())
        .collect();

    // Per-entity state: (present?, since-when, consecutive-sample count).
    let mut ip_state: HashMap<IpAddr, (bool, Instant, u32)> = HashMap::new();
    let mut ble_state: HashMap<String, (bool, Instant, u32)> = HashMap::new();

    // Optional netmonloc cross-check: ip -> last FASE 1 L2 confirmation epoch.
    let mut nm_last: HashMap<IpAddr, i64> = HashMap::new();
    let mut nm_checked = false;
    if let Some(path) = netmonloc_path {
        nm_checked = load_netmonloc(path, &mut nm_last);
        logger.log(&format!(
            "classify: netmonloc cross-check {} ({})",
            if nm_checked {
                "ACTIVE"
            } else {
                "unavailable (log not readable)"
            },
            path.display()
        ));
    }
    let boot_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Sliding windows of recent events (pruned to CLASSIFY_WINDOW).
    let mut ip_appears: Vec<(Instant, IpAddr)> = Vec::new();
    let mut ip_leaves: Vec<(Instant, IpAddr)> = Vec::new();
    let mut ble_ons: Vec<(Instant, String)> = Vec::new();
    let mut ble_offs: Vec<(Instant, String)> = Vec::new();
    // Pairs already reported (avoid repeats).
    let mut emitted: HashSet<(String, IpAddr)> = HashSet::new();

    let start = Instant::now();
    let mut n = 0usize;

    // Ctrl+C handler
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.store(true, Ordering::Relaxed);
        });
    }

    loop {
        if let Some(secs) = seconds {
            if start.elapsed() >= Duration::from_secs(secs) {
                break;
            }
        }
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let seen = scan_once(&adapters).await;
        let online = crate::lan::probe_alive(&known_ips);

        // Periodically re-sweep the subnets and merge hosts that joined after
        // startup. A freshly discovered host is NOT an appearance: its state is
        // seeded as stable, so only a real offline->online transition after
        // this counts (and only if netmonloc confirms it).
        if n > 0 && n.is_multiple_of(DISCOVERY_EVERY) {
            if let Some(path) = netmonloc_path {
                load_netmonloc(path, &mut nm_last);
            }
            for ip in crate::lan::arp_sweep(subnets) {
                if !known_ips.contains(&ip) {
                    known_ips.push(ip);
                    lan_label.entry(ip).or_insert_with(|| ip.to_string());
                    ip_state.insert(ip, (true, Instant::now(), CLASSIFY_CONFIRM));
                    logger.log(&format!("classify: new LAN host discovered: {ip}"));
                }
            }
        }

        // Track any fingerprint we have ever seen.
        for f in seen.keys() {
            known_fps.insert(f.clone());
        }

        n += 1;
        let now = Instant::now();

        // --- IP state transitions (confirmed by consecutive samples) ---
        for ip in &known_ips {
            let is_on = online.contains(ip);
            match ip_state.get(ip).copied() {
                None => {
                    // Boot: record state as stable (no event for the initial state).
                    ip_state.insert(*ip, (is_on, now, CLASSIFY_CONFIRM));
                }
                Some((was_on, since, cnt)) => {
                    if was_on != is_on {
                        // State changed: start counting the new state, no event yet.
                        ip_state.insert(*ip, (is_on, now, 1));
                    } else if cnt == CLASSIFY_CONFIRM - 1 {
                        // New state stable for CLASSIFY_CONFIRM samples: a real
                        // transition, timestamped when it started.
                        if n >= CLASSIFY_WARMUP {
                            if is_on {
                                ip_appears.push((since, *ip));
                            } else {
                                ip_leaves.push((since, *ip));
                            }
                        }
                        ip_state.insert(*ip, (is_on, since, CLASSIFY_CONFIRM));
                    } else {
                        ip_state.insert(*ip, (is_on, since, cnt + 1));
                    }
                }
            }
        }

        // --- BLE state transitions (confirmed by consecutive samples) ---
        for f in &known_fps {
            let present = seen.get(f).copied().flatten().is_some();
            match ble_state.get(f).copied() {
                None => {
                    ble_state.insert(f.clone(), (present, now, CLASSIFY_CONFIRM));
                }
                Some((was, since, cnt)) => {
                    if was != present {
                        ble_state.insert(f.clone(), (present, now, 1));
                    } else if cnt == CLASSIFY_CONFIRM - 1 {
                        if n >= CLASSIFY_WARMUP {
                            if present {
                                ble_ons.push((since, f.clone()));
                            } else {
                                ble_offs.push((since, f.clone()));
                            }
                        }
                        ble_state.insert(f.clone(), (present, since, CLASSIFY_CONFIRM));
                    } else {
                        ble_state.insert(f.clone(), (present, since, cnt + 1));
                    }
                }
            }
        }

        // --- Match: IP appears <-> BLE turns on (both within +/-5 min, BLE still active) ---
        for (ip_ts, ip) in &ip_appears {
            for (on_ts, f) in &ble_ons {
                if emitted.contains(&(f.clone(), *ip)) {
                    continue;
                }
                let d = if *on_ts >= *ip_ts {
                    on_ts.duration_since(*ip_ts)
                } else {
                    ip_ts.duration_since(*on_ts)
                };
                if d > CLASSIFY_WINDOW {
                    continue;
                }
                // The BLE must still be active right now (persistent).
                if !seen.get(f).copied().flatten().is_some() {
                    continue;
                }
                // Cross-check with netmonloc: the IP must have a recent L2
                // confirmation (skipped when the netmonloc log is unavailable).
                if nm_checked {
                    let ev_epoch = boot_epoch + ip_ts.duration_since(start).as_secs() as i64;
                    let ok = nm_last
                        .get(ip)
                        .map(|&last| (ev_epoch - last).abs() <= CLASSIFY_WINDOW.as_secs() as i64)
                        .unwrap_or(false);
                    if !ok {
                        logger.log(&format!(
                            "classify: skip match IP {ip} appear <-> BLE {f}: no recent netmonloc L2 confirmation"
                        ));
                        continue;
                    }
                }
                emitted.insert((f.clone(), *ip));
                let delta_s = if *on_ts >= *ip_ts {
                    on_ts.duration_since(*ip_ts).as_secs() as i64
                } else {
                    -((*ip_ts).duration_since(*on_ts).as_secs() as i64)
                };
                let ip_label = mac_names
                    .get(ip)
                    .map(|(mac, desc, person)| {
                        if person.is_empty() {
                            format!("{desc} [{mac}]")
                        } else {
                            format!("{desc} ({person}) [{mac}]")
                        }
                    })
                    .or_else(|| lan_label.get(ip).cloned())
                    .unwrap_or_else(|| ip.to_string());
                let b_label = ble_label.get(f).cloned().unwrap_or_else(|| f.clone());
                let msg = format!(
                    "MATCH: IP {ip} (\"{ip_label}\") APPEARED <-> BLE {f} (\"{b_label}\") turned ON, delta {delta_s:+}s, still active"
                );
                logger.log(&format!("classify {msg}"));
                crate::bn!("\x1b[32m[CLASSIFY] MATCH\x1b[0m: IP {ip} appare <-> BLE {f} si attiva (delta {delta_s:+}s) [attivo]");
            }
        }

        // --- Match: IP leaves <-> BLE turns off (both within +/-5 min, both still gone) ---
        for (ip_ts, ip) in &ip_leaves {
            for (off_ts, f) in &ble_offs {
                if emitted.contains(&(f.clone(), *ip)) {
                    continue;
                }
                let d = if *off_ts >= *ip_ts {
                    off_ts.duration_since(*ip_ts)
                } else {
                    ip_ts.duration_since(*off_ts)
                };
                if d > CLASSIFY_WINDOW {
                    continue;
                }
                // Both must still be gone right now.
                if seen.get(f).copied().flatten().is_some() || online.contains(ip) {
                    continue;
                }
                // Cross-check with netmonloc: the IP should NOT have a recent
                // L2 confirmation (skipped when the netmonloc log is unavailable).
                if nm_checked {
                    let ev_epoch = boot_epoch + ip_ts.duration_since(start).as_secs() as i64;
                    let ok = nm_last
                        .get(ip)
                        .map(|&last| ev_epoch - last > CLASSIFY_WINDOW.as_secs() as i64)
                        .unwrap_or(true);
                    if !ok {
                        logger.log(&format!(
                            "classify: skip match IP {ip} leave <-> BLE {f}: netmonloc still confirms the IP"
                        ));
                        continue;
                    }
                }
                emitted.insert((f.clone(), *ip));
                let delta_s = if *off_ts >= *ip_ts {
                    off_ts.duration_since(*ip_ts).as_secs() as i64
                } else {
                    -((*ip_ts).duration_since(*off_ts).as_secs() as i64)
                };
                let ip_label = mac_names
                    .get(ip)
                    .map(|(mac, desc, person)| {
                        if person.is_empty() {
                            format!("{desc} [{mac}]")
                        } else {
                            format!("{desc} ({person}) [{mac}]")
                        }
                    })
                    .or_else(|| lan_label.get(ip).cloned())
                    .unwrap_or_else(|| ip.to_string());
                let b_label = ble_label.get(f).cloned().unwrap_or_else(|| f.clone());
                let msg = format!(
                    "MATCH: IP {ip} (\"{ip_label}\") LEFT <-> BLE {f} (\"{b_label}\") turned OFF, delta {delta_s:+}s, both still gone"
                );
                logger.log(&format!("classify {msg}"));
                crate::bn!("\x1b[33m[CLASSIFY] MATCH\x1b[0m: IP {ip} esce <-> BLE {f} si spegne (delta {delta_s:+}s) [entrambi spariti]");
            }
        }

        // Prune old events from the sliding windows.
        ip_appears.retain(|(t, _)| now.duration_since(*t) <= CLASSIFY_WINDOW);
        ip_leaves.retain(|(t, _)| now.duration_since(*t) <= CLASSIFY_WINDOW);
        ble_ons.retain(|(t, _)| now.duration_since(*t) <= CLASSIFY_WINDOW);
        ble_offs.retain(|(t, _)| now.duration_since(*t) <= CLASSIFY_WINDOW);

        logger.log(&format!(
            "classify sample {n}: {} BLE, {}/{} LAN online",
            seen.len(),
            online.len(),
            known_ips.len()
        ));
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m classify sample {n}: {} BLE, {}/{} LAN online",
            seen.len(),
            online.len(),
            known_ips.len()
        );

        if let Some(secs) = seconds {
            let secs_elapsed = start.elapsed().as_secs();
            if secs_elapsed < secs {
                tokio::time::sleep(Duration::from_secs(SAMPLE_SECS.min(secs - secs_elapsed))).await;
            }
        } else {
            tokio::time::sleep(Duration::from_secs(SAMPLE_SECS)).await;
        }
    }

    Ok(())
}

/// Parse a netmonloc debug log: keep the LAST FASE 1 L2 confirmation epoch
/// per IP (`[ts ... FASE 1: ip ... vivo ...`). Returns false when the file is
/// unreadable. Re-reading it is cheap (~1-2 MB) and picks up new lines.
fn load_netmonloc(path: &Path, out: &mut HashMap<IpAddr, i64>) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    for line in text.lines() {
        if !line.contains("FASE 1:") || !line.contains("vivo") {
            continue;
        }
        let Some(ip_start) = line.find("FASE 1: ") else {
            continue;
        };
        let ip_str = line[ip_start + "FASE 1: ".len()..]
            .split_whitespace()
            .next()
            .unwrap_or("");
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };
        let Some(ts) = crate::logging::parse_rfc3339_epoch(&line[1..21]) else {
            continue;
        };
        out.insert(ip, ts);
    }
    true
}

/// Collect the current stable-fingerprint -> RSSI map from a fresh scan.
async fn collect_fingerprints(
    adapters: &[btleplug::platform::Adapter],
) -> HashMap<String, Option<i16>> {
    let mut seen: HashMap<String, Option<i16>> = HashMap::new();
    for a in adapters {
        let Ok(peripherals) = a.peripherals().await else {
            continue;
        };
        for p in peripherals {
            let Ok(Some(props)) = p.properties().await else {
                continue;
            };
            let mfr = props.manufacturer_data.clone();
            let services = props.services.clone();
            let service_data = props.service_data.clone();
            let Some(f) = stable_fingerprint(&mfr, &services, &service_data) else {
                continue;
            };
            // Prefer the strongest (most recent) RSSI for this fingerprint.
            match seen.get_mut(&f) {
                Some(slot @ None) => *slot = props.rssi,
                Some(Some(old)) => {
                    if let Some(new) = props.rssi {
                        if new > *old {
                            *old = new;
                        }
                    }
                }
                None => {
                    seen.insert(f, props.rssi);
                }
            }
        }
    }
    seen
}

/// Report the BLE <-> LAN co-movement correlation for every fingerprint/IP
/// pair with enough data. Phi ~ +1 means "when the BLE device is present the
/// IP is online (and vice versa)".
fn report(
    logger: &Logger,
    initial: &[BleDevice],
    lan: &[LanDevice],
    ble_series: &HashMap<String, Vec<Option<i16>>>,
    lan_series: &HashMap<IpAddr, Vec<bool>>,
    lan_rtt_series: &HashMap<IpAddr, Vec<Option<u32>>>,
    samples: usize,
) {
    // Fingerprint -> readable label.
    let ble_label: HashMap<&str, String> = initial
        .iter()
        .filter_map(|d| {
            d.fingerprint.as_deref().map(|f| {
                let label = d
                    .name
                    .clone()
                    .or_else(|| d.hint.clone())
                    .unwrap_or_else(|| "<unnamed>".to_string());
                (f, label)
            })
        })
        .collect();

    // IP string -> readable label.
    let lan_label: HashMap<IpAddr, String> = lan
        .iter()
        .filter_map(|d| {
            d.ip.parse::<IpAddr>().ok().map(|ip| {
                let label = if d.hostnames.is_empty() {
                    d.ip.clone()
                } else {
                    d.hostnames.join(",")
                };
                (ip, label)
            })
        })
        .collect();

    let mut results: Vec<(f32, f32, String, String, String)> = Vec::new();
    for (f, bseries) in ble_series {
        let bp: Vec<bool> = bseries.iter().map(|r| r.is_some()).collect();
        let present = bp.iter().filter(|b| **b).count();
        if present < 2 {
            continue;
        }
        let mean_rssi = {
            let vals: Vec<i16> = bseries.iter().filter_map(|r| *r).collect();
            if vals.is_empty() {
                0.0
            } else {
                vals.iter().map(|v| *v as f32).sum::<f32>() / vals.len() as f32
            }
        };
        for (ip, lseries) in lan_series {
            if lseries.len() != samples {
                continue;
            }
            let Some(phi) = phi_coefficient(&bp, lseries) else {
                continue;
            };
            if phi <= 0.25 {
                continue;
            }
            let b_label = ble_label
                .get(f.as_str())
                .cloned()
                .unwrap_or_else(|| f.clone());
            let l_label = lan_label.get(ip).cloned().unwrap_or_else(|| ip.to_string());
            results.push((phi, mean_rssi, b_label, l_label, f.clone()));
        }
    }

    // RSSI (BLE) vs RTT (LAN) continuous co-movement: both degrade with
    // physical distance, so a phone that stays online can still be matched.
    let mut rtt_results: Vec<(f32, f32, String, String)> = Vec::new();
    for (f, bseries) in ble_series {
        let b_label = ble_label
            .get(f.as_str())
            .cloned()
            .unwrap_or_else(|| f.clone());
        for (ip, rtts) in lan_rtt_series {
            if rtts.len() != samples {
                continue;
            }
            let Some(r) = pearson(bseries, rtts) else {
                continue;
            };
            // Strong anti-correlation = RSSI strong (near) when RTT low (near).
            if r > -0.5 {
                continue;
            }
            let mean_rssi = {
                let vals: Vec<i16> = bseries.iter().filter_map(|x| *x).collect();
                if vals.is_empty() {
                    0.0
                } else {
                    vals.iter().map(|v| *v as f32).sum::<f32>() / vals.len() as f32
                }
            };
            let l_label = lan_label.get(ip).cloned().unwrap_or_else(|| ip.to_string());
            rtt_results.push((r, mean_rssi, b_label.clone(), l_label));
        }
    }
    rtt_results.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m === Co-movement (BLE RSSI <-> LAN presence) ===");
    logger.log(&format!(
        "co-movement: {} sample(s), {} BLE fingerprint(s), {} LAN IP(s)",
        samples,
        ble_series.len(),
        lan_series.len()
    ));

    if results.is_empty() {
        let line =
            "no presence correlation (need the device to appear/disappear during the window)";
        logger.log(&format!("co-movement: {line}"));
        crate::bn!("  {line}");
    }

    for (phi, mean_rssi, b_label, l_label, f) in results {
        let line =
            format!("{b_label} (RSSI ~{mean_rssi:.0} dBm) <-> {l_label}  [phi={phi:+.2}]  ({f})",);
        logger.log(&format!("co-movement: {line}"));
        crate::bn!("  \x1b[33m{}\x1b[0m", line);
    }

    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m === Co-movement (BLE RSSI <-> LAN RTT) ===");
    if rtt_results.is_empty() {
        let line =
            "no RSSI<->RTT correlation (move the device during the window, or ICMP is filtered)";
        logger.log(&format!("co-movement rtt: {line}"));
        crate::bn!("  {line}");
    } else {
        for (r, mean_rssi, b_label, l_label) in rtt_results {
            let line = format!(
                "{b_label} (RSSI ~{mean_rssi:.0} dBm) <-> {l_label}  [r={r:+.2}; negative = co-moving distance]",
            );
            logger.log(&format!("co-movement rtt: {line}"));
            crate::bn!("  \x1b[33m{}\x1b[0m", line);
        }
    }
}

/// Phi coefficient (binary Pearson correlation) between two boolean series.
fn phi_coefficient(a: &[bool], b: &[bool]) -> Option<f32> {
    let n = a.len();
    if n != b.len() || n < 2 {
        return None;
    }
    let (mut aa, mut ab, mut ba, mut bb) = (0i64, 0i64, 0i64, 0i64);
    for i in 0..n {
        match (a[i], b[i]) {
            (true, true) => aa += 1,
            (true, false) => ab += 1,
            (false, true) => ba += 1,
            (false, false) => bb += 1,
        }
    }
    let num = (aa * bb - ab * ba) as f64;
    let denom = ((aa + ab) as f64 * (ba + bb) as f64 * (aa + ba) as f64 * (ab + bb) as f64).sqrt();
    if denom == 0.0 {
        return None;
    }
    Some((num / denom) as f32)
}

/// Pearson correlation between a BLE RSSI series (Option<i16>) and a LAN RTT
/// series (Option<u32>), pairing only the samples where both are present.
/// Negative r = RSSI strong (near) when RTT low (near): co-moving distance.
fn pearson(a: &[Option<i16>], b: &[Option<u32>]) -> Option<f32> {
    if a.len() != b.len() {
        return None;
    }
    let mut xs: Vec<f32> = Vec::new();
    let mut ys: Vec<f32> = Vec::new();
    for (x, y) in a.iter().zip(b.iter()) {
        if let (Some(x), Some(y)) = (x, y) {
            xs.push(*x as f32);
            ys.push(*y as f32);
        }
    }
    if xs.len() < 3 {
        return None;
    }
    let n = xs.len() as f32;
    let mx = xs.iter().sum::<f32>() / n;
    let my = ys.iter().sum::<f32>() / n;
    let (mut cov, mut vx, mut vy) = (0.0f32, 0.0f32, 0.0f32);
    for (x, y) in xs.iter().zip(ys.iter()) {
        cov += (x - mx) * (y - my);
        vx += (x - mx) * (x - mx);
        vy += (y - my) * (y - my);
    }
    if vx == 0.0 || vy == 0.0 {
        return None;
    }
    Some(cov / (vx * vy).sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f32, b: f32) -> bool {
        (a - b).abs() < 0.001
    }

    #[test]
    fn phi_perfect_positive() {
        let a = [true, true, false, false];
        let b = [true, true, false, false];
        assert!(close(phi_coefficient(&a, &b).unwrap(), 1.0));
    }

    #[test]
    fn phi_perfect_negative() {
        let a = [true, true, false, false];
        let b = [false, false, true, true];
        assert!(close(phi_coefficient(&a, &b).unwrap(), -1.0));
    }

    #[test]
    fn phi_independent_zero() {
        let a = [true, false, true, false];
        let b = [true, true, false, false];
        assert!(close(phi_coefficient(&a, &b).unwrap(), 0.0));
    }

    #[test]
    fn phi_constant_series_is_none() {
        let a = [true, true, true];
        let b = [true, true, true];
        assert!(phi_coefficient(&a, &b).is_none());
    }

    #[test]
    fn pearson_anticorrelated() {
        let rssi = [Some(-40i16), Some(-50), Some(-60), Some(-70)];
        let rtt = [Some(5u32), Some(15), Some(25), Some(35)];
        assert!(close(pearson(&rssi, &rtt).unwrap(), -1.0));
    }

    #[test]
    fn pearson_skips_missing() {
        let rssi = [Some(-40i16), None, Some(-60), Some(-70)];
        let rtt = [Some(5u32), Some(999), Some(25), Some(35)];
        assert!(close(pearson(&rssi, &rtt).unwrap(), -1.0));
    }

    #[test]
    fn pearson_constant_is_none() {
        let rssi = [Some(-40i16), Some(-40), Some(-40)];
        let rtt = [Some(5u32), Some(6), Some(5)];
        assert!(pearson(&rssi, &rtt).is_none());
    }
}
