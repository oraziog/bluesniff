use std::collections::HashSet;

use crate::bluetooth::BleDevice;
use crate::lan::LanDevice;
use crate::logging::Logger;

/// Print the LAN devices alongside the BLE scan and report candidate matches.
///
/// Matching keys, in order of reliability:
/// 1. name similarity (BLE GATT name vs mDNS instance/hostname, token-based);
/// 2. vendor (BLE company ID vs LAN OUI vendor).
///
/// The MACs are NOT compared: BLE MACs are random and rotate, so equality
/// would never match — identity lives in name/vendor + co-presence.
pub fn report(logger: &Logger, ble: &[BleDevice], lan: &[LanDevice]) {
    logger.log(&format!("LAN: {} device(s) in ARP table", lan.len()));
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m === WiFi/LAN devices (ARP + mDNS) ===");
    for d in lan {
        let vendor_display = if d.vendor.is_empty() {
            "-"
        } else {
            d.vendor.as_str()
        };
        let host = if d.hostnames.is_empty() {
            "-".to_string()
        } else {
            d.hostnames.join(",")
        };
        logger.log(&format!(
            "lan {} {} {} hostname={}",
            d.ip, d.mac, d.vendor, host
        ));
        crate::bn!("  {:>15}  {}  {:<18} {}", d.ip, d.mac, vendor_display, host);
    }

    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m === Match BLE <-> LAN (name/vendor) ===");

    // (score, reason, ble_index, lan_index) — keep scores for sorting.
    let mut matches: Vec<(f32, String, usize, usize)> = Vec::new();
    for (bi, b) in ble.iter().enumerate() {
        for (li, l) in lan.iter().enumerate() {
            let (score, reason) = match_score(b, l);
            if score >= 0.4 {
                matches.push((score, reason, bi, li));
            }
        }
    }
    matches.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    if matches.is_empty() {
        logger.log("no BLE<->LAN matches");
        crate::bn!("  (nessun match)");
        return;
    }

    for (score, reason, bi, li) in matches {
        let b = &ble[bi];
        let l = &lan[li];
        let lan_name = if l.hostnames.is_empty() {
            "-".to_string()
        } else {
            l.hostnames.join(",")
        };
        let line = format!(
            "{} (BLE {}) <-> {} (LAN {})  [{} | {:.0}%]",
            b.name.as_deref().unwrap_or("<none>"),
            b.mac,
            lan_name,
            l.ip,
            reason,
            score * 100.0,
        );
        logger.log(&format!("match {line}"));
        crate::bn!("  \x1b[33m{}\x1b[0m", line);
    }
}

/// Score a BLE device against a LAN device (0.0..1.0).
fn match_score(b: &BleDevice, l: &LanDevice) -> (f32, String) {
    // 1. Name similarity: strongest signal (e.g. BLE "Galaxy A41 di Salvatore"
    //    vs mDNS "Galaxy-A41"). Try every candidate name this IP announced.
    if let Some(bn) = &b.name {
        for ln in &l.hostnames {
            let sim = name_similarity(bn, ln);
            if sim >= 0.5 {
                return (sim * 0.95, format!("name \"{bn}\" ~ \"{ln}\""));
            }
        }
    }

    // 2. Vendor match: weaker, but useful when MAC is not randomised.
    if let Some(bv) = &b.vendor {
        if !l.vendor.is_empty() && bv.eq_ignore_ascii_case(&l.vendor) {
            return (0.45, format!("vendor {bv}"));
        }
    }

    (0.0, String::new())
}

/// Token-based similarity for two device names (case-insensitive, stop-words
/// removed, "di/il/la/..." dropped). Jaccard over token sets.
fn name_similarity(a: &str, b: &str) -> f32 {
    let ta = tokens(a);
    let tb = tokens(b);
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let inter = ta.intersection(&tb).count();
    let union = ta.union(&tb).count();
    inter as f32 / union as f32
}

fn tokens(name: &str) -> HashSet<String> {
    const STOPWORDS: &[&str] = &[
        "di", "del", "della", "dello", "dei", "il", "la", "le", "lo", "the", "s", "m",
    ];
    name.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty() && !STOPWORDS.contains(t))
        .map(|t| t.to_string())
        .collect()
}
