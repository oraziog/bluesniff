use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::logging::Logger;

/// TTL of the negative cache (7 days): a MAC that failed to resolve is not
/// retried on the API for a week, then it is tried again. Mirrors netmonloc so
/// the two tools behave identically on a shared cache file.
const NEGATIVE_CACHE_TTL_SECS: u64 = 7 * 24 * 3600;

/// On-disk cache format shared with netmonloc (`vendors.json` next to the exe).
///
/// `entries` is flattened to the top level (MAC -> vendor) and `negative` is a
/// nested MAC -> unix-timestamp map, so the file remains byte-compatible with
/// netmonloc's `VendorCacheFile` (including its legacy flat format without the
/// `negative` field).
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
struct VendorCacheFile {
    #[serde(flatten)]
    entries: HashMap<String, String>,
    #[serde(default)]
    negative: HashMap<String, u64>,
}

impl VendorCacheFile {
    fn load(path: &Path) -> VendorCacheFile {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => VendorCacheFile::default(),
        }
    }

    fn save(&self, path: &Path) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    fn is_negatively_cached(&self, mac: &str, now_unix: u64) -> bool {
        self.negative
            .get(mac)
            .is_some_and(|ts| now_unix.saturating_sub(*ts) < NEGATIVE_CACHE_TTL_SECS)
    }

    /// Removes expired negative entries; returns how many were removed so the
    /// caller knows whether a save is worth doing.
    fn evict_expired_negatives(&mut self, now_unix: u64) -> usize {
        let before = self.negative.len();
        self.negative
            .retain(|_, ts| now_unix.saturating_sub(*ts) < NEGATIVE_CACHE_TTL_SECS);
        before - self.negative.len()
    }
}

/// Resolve the OUI vendor for a list of MACs via `api.macvendors.com`, backed
/// by a persistent `vendors.json` cache next to the executable (same file and
/// schema as netmonloc). Locally-administered (randomised) MACs are skipped.
/// Returns MAC -> vendor (absent = unknown/skipped). Rate-limit aware (1 req/s).
pub async fn resolve_vendors(logger: &Logger, macs: &[String]) -> HashMap<String, String> {
    let path = exe_dir().join("vendors.json");
    let mut cache = VendorCacheFile::load(&path);
    let now = unix_now();
    if cache.evict_expired_negatives(now) > 0 {
        cache.save(&path);
    }

    let mut out = HashMap::new();

    // Normalise to uppercase so bluesniff and netmonloc share cache entries.
    let mut targets: Vec<String> = macs
        .iter()
        .filter(|m| !is_locally_administered(m))
        .map(|m| m.to_uppercase())
        .collect();
    targets.sort();
    targets.dedup();

    if targets.is_empty() {
        logger.log("OUI: all MACs are locally administered (randomised), skipping lookups");
        return out;
    }

    // Split into cache hits vs. MACs that still need the API.
    let mut to_fetch: Vec<String> = Vec::new();
    for mac in &targets {
        if let Some(vendor) = cache.entries.get(mac) {
            if !vendor.is_empty() {
                out.insert(mac.clone(), vendor.clone());
                logger.log(&format!("OUI {mac} = {vendor} (cache)"));
                continue;
            }
        }
        if cache.is_negatively_cached(mac, now) {
            logger.log(&format!("OUI {mac} = unknown (negative cache)"));
            continue;
        }
        to_fetch.push(mac.clone());
    }

    if to_fetch.is_empty() {
        return out;
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            logger.log(&format!("OUI: HTTP client error: {e}"));
            return out;
        }
    };

    logger.log(&format!(
        "OUI: resolving {} non-cached MAC(s) via API",
        to_fetch.len()
    ));
    for (i, mac) in to_fetch.iter().enumerate() {
        // macvendors.com free tier throttles at ~1 req/sec.
        if i > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let url = format!("https://api.macvendors.com/{mac}");
        let mut resolved = false;
        match client.get(&url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text().await {
                        let vendor = text.trim().to_string();
                        if !vendor.is_empty() && !vendor.contains("errors") {
                            logger.log(&format!("OUI {mac} = {vendor}"));
                            cache.entries.insert(mac.clone(), vendor.clone());
                            cache.negative.remove(mac);
                            out.insert(mac.clone(), vendor);
                            resolved = true;
                        }
                    }
                } else if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    logger.log("OUI: rate limited, stopping lookups");
                    cache.save(&path);
                    break;
                } else {
                    logger.log(&format!("OUI {mac}: HTTP {}", resp.status()));
                }
            }
            Err(e) => {
                logger.log(&format!("OUI {mac}: {e}"));
            }
        }
        if !resolved {
            // Negative caching: don't re-query this MAC for a week.
            cache.negative.insert(mac.clone(), now);
            logger.log(&format!("OUI {mac} = unknown"));
        }
        cache.save(&path);
    }

    out
}

/// `vendors.json` (and the exe) live next to the executable.
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True if the MAC has the "locally administered" bit set (second bit of the
/// first octet) — the signature of a randomised / privacy MAC.
///
/// Un MAC vuoto o illeggibile non e' "randomizzato": non lo sappiamo. In quel
/// caso rispondiamo `false`, cosi' la scheda non etichetta un dispositivo
/// sconosciuto come privato.
pub fn is_locally_administered(mac: &str) -> bool {
    let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    match clean.get(0..2) {
        Some(hex) => u8::from_str_radix(hex, 16)
            .map(|b| (b & 0x02) != 0)
            .unwrap_or(false),
        None => false,
    }
}
