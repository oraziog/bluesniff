//! netmonloc integration: bluesniff streams its sightings out via standard
//! calls instead of a log file that the other application would have to read.
//!
//! Two channels, same payload:
//! - `--json`: one NDJSON line per scan cycle on **stdout** (netmonloc starts
//!   `bluesniff --listen --json` as a subprocess and reads its stdout; a
//!   `snapshot` line on our stdin answers with an immediate JSON line);
//! - `--push <url>`: the same snapshot is POSTed (HTTP, `application/json`)
//!   to netmonloc's endpoint from a background task, so the scan loop never
//!   blocks. Retry with exponential backoff; if newer snapshots queue up
//!   while the server is down, the stale ones are coalesced (fresh wins).
//!
//! In either streaming mode `presenze.csv` is NOT written: the log stays the
//! local archive only for non-streaming runs, exactly like netmonloc wants
//! ("dacci i dati via chiamate, non via file").

use std::time::Duration;

use crate::classify::{classify_device, proximity_zone};
use crate::logging::Logger;

/// Streaming configuration (built in `main` from `--json` / `--push`).
#[derive(Debug, Clone, Default)]
pub struct StreamConfig {
    /// `--json`: one NDJSON line per cycle on stdout.
    pub json: bool,
    /// `--push <url>`: POST the snapshot to this endpoint.
    pub push_url: Option<String>,
    /// `--push-token <tok>`: optional `X-Api-Token` header.
    pub push_token: Option<String>,
}

impl StreamConfig {
    pub fn active(&self) -> bool {
        self.json || self.push_url.is_some()
    }
}

/// Everything the listen loop needs to stream (config + the pusher sender
/// when `--push` is active).
pub struct StreamHandle {
    pub cfg: StreamConfig,
    pub push_tx: Option<tokio::sync::mpsc::UnboundedSender<serde_json::Value>>,
}

/// Build the per-cycle snapshot payload. Pure function, unit-testable.
///
/// ```json
/// {
///   "protocol": "bluesniff/1",
///   "station": "8C:88:2B:31:5B:74",
///   "station_name": "VM_WIN_11",
///   "ts": "2026-09-03T10:00:00Z",
///   "cycle": 42,
///   "sightings": [ { "mac": "...", "name": "...", "rssi": -70, ... } ]
/// }
/// ```
///
/// Optional fields (name, vendor, rssi, …) are omitted when unknown, so the
/// schema is self-describing. netmonloc derives presence (arrived/gone) by
/// diffing consecutive snapshots: every cycle lists exactly what is on air
/// right now.
pub fn snapshot_value(
    station: &str,
    station_name: &str,
    ts: &str,
    cycle: usize,
    seen: &[crate::blewatcher::Seen],
) -> serde_json::Value {
    let sightings: Vec<serde_json::Value> = seen
        .iter()
        .map(|d| {
            let mut o = serde_json::Map::new();
            o.insert("mac".to_string(), serde_json::json!(d.mac));
            if let Some(name) = &d.name {
                o.insert("name".to_string(), serde_json::json!(name));
            }
            if let Some(vendor) = &d.vendor {
                o.insert("vendor".to_string(), serde_json::json!(vendor));
            }
            if let Some(hint) = &d.hint {
                o.insert("hint".to_string(), serde_json::json!(hint));
            }
            if let Some(model_id) = d.model_id {
                o.insert("model_id".to_string(), serde_json::json!(model_id));
            }
            if let Some(phantom) = d.phantom {
                o.insert("phantom".to_string(), serde_json::json!(phantom));
            }
            if let Some(tx) = d.tx_power {
                o.insert("tx_power".to_string(), serde_json::json!(tx));
            }
            let category =
                classify_device(d.name.as_deref(), d.vendor.as_deref(), d.hint.as_deref());
            o.insert("category".to_string(), serde_json::json!(category.label()));
            if let Some(rssi) = d.rssi {
                o.insert("rssi".to_string(), serde_json::json!(rssi));
            }
            if let Some(zone) = proximity_zone(d.rssi) {
                o.insert("zone".to_string(), serde_json::json!(zone));
            }
            if let Some(c) = d.connectable {
                o.insert("connectable".to_string(), serde_json::json!(c));
            }
            serde_json::Value::Object(o)
        })
        .collect();

    serde_json::json!({
        "protocol": "bluesniff/1",
        "station": station,
        "station_name": station_name,
        "ts": ts,
        "cycle": cycle,
        "sightings": sightings,
    })
}

/// Spawn the background HTTP pusher. Returns the sender the listen loop uses;
/// `send` never blocks.
///
/// `logger` e' preso **per valore**: e' un `Logger` (condiviso, clonabile), non
/// un riferimento, quindi il thread lo possiede e non serve alcun `&'static`
/// inventato. Il main passa `logger.clone()`.
pub fn spawn_pusher(
    logger: Logger,
    url: String,
    token: Option<String>,
) -> tokio::sync::mpsc::UnboundedSender<serde_json::Value> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    // IMPORTANT (this VM): the pusher runs on its OWN OS thread with a
    // dedicated current-thread tokio runtime. When it shared the main
    // runtime, concurrent reqwest activity stalled the listen loop after 1-2
    // cycles and ended in STATUS_HEAP_CORRUPTION (0xC0000374) — the WinRT BLE
    // watcher's COM apartment does not tolerate the shared runtime's
    // worker/timer activity.
    std::thread::Builder::new()
        .name("bt-push".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    logger.log(&format!("push: cannot start dedicated runtime: {e}"));
                    return;
                }
            };
            rt.block_on(push_loop(logger, &url, token.as_deref(), rx));
        })
        .ok();
    tx
}

/// Delivery loop (executed inside the pusher thread's own runtime). Retry
/// with exponential backoff; if newer snapshots queue up while the server is
/// down, the stale ones are coalesced (fresh wins, memory stays bounded).
async fn push_loop(
    logger: Logger,
    url: &str,
    token: Option<&str>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let mut backoff_secs: u64 = 1;
    // Latest payload still to deliver (None = waiting for the next one).
    let mut pending: Option<serde_json::Value> = None;
    loop {
        if pending.is_none() {
            match rx.recv().await {
                Some(v) => pending = Some(v),
                None => break, // channel closed -> process ending
            }
        }
        let payload = pending.take().unwrap();
        let mut req = client.post(url);
        if let Some(tok) = token {
            req = req.header("x-api-token", tok);
        }
        match req.json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                backoff_secs = 1;
                logger.log(&format!(
                    "push: {url} -> {} (cycle {})",
                    resp.status(),
                    payload["cycle"]
                ));
            }
            Ok(resp) => {
                logger.log(&format!(
                    "push: {url} -> HTTP {} (retry in {backoff_secs}s)",
                    resp.status()
                ));
                sleep_and_coalesce(&mut rx, &mut pending, &mut backoff_secs, payload).await;
            }
            Err(e) => {
                logger.log(&format!(
                    "push: {url} failed: {e} (retry in {backoff_secs}s)"
                ));
                sleep_and_coalesce(&mut rx, &mut pending, &mut backoff_secs, payload).await;
            }
        }
    }
}

/// After a failed POST: sleep the current backoff, grow it (capped at 30 s),
/// and drain any newer queued snapshots keeping only the freshest one, so a
/// long outage coalesces the backlog instead of replaying stale frames.
async fn sleep_and_coalesce(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
    pending: &mut Option<serde_json::Value>,
    backoff_secs: &mut u64,
    failed: serde_json::Value,
) {
    tokio::time::sleep(Duration::from_secs(*backoff_secs)).await;
    *backoff_secs = (*backoff_secs * 2).min(30);
    let mut latest = None;
    while let Ok(v) = rx.try_recv() {
        latest = Some(v);
    }
    *pending = latest.or(Some(failed));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blewatcher::Seen;

    fn seen(mac: &str, name: Option<&str>, rssi: Option<i16>) -> Seen {
        Seen {
            mac: mac.to_string(),
            name: name.map(|s| s.to_string()),
            rssi,
            vendor: None,
            hint: None,
            fingerprint: None,
            model_id: None,
            phantom: None,
            tx_power: None,
            tx_ibeacon: false,
            connectable: None,
        }
    }

    #[test]
    fn snapshot_shape_and_fields() {
        let v = snapshot_value(
            "AA:BB:CC:DD:EE:FF",
            "PC01",
            "2026-09-03T10:00:00Z",
            7,
            &[
                seen("11:22:33:44:55:66", Some("iPhone di Pino"), Some(-65)),
                seen("AA:BB:CC:DD:EE:01", None, None),
            ],
        );
        assert_eq!(v["protocol"], "bluesniff/1");
        assert_eq!(v["station"], "AA:BB:CC:DD:EE:FF");
        assert_eq!(v["station_name"], "PC01");
        assert_eq!(v["ts"], "2026-09-03T10:00:00Z");
        assert_eq!(v["cycle"], 7);
        let s = &v["sightings"];
        assert_eq!(s.as_array().unwrap().len(), 2);
        let first = &s[0];
        assert_eq!(first["mac"], "11:22:33:44:55:66");
        assert_eq!(first["name"], "iPhone di Pino");
        assert_eq!(first["category"], "phone");
        assert_eq!(first["rssi"], -65);
        assert_eq!(first["zone"], "far");
        // Senza name/vendor il device cade in "other"; i campi assenti non
        // compaiono proprio (schema auto-descrittivo).
        let second = &s[1];
        assert_eq!(second["mac"], "AA:BB:CC:DD:EE:01");
        assert_eq!(second["category"], "other");
        assert!(second.get("name").is_none());
        assert!(second.get("rssi").is_none());
        assert!(second.get("zone").is_none());
        assert!(second.get("connectable").is_none());
        // Serializza come una singola riga NDJSON valida (niente newline).
        let line = v.to_string();
        assert!(!line.contains('\n'));
        assert!(line.contains("\"name\""));
        assert!(serde_json::from_str::<serde_json::Value>(&line).is_ok());
    }

    #[test]
    fn snapshot_optional_fields_and_escaping() {
        let mut d = seen(
            "11:22:33:44:55:66",
            Some("Tile \"casa\" (kitchen)"),
            Some(-30),
        );
        d.vendor = Some("Tile Inc".to_string());
        d.hint = Some("tile".to_string());
        d.phantom = Some("tile");
        d.connectable = Some(false);
        let v = snapshot_value("ST", "host", "2026-09-03T10:00:00Z", 1, &[d]);
        let s = &v["sightings"][0];
        assert_eq!(s["vendor"], "Tile Inc");
        assert_eq!(s["hint"], "tile");
        assert_eq!(s["phantom"], "tile");
        assert_eq!(s["connectable"], false);
        assert_eq!(s["zone"], "immediate");
        // Le virgolette nel nome devono essere sfuggite nella riga NDJSON.
        let line = v.to_string();
        assert!(line.contains("Tile \\\"casa\\\" (kitchen)"));
        assert!(serde_json::from_str::<serde_json::Value>(&line).is_ok());
    }
}
