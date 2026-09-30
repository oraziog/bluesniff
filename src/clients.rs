//! Tracciamento dei client connessi alla dashboard.
//!
//! La dashboard di default ascolta su `127.0.0.1`, ma con `--dashboard-addr lan`
//! si espone a tutta la rete locale. In quel momento la domanda "chi si e'
//! collegato" diventa legittima, e senza questo modulo la risposta sarebbe
//! "non lo so".
//!
//! Nota su cosa viene registrato: **solo indirizzi IP, mai richieste, header o
//! contenuti**. Il percorso della richiesta resta fuori perche' una dashboard
//! esposta che registra cosa guarda ogni utente e' un registro di sorveglianza,
//! non uno strumento diagnostico. Serve a rispondere "quanti e quali IP", che
//! e' la domanda operativa, e nient'altro.
//!
//! Un IP puo' essere piu' di un client reale (NAT, proxy) e un client puo'
//! cambiare IP: sono stime, non identita'. L'app lo dice.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Un client visto almeno una volta.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub ip: String,
    /// Indirizzo non compresso, utile per distinguere due IPv6 equivalenti.
    pub full_ip: String,
    /// Richieste HTTP servite a questo IP.
    pub requests: u64,
    /// Prima e ultima richiesta (epoch ms).
    pub first_ms: i64,
    pub last_ms: i64,
    /// Ultimo percorso richiesto: serve a distinguere una dashboard aperta da
    /// uno script che martella l'API. Non e' un log di navigazione.
    pub last_path: String,
}

static CLIENTS: Mutex<Option<HashMap<String, ClientInfo>>> = Mutex::new(None);
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Registra una richiesta dal peer indicato.
///
/// `ip` e' l'indirizzo del peer. Quando manca (per esempio con un reverse
/// proxy) non registriamo nulla: inventare un "sconosciuto" unico per richiesta
/// produrrebbe un elenco di clienti falso, che e' peggio di non avere nulla.
pub fn note(ip: Option<IpAddr>, path: &str) {
    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    let Some(ip) = ip else { return };
    let now = now_ms();
    let key = ip.to_string();
    let mut guard = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let entry = map.entry(key.clone()).or_insert_with(|| ClientInfo {
        ip: key.clone(),
        full_ip: key.clone(),
        requests: 0,
        first_ms: now,
        last_ms: now,
        last_path: path.to_string(),
    });
    entry.requests += 1;
    entry.last_ms = now;
    entry.full_ip = key;
    entry.last_path = path.to_string();
}

/// Client noti, dal piu' recente al meno recente.
pub fn clients() -> Vec<ClientInfo> {
    let guard = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(map) = guard.as_ref() else {
        return Vec::new();
    };
    let mut out: Vec<ClientInfo> = map.values().cloned().collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.last_ms));
    out
}

pub fn total_requests() -> u64 {
    TOTAL_REQUESTS.load(Ordering::Relaxed)
}

/// JSON per la dashboard.
pub fn clients_json() -> serde_json::Value {
    let list = clients();
    let now = now_ms();
    serde_json::json!({
        "unique_ips": list.len(),
        "total_requests": total_requests(),
        "note": "Solo indirizzi IP: non registriamo richieste, header o contenuti.",
        "clients": list.iter().map(|c| serde_json::json!({
            "ip": c.ip,
            "requests": c.requests,
            "first_seen": crate::logging::rfc3339_millis(c.first_ms),
            "last_seen": crate::logging::rfc3339_millis(c.last_ms),
            "last_seen_ms": c.last_ms,
            "idle_seconds": ((now - c.last_ms) / 1000).max(0),
            "last_path": c.last_path,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Il registro e' globale: i test non girano in parallelo fra loro.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() {
        *CLIENTS.lock().unwrap_or_else(|e| e.into_inner()) = None;
        TOTAL_REQUESTS.store(0, Ordering::Relaxed);
    }

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, a))
    }

    #[test]
    fn registra_e_agrega_lo_stesso_ip() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        note(Some(ip(10)), "/api/raw");
        note(Some(ip(10)), "/api/presence");
        note(Some(ip(10)), "/api/presence");
        let c = clients();
        assert_eq!(c.len(), 1, "lo stesso IP deve contare una volta sola");
        assert_eq!(c[0].requests, 3);
        assert_eq!(c[0].ip, "192.168.1.10");
    }

    #[test]
    fn conta_gli_ip_distinti_e_ordina_per_uso_recente() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        note(Some(ip(10)), "/a");
        std::thread::sleep(std::time::Duration::from_millis(5));
        note(Some(ip(20)), "/b");
        std::thread::sleep(std::time::Duration::from_millis(5));
        note(Some(ip(10)), "/c");
        let c = clients();
        assert_eq!(c.len(), 2);
        // Il piu' recente sta in cima.
        assert_eq!(c[0].ip, "192.168.1.10");
    }

    #[test]
    fn senza_ip_non_inventa_cliente() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        note(None, "/api/raw");
        // Nessun IP: niente voci. Inventare "sconosciuto" produrrebbe un elenco
        // di clienti falso, che e' peggio di un elenco vuoto.
        assert!(clients().is_empty());
        assert_eq!(total_requests(), 1, "la richiesta e' comunque contata");
    }

    #[test]
    fn il_json_dichiara_che_sono_stime() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        note(Some(ip(10)), "/api/raw");
        let v = clients_json();
        assert_eq!(v["unique_ips"], 1);
        assert_eq!(v["total_requests"], 1);
        assert!(v["note"].as_str().unwrap().contains("Solo indirizzi IP"));
        assert!(v["clients"][0]["last_path"]
            .as_str()
            .unwrap()
            .starts_with("/api"));
    }
}
