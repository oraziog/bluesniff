//! Registrazione mDNS Service Discovery per bluesniff.
//!
//! Questo modulo permette a bluesniff di annunciare la propria presenza e i
//! servizi disponibili (dashboard web, API) nella rete locale tramite mDNS/
//! Bonjour/Avahi. I dispositivi nella stessa rete (PC, smartphone, Apple,
//! Linux) possono così scoprire automaticamente bluesniff.
//!
//! Il servizio viene registrato come `_blusniff._tcp.local.` con record TXT
//! contenenti versione, stato e descrizione. Il daemon mDNS-sd viene mantenuto
//! in vita per tutta la durata dell'applicazione.

use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;

use mdns_sd::{ServiceDaemon, ServiceInfo};

use crate::logging::Logger;

/// Versione del pacchetto (letta da Cargo.toml a compile-time).
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Tipo di servizio mDNS per bluesniff.
const SERVICE_TYPE: &str = "_blusniff._tcp.local.";

/// Nome dell'istanza che apparirà nei dispositivi di rete.
const INSTANCE_NAME: &str = "BlueSniff Network Monitor";

/// Registra il servizio bluesniff nella rete locale tramite mDNS.
///
/// Ritorna il `ServiceDaemon` per mantenerlo in vita nello scope del chiamante:
/// se la variabile viene deallocata (Drop), l'annuncio mDNS si interrompe.
///
/// # Argomenti
///
/// * `logger` - Logger per i messaggi di stato.
/// * `port` - Porta TCP del servizio da annunciare (es. 9000 per la dashboard).
///
/// # Errori
///
/// Ritorna un errore se il daemon mDNS non può essere avviato o il servizio
/// registrato (non bloccante: l'errore viene loggato e l'app continua).
pub fn start_mdns_responder(logger: &Logger, port: u16) -> Result<ServiceDaemon, Box<dyn Error>> {
    logger.log(&format!(
        "mDNS register: avvio daemon per servizio {}",
        SERVICE_TYPE
    ));

    // Avvia il daemon mDNS (gestisce broadcast/risposta multicast).
    let mdns = ServiceDaemon::new()?;

    // Raccogliamo gli indirizzi IP locali per il servizio.
    let addrs = local_ip_addresses();
    if addrs.is_empty() {
        logger.log("mDNS register: nessun indirizzo IP locale rilevato");
    } else {
        logger.log(&format!(
            "mDNS register: IP locali rilevati: {}",
            addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // Record TXT con metadati del servizio.
    let mut txt_props = HashMap::new();
    txt_props.insert("version".to_string(), PKG_VERSION.to_string());
    txt_props.insert("status".to_string(), "active".to_string());
    txt_props.insert(
        "description".to_string(),
        "Bluetooth scanner con dashboard web e API".to_string(),
    );
    txt_props.insert("dashboard".to_string(), format!("http://localhost:{port}"));

    // Crea le informazioni del servizio.
    // mdns-sd seleziona automaticamente l'interfaccia primaria se gli IP non
    // vengono specificati esplicitamente.
    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        INSTANCE_NAME,
        &mdns_hostname(),
        "",
        port,
        txt_props,
    )?;

    // Registra il servizio nel daemon.
    match mdns.register(service_info) {
        Ok(_) => {
            logger.log(&format!(
                "mDNS register: servizio '{}' registrato su porta {} (versione {})",
                INSTANCE_NAME, port, PKG_VERSION
            ));
            Ok(mdns)
        }
        Err(e) => {
            let msg = format!("mDNS register: registrazione fallita: {e}");
            logger.log(&msg);
            // Non è un errore fatale: l'app continua senza mDNS.
            Err(e.into())
        }
    }
}

/// Indirizzi IPv4 locali utilizzabili per annunciare l'interfaccia di rete.
///
/// Delegato a `lan::local_ipv4_addrs()`, che interroga la tabella IP di
/// Winsock (GetIpAddrTable). I due approcci che avevamo prima fallivano in
/// scenari frequenti: il socket verso 8.8.8.8 non funziona senza connettivita
/// Internet, e la risoluzione del nome host dipende da NetBIOS e DNS.
fn local_ip_addresses() -> Vec<IpAddr> {
    crate::lan::local_ipv4_addrs()
        .into_iter()
        .map(IpAddr::V4)
        .collect()
}

/// Ottieni il nome della macchina dall'ambiente (COMPUTERNAME su Windows,
/// HOSTNAME su Linux/macOS), con fallback a "bluesniff".
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "bluesniff".to_string())
}

/// Hostname completo in formato mDNS: mdns-sd esige che termini con ".local.".
/// Usa solo il primo label del nome macchina (evita domini tipo
/// "pc.example.com", che sono invalidi come host mDNS).
fn mdns_hostname() -> String {
    let raw = hostname();
    let label = raw.split('.').next().unwrap_or("bluesniff").trim();
    if label.is_empty() {
        "bluesniff.local.".to_string()
    } else {
        format!("{label}.local.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_ip_addresses() {
        let addrs = local_ip_addresses();
        // Dovrebbe esserci almeno un IP (anche se in un ambiente CI potrebbe
        // non averne, quindi solo verifichiamo che non panic).
        println!("IP locali rilevati: {:?}", addrs);
    }

    #[test]
    fn test_hostname() {
        let h = hostname();
        assert!(!h.is_empty(), "hostname non dovrebbe essere vuoto");
        println!("Hostname: {h}");
    }

    #[test]
    fn test_mdns_hostname_valido() {
        let h = mdns_hostname();
        assert!(h.ends_with(".local."), "deve terminare con .local.: {h}");
        assert!(!h.starts_with('.'), "non deve iniziare con un punto: {h}");
        assert!(!h.contains(".."), "non deve contenere punti doppi: {h}");
        println!("Hostname mDNS: {h}");
    }
}
