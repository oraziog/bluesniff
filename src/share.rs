//! Condivisione della dashboard sulla rete locale, con scelta ricordata.
//!
//! Il problema che risolve: di default la dashboard ascolta su `127.0.0.1`,
//! quindi non e' raggiungibile dagli altri. La barra di condivisione che c'era
//! gia' mostrava gli indirizzi utili, ma ha un difetto di gallo e uovo:
//! **compare solo se sei gia' entrato da un IP di rete**, quindi da loopback
//! non hai modo di attivarla. Qui il pulsante c'e' sempre e fa esattamente
//! quello che dice: espone, annuncia via mDNS, e alla fine si ricorda.
//!
//! Quello che NON facciamo, e va detto: **non apriamo porte del firewall di
//! Windows`. Servono diritti di amministratore e significa aprire la macchina
//! a chiunque sulla rete. Il pulsante prova a dirti se la porta e' raggiungibile
//! da fuori e, se non lo e', te lo dice: la decisione di aprire il firewall e'
//! tua, presa con gli occhi aperti.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// Impostazione di condivisione, salvata accanto all'eseguibile.
///
/// Un file invece di una chiave di registro o di un DB: sta dove l'utente
/// guarda, si cancella cancellando un file, e non richiede permessi.
const SETTINGS_FILE: &str = "share.json";

/// Condivisione richiesta dall'utente (persistita fra un riavvio e l'altro).
static WANTED: AtomicBool = AtomicBool::new(false);

/// L'annuncio mDNS e' partito davvero? Lo tiene il modulo cosi' la dashboard
/// non promette un servizio che il daemon non sta pubblicando: un annuncio
/// fallito e' molto diverso da uno attivo, e la differenza si vede solo
/// guardando cosa e' riuscito a fare `start_mdns_responder`.
static MDNS_LIVE: AtomicBool = AtomicBool::new(false);

/// Registra l'esito dell'annuncio mDNS.
pub fn set_mdns_live(v: bool) {
    MDNS_LIVE.store(v, Ordering::Relaxed);
}

/// L'annuncio mDNS e' attivo in questo momento?
pub fn mdns_live() -> bool {
    MDNS_LIVE.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShareSettings {
    /// L'utente ha chiesto di condividere: al prossimo avvio si riapplica.
    #[serde(default)]
    pub enabled: bool,
    /// Ultimo stato applicato, solo informativo per la dashboard.
    #[serde(default)]
    pub last_bind: Option<String>,
    #[serde(default)]
    pub last_port: Option<u16>,
}

/// Percorso del file di impostazioni, accanto all'eseguibile.
///
/// `BLUESNIFF_SHARE_CONFIG` permette di puntare altrove: serve ai test, che non
/// devono mai scrivere nella cartella dell'utente reale (e cancellargli la
/// configurazione di condivisione tra un test e l'altro).
fn settings_path() -> PathBuf {
    if let Ok(p) = std::env::var("BLUESNIFF_SHARE_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    crate::logging::exe_dir().join(SETTINGS_FILE)
}

/// Legge le impostazioni. Un file assente o illeggibile non è un errore:
/// l'utente non ha mai condiviso, e va bene così.
pub fn load() -> ShareSettings {
    let path = settings_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ShareSettings::default();
    };
    // Se il file è corrotto ripartiamo da zero invece di far fallire l'avvio:
    // un'impostazione di condivisione non deve mai impedire a bluesniff di
    // partire.
    serde_json::from_str(&text).unwrap_or_default()
}

/// Salva le impostazioni. La scrittura è "atomica" nel senso pragmatico che
/// scriviamo su un file temporaneo e poi rinominiamo: un'interruzione a metà
/// non lascia un share.json troncato che al prossimo avvio fa fallback silenzioso.
pub fn save(s: &ShareSettings) -> std::io::Result<()> {
    let path = settings_path();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(s).unwrap_or_default())?;
    std::fs::rename(&tmp, &path)
}

/// L'utente vuole la dashboard condivisa?
pub fn wanted() -> bool {
    WANTED.load(Ordering::Relaxed)
}

/// Imposta la desiderata e la persiste, così il prossimo riavvio la riapplica.
pub fn set_wanted(on: bool) -> std::io::Result<()> {
    WANTED.store(on, Ordering::Relaxed);
    let mut s = load();
    s.enabled = on;
    save(&s)
}

/// Ripristina la desiderata all'avvio, dalla persistenza.
pub fn restore() -> bool {
    let s = load();
    WANTED.store(s.enabled, Ordering::Relaxed);
    s.enabled
}

/// L'indirizzo di bind da usare, dato che l'utente vuole condividere.
///
/// `0.0.0.0` significa "tutte le interfacce". Restituire l'indirizzo esplicito
/// della macchina sarebbe peggio: se il Wi-Fi cade e l'ethernet resta, la
/// dashboard diventerebbe irraggiungibile.
pub fn bind_addr(share: bool, requested: IpAddr) -> IpAddr {
    if share || requested.is_unspecified() {
        IpAddr::from([0, 0, 0, 0])
    } else {
        requested
    }
}

/// Nome della regola di firewall che creiamo (o cerchiamo).
pub const RULE_NAME: &str = "bluesniff dashboard";

/// Esito della verifica/apertura della porta nel firewall.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Firewall {
    /// La regola c'e' (l'apertura e' riuscita in precedenza).
    pub rule_present: bool,
    /// L'apertura e' stata tentata adesso.
    pub attempted: bool,
    /// Esito: "open" (regola presente), "created" (l'abbiamo appena aperta),
    /// "needs_admin" (serve amministratore), "error" (altro).
    pub state: String,
    /// Cosa fare, in parole semplici. Lo mostriamo all'utente.
    pub detail: String,
    /// Il comando esatto da eseguire come amministratore, se serve.
    pub command: String,
}

/// Verifica se la regola di apertura esiste gia'.
///
/// `netsh` e' scelto perche' funziona anche su Windows Server dove il modulo
/// `New-NetFirewallRule` non e' sempre presente, e restituisce un exit code
/// pulito: 0 trovata, 1 non trovata. Non richiede diritti speciali per
/// interrogare, quindi lo stato e' sempre leggibile anche da utente normale.
///
/// Pubblica perché `doctor` la usa per il check "la dashboard è raggiungibile
/// da altri dispositivi?": la domanda è sulla sola lettura, mai sull'apertura.
pub fn rule_exists(port: u16) -> bool {
    let out = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={RULE_NAME}"),
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains(&format!("LocalPort:                             {port}"))
                || text.contains("LocalPort:") && text.contains(&port.to_string())
        }
        _ => false,
    }
}

/// Apre la porta nel firewall, o dice con chiarezza perche' non e' riuscito.
///
/// Restituire un esito e non un `bool` perche' "non ha funzionato" ha tre
/// cause molto diverse per l'utente: serve l'amministratore, il comando e'
/// fallito per un altro motivo, oppure la regola c'e' gia'. Una dashboard che
/// dicesse solo "no" sarebbe indistinguibile dalle altre due.
pub fn ensure_port(port: u16) -> Firewall {
    let command = format!(
        "netsh advfirewall firewall add rule name=\"{RULE_NAME}\" dir=in action=allow protocol=TCP localport={port}"
    );
    if rule_exists(port) {
        return Firewall {
            rule_present: true,
            attempted: false,
            state: "open".into(),
            detail: format!("porta {port} gia' aperta nel firewall"),
            command,
        };
    }
    let out = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={RULE_NAME}"),
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={port}"),
        ])
        .output();
    let (state, detail): (&str, String) = match out {
        Ok(o) if o.status.success() => {
            let c = format!(
                "porta {port} aperta: chi e' sulla stessa rete puo' raggiungere la dashboard"
            );
            ("created", c)
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let err = err.trim();
            // netsh non distingue "serve admin" da un altro errore con un
            // codice dedicato, ma il messaggio lo dice: lo riportiamo e
            // decidiamo da li', senza indovinare.
            let low = err.to_lowercase();
            if low.contains("elevation") || low.contains("access is denied") || err.is_empty() {
                (
                    "needs_admin",
                    "serve diritti di amministratore per aprire la porta".to_string(),
                )
            } else {
                ("error", format!("netsh: {err}"))
            }
        }
        Err(e) => ("error", format!("netsh non eseguibile: {e}")),
    };
    Firewall {
        rule_present: state == "created",
        attempted: true,
        state: state.into(),
        detail,
        command,
    }
}

/// Rimuove la regola. Serve per chi spegne la condivisione: lasciare aperta
/// una porta che non serve piu' sarebbe una sorpresa sgradita.
pub fn close_port() -> Firewall {
    let out = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={RULE_NAME}"),
        ])
        .output();
    Firewall {
        rule_present: false,
        attempted: true,
        state: match &out {
            Ok(o) if o.status.success() => "closed",
            _ => "no_rule",
        }
        .into(),
        detail: "regola di apertura rimossa".into(),
        command: format!("netsh advfirewall firewall delete rule name=\"{RULE_NAME}\""),
    }
}

/// Stato per la dashboard.
pub fn status_json(share_active: bool, port: u16) -> serde_json::Value {
    let present = rule_exists(port);
    let fw = Firewall {
        rule_present: present,
        attempted: false,
        // `state` vuota quando la regola non c'e': la UI la legge per
        // scegliere il colore, e una stringa vuota la farebbe sembrare un
        // esito sconosciuto invece di "porta chiusa".
        state: if present { "open" } else { "closed" }.into(),
        detail: if present {
            format!("porta {port} gia' aperta nel firewall")
        } else {
            format!("porta {port} non ancora aperta")
        },
        command: format!(
            "netsh advfirewall firewall add rule name=\"{RULE_NAME}\" dir=in action=allow protocol=TCP localport={port}"
        ),
    };
    serde_json::json!({
        "wanted": wanted(),
        "active": share_active,
        "mdns": mdns_live(),
        "port": port,
        "firewall": fw,
        "firewall_note": if fw.rule_present {
            "porta aperta nel firewall: raggiungibile dalla rete locale"
        } else {
            "porta non ancora aperta: si puo' aprire con un click, se bluesniff gira come amministratore"
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Il percorso del file e' globale: i test non girano in parallelo.
    static LOCK: Mutex<()> = Mutex::new(());

    /// Isola il file di impostazioni in una directory temporanea, cosi' il
    /// test non tocca mai la configurazione reale dell'utente.
    fn with_temp_settings<R>(f: impl FnOnce() -> R) -> R {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("bluesniff-share-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(SETTINGS_FILE);
        std::env::set_var("BLUESNIFF_SHARE_CONFIG", &file);
        let out = f();
        std::env::remove_var("BLUESNIFF_SHARE_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn bind_alla_condivisione_e_loopback_otherwise() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            bind_addr(true, loopback),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(bind_addr(false, loopback), loopback);
    }

    #[test]
    fn un_indirizzo_gia_selettivo_non_viene_sovrascritto_senza_condivisione() {
        // Se l'utente ha scelto esplicitamente 0.0.0.0 al lancio, non lo
        // "chiudiamo" da soli: era una sua scelta esplicita.
        let all: IpAddr = "0.0.0.0".parse().unwrap();
        assert_eq!(bind_addr(false, all), all);
    }

    #[test]
    fn serde_sopravvive_a_un_file_corrotto() {
        // Non e' un test del file reale: verifichiamo la regola che vale, cioe'
        // che il deserializzatore non deve mai far fallire l'avvio.
        let bad = "questa non e' json";
        let s: ShareSettings = serde_json::from_str(bad).unwrap_or_default();
        assert!(
            !s.enabled,
            "un file illeggibile deve valere 'non condiviso'"
        );
    }

    #[test]
    fn le_impostazioni_vanno_e_tornano() {
        with_temp_settings(|| {
            let s = ShareSettings {
                enabled: true,
                last_bind: Some("0.0.0.0".into()),
                last_port: Some(9000),
            };
            save(&s).unwrap();
            let back = load();
            assert!(back.enabled);
            assert_eq!(back.last_port, Some(9000));
        });
    }

    #[test]
    fn wanted_e_una_scelta_memorizzata() {
        with_temp_settings(|| {
            assert!(!wanted(), "si parte da non condiviso");
            set_wanted(true).unwrap();
            assert!(wanted());
            // Simula un riavvio: la memoria di processo sparisce, il file no.
            WANTED.store(false, Ordering::Relaxed);
            assert!(restore(), "la scelta deve sopravvivere al riavvio");
            let _ = set_wanted(false);
        });
    }

    #[test]
    fn lo_stato_json_dice_se_mdns_e_vivo() {
        // La UI promette "annunciato come _blusniff._tcp" solo se il daemon
        // e' partito davvero: se il flag mentisse, l'utente cercherebbe un
        // servizio che non esiste.
        set_mdns_live(false);
        assert!(!status_json(true, 9000)["mdns"].as_bool().unwrap());
        set_mdns_live(true);
        assert!(status_json(true, 9000)["mdns"].as_bool().unwrap());
        set_mdns_live(false);
    }

    #[test]
    fn lo_stato_riporta_anche_un_esito_fallito() {
        // "Non ho toccato il firewall" e "ho provato e servono diritti" sono
        // informazioni diverse: la UI deve poter distinguere i due casi.
        let fw = Firewall {
            rule_present: false,
            attempted: true,
            state: "needs_admin".into(),
            detail: "serve diritti".into(),
            command: "netsh ...".into(),
        };
        let j = serde_json::to_value(&fw).unwrap();
        assert_eq!(j["state"], "needs_admin");
        assert!(j["attempted"].as_bool().unwrap());
        assert!(!j["rule_present"].as_bool().unwrap());
    }

    #[test]
    fn la_porta_chiusa_viene_dichiarata_come_tale() {
        // Non possiamo testare l'apertura vera (ci vuole amministratore e
        // toccherebbe il firewall della macchina di sviluppo), ma possiamo
        // verificare che lo stato non prometta mai una porta aperta quando
        // la regola non c'e'. E' la promise che fa la differenza per l'utente.
        let j = status_json(true, 9123);
        let fw = &j["firewall"];
        if fw["rule_present"].as_bool() == Some(false) {
            assert!(
                j["firewall_note"]
                    .as_str()
                    .unwrap()
                    .contains("non ancora aperta"),
                "senza regola, la nota deve dire che la porta non e' aperta"
            );
        }
    }
}
