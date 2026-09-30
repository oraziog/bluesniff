//! Lista nera dei dispositivi che l'utente ha deciso di non vedere.
//!
//! Un file `ignore.txt`, un MAC per riga, `#` per i commenti. Niente nome e
//! niente persona: l'ignore e' un dato binario ("questo non lo voglio piu'").
//! Tenere il file separato da `bt_known.txt` serve a due desideri che
//! l'utente ha gia' espresso separatamente: "voglio le notifiche di questo"
//! e "non voglio vederlo in tabella". Un dispositivo puo' essere seguito *e*
//! ignorato, e in quel caso le notifiche continuano.
//!
//! L'editing e' preservante come in `known.rs`: aggiungiamo in fondo, e per
//! rimuovere ricostruiamo il file riga per riga lasciandoti commenti, righe
//! vuote e ordine scelti a mano.
//!
//! **L'ignore e' per MAC, non per fingerprint.** E' la scelta piu' importante
//! del modulo e ha un costo noto: un AirTag (o un telefono) che cambia MAC
//! ogni 15 minuti dovrebbe essere ignorato piu' volte. L'alternativa scartata
//! e' l'ignore per fingerprint, che inseguirebbe il dispositivo ovunque:
//! pero' il fingerprint e' una nostra etichetta interna, non qualcosa che
//! l'utente vede o puo' controllare, e un errore di collisione li nasconderebbe
//! per sempre senza che lui possa accorgersene. Un MAC esatto e' almeno
//! reversibile e leggibile.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Percorso di `ignore.txt`.
///
/// Come `known::path()`, accanto all'eseguibile, con
/// `BLUESNIFF_BT_IGNORE` come override per i test: senza, i test scriverebbero
/// nella cartella dell'exe vero.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("BLUESNIFF_BT_IGNORE") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    crate::logging::exe_dir().join("ignore.txt")
}

/// Righe del file che non sono un MAC: commenti, righe vuote, intestazione.
///
/// Una riga che non e' un MAC non e' un errore da far fallire: il file e' roba
/// dell'utente e puo' contenere note. Ignorarle e' il comportamento che gli
/// permette di scriverci dentro, e la alternativa (fallire) gli impedirebbe di
/// aprire il file per capire cosa sia successo.
fn is_data_line(trimmed: &str) -> bool {
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

/// MAC ignorati, normalizzati e deduplicati.
///
/// Un file non esistente non e' un errore: vuol dire che nessuno ha ancora
/// ignorato niente. Non creiamo il file per il solo fatto di averlo letto, per
/// non lasciare spazzatura accanto all'eseguibile.
pub fn load(path: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines() {
        let first = line.trim().split(';').next().unwrap_or("");
        let mac = crate::fsx::normalize_mac(first);
        if !mac.is_empty() && seen.insert(mac.clone()) {
            out.push(mac);
        }
    }
    out
}

/// Come `load`, ma come insieme: e' quello che usa il rendering della tabella,
/// dove la domanda e' "questo MAC e' nella lista?", non "quanti sono".
pub fn load_set(path: &Path) -> HashSet<String> {
    load(path).into_iter().collect()
}

/// True se il MAC e' gia' ignorato (case-insensitive, formato indifferente).
pub fn is_ignored(path: &Path, mac: &str) -> bool {
    let want = crate::fsx::normalize_mac(mac);
    if want.is_empty() {
        return false;
    }
    load_set(path).contains(&want)
}

/// Aggiunge un MAC alla lista nera. No-op se c'era gia'.
///
/// La semantica e' "assicurati che sia ignorato", non "registra un evento di
/// ignore": un doppio click o due schede aperte non devono creare righe
/// duplicate, e un file con duplicati che l'utente ha scritto a mano non deve
/// crescere a ogni avvio della dashboard.
pub fn ignore(path: &Path, mac: &str) -> std::io::Result<()> {
    let mac = crate::fsx::normalize_mac(mac);
    if mac.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "MAC non valido",
        ));
    }
    if is_ignored(path, &mac) {
        return Ok(());
    }
    use std::io::Write;
    let existed = path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if !existed {
        // Commento di intestazione solo se il file e' nato qui: se esisteva
        // gia', non mettiamo mano alle sue prime righe.
        file.write_all(b"# MAC ignorati: una riga per dispositivo, # per commenti\n")?;
    }
    file.write_all(format!("{mac}\n").as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Rimuove il MAC dalla lista. True se qualcosa e' stato rimosso.
///
/// Un MAC non valido e' un `Err`, non un no-op: se l'utente (o uno script)
/// manda "spazzatura", dirgli "fatto" sarebbe una risposta falsa. Lo stesso
/// vale in `known::unfollow`.
///
/// Se invece il MAC e' valido ma assente, non riscriviamo il file: una
/// riscrittura a vuoto durante un file che l'utente sta editando perderebbe la
/// sua modifica.
pub fn unignore(path: &Path, mac: &str) -> std::io::Result<bool> {
    let want = crate::fsx::normalize_mac(mac);
    if want.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "MAC non valido",
        ));
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(false);
    };
    let eol = crate::fsx::detect_eol(&text);
    let mut out = String::with_capacity(text.len());
    let mut removed = false;
    for line in text.lines() {
        if !removed && is_data_line(line.trim()) {
            let first = line.trim().split(';').next().unwrap_or("");
            if crate::fsx::normalize_mac(first) == want {
                removed = true;
                continue;
            }
        }
        out.push_str(line);
        out.push_str(eol);
    }
    if removed {
        crate::fsx::write_atomic(path, &out)?;
    }
    Ok(removed)
}

/// Svuota la lista degli ignorati, restituendo quanti ne aveva.
///
/// I commenti e l'intestazione restano: `--unignore-all` significa "non
/// ricordare piu' nessun dispositivo", non "cancella il file". Un utente che
/// aveva scritto "# AirTag del vicino" nel file si ritroverebbe quel file
/// vuoto e si chiederebbe cosa sia successo. Il file non viene cancellato per
///che' `doctor` lo segnala come mancante al riavvio, e l'utente ricreerebbe a
/// mano quello che avevamo gia' scritto.
///
/// L'alternativa scartata (truncate a zero byte) e' piu' semplice ma tratta
/// il file come se fosse di bluesniff, e non e' vero.
pub fn unignore_all(path: &Path) -> std::io::Result<usize> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(0);
    };
    let count = load(path).len();
    let eol = crate::fsx::detect_eol(&text);
    let mut out = String::new();
    for line in text.lines() {
        if !is_data_line(line.trim()) {
            out.push_str(line);
            out.push_str(eol);
        }
    }
    if count > 0 {
        crate::fsx::write_atomic(path, &out)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bluesniff-ignore-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("ignore.txt")
    }

    #[test]
    fn ignore_aggiunge_e_preserva_il_resto() {
        let p = tmp_path("ignore");
        std::fs::write(&p, "# nota importante\nAA:BB:CC:DD:EE:01\n").unwrap();
        ignore(&p, "EC:ED:73:65:AC:45").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.starts_with("# nota importante"),
            "commento perso: {text}"
        );
        assert!(text.contains("AA:BB:CC:DD:EE:01\n"), "riga persa: {text}");
        assert!(
            text.contains("EC:ED:73:65:AC:45\n"),
            "riga nuova assente: {text}"
        );
    }

    #[test]
    fn ignore_crea_il_file_con_intestazione() {
        let p = tmp_path("nuovo");
        ignore(&p, "aa:bb:cc:dd:ee:01").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("# MAC ignorati"), "senza header: {text}");
        // Scriviamo normalizzato, anche se l'utente ha scritto in minuscolo.
        assert!(
            text.contains("AA:BB:CC:DD:EE:01"),
            "non normalizzato: {text}"
        );
    }

    #[test]
    fn ignore_non_duplica() {
        let p = tmp_path("idem");
        ignore(&p, "AA:BB:CC:DD:EE:01").unwrap();
        ignore(&p, "AA:BB:CC:DD:EE:01").unwrap();
        ignore(&p, "aa-bb-cc-dd-ee-01").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.matches("AA:BB:CC:DD:EE:01").count(), 1, "{text}");
    }

    #[test]
    fn ignore_rifiuta_un_mac_non_valido() {
        let p = tmp_path("invalido");
        let err = ignore(&p, "non-e-un-mac").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!p.exists(), "il file non doveva essere creato");
    }

    #[test]
    fn unignore_rimuove_solo_quella_riga() {
        let p = tmp_path("unignore");
        std::fs::write(
            &p,
            "# AirTag del vicino\nAA:BB:CC:DD:EE:01\n\nAA:BB:CC:DD:EE:02\n# coda\n",
        )
        .unwrap();
        assert!(unignore(&p, "AA:BB:CC:DD:EE:01").unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("AA:BB:CC:DD:EE:01"), "{text}");
        assert!(text.contains("AA:BB:CC:DD:EE:02"), "{text}");
        assert!(text.contains("# AirTag del vicino"), "{text}");
        assert!(text.contains("# coda"), "{text}");
        assert!(
            text.contains("\n\nAA:BB:CC:DD:EE:02"),
            "riga vuota persa: {text:?}"
        );
    }

    #[test]
    fn unignore_di_mac_assente_non_riscrive_il_file() {
        let p = tmp_path("noop");
        let orig = "# c\nAA:BB:CC:DD:EE:01\n";
        std::fs::write(&p, orig).unwrap();
        assert!(!unignore(&p, "FF:FF:FF:FF:FF:FF").unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), orig);
    }

    #[test]
    fn unignore_di_mac_assente_su_file_inesistente() {
        let p = tmp_path("inesistente");
        assert!(!unignore(&p, "AA:BB:CC:DD:EE:01").unwrap());
        assert!(!p.exists(), "non deve creare il file");
    }

    #[test]
    fn unignore_rifiuta_un_mac_non_valido() {
        // No-op silenzioso sarebbe una risposta falsa: l'utente ha scritto
        // male e noi gli diremmo che è andata bene.
        let p = tmp_path("invalido2");
        let err = unignore(&p, "non-un-mac").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn is_ignored_ignora_case_e_formato() {
        let p = tmp_path("is");
        std::fs::write(&p, "aa-bb-cc-dd-ee-01\n").unwrap();
        assert!(is_ignored(&p, "AA:BB:CC:DD:EE:01"));
        assert!(is_ignored(&p, "AABBCCDDEE01"));
        assert!(!is_ignored(&p, "AA:BB:CC:DD:EE:02"));
        assert!(!is_ignored(&p, "spazzatura"));
    }

    #[test]
    fn load_ignora_le_righe_malformate_senza_fallire() {
        let p = tmp_path("malformed");
        std::fs::write(
            &p,
            "# header\n\nriga_invalida\nAA:BB:CC:DD:EE:01\nquasi-un-mac\n",
        )
        .unwrap();
        let got = load(&p);
        assert_eq!(got, vec!["AA:BB:CC:DD:EE:01".to_string()], "{got:?}");
    }

    #[test]
    fn load_deduplica_i_duplicati_scritti_a_mano() {
        let p = tmp_path("dup");
        std::fs::write(
            &p,
            "AA:BB:CC:DD:EE:01\naa:bb:cc:dd:ee:01\nAABBCCDDEE01\nAA:BB:CC:DD:EE:02\n",
        )
        .unwrap();
        assert_eq!(load(&p).len(), 2, "duplicati non compattati");
    }

    #[test]
    fn load_su_file_inesistente_resta_vuoto() {
        let p = tmp_path("vuoto");
        assert!(load(&p).is_empty());
        assert!(!p.exists(), "la lettura non deve creare il file");
    }

    #[test]
    fn unignore_all_svuota_i_mac_e_tiene_i_commenti() {
        let p = tmp_path("all");
        std::fs::write(
            &p,
            "# MAC ignorati\n# AirTag del vicino\nAA:BB:CC:DD:EE:01\nAA:BB:CC:DD:EE:02\n",
        )
        .unwrap();
        assert_eq!(unignore_all(&p).unwrap(), 2);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("AA:BB"), "MAC rimasti: {text}");
        assert!(
            text.contains("# AirTag del vicino"),
            "commento perso: {text}"
        );
        assert!(
            text.contains("# MAC ignorati"),
            "intestazione persa: {text}"
        );
    }

    #[test]
    fn unignore_all_su_lista_vuota_non_riscrive() {
        let p = tmp_path("vuoto2");
        let orig = "# solo commenti\n";
        std::fs::write(&p, orig).unwrap();
        assert_eq!(unignore_all(&p).unwrap(), 0);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), orig);
    }

    #[test]
    fn ciclo_ignore_unignore_ritorna_all_originale() {
        let p = tmp_path("ciclo");
        let orig = "# nota\nAA:BB:CC:DD:EE:01\n\n";
        std::fs::write(&p, orig).unwrap();
        ignore(&p, "AA:BB:CC:DD:EE:02").unwrap();
        assert!(unignore(&p, "AA:BB:CC:DD:EE:02").unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), orig);
    }

    #[test]
    fn unignore_preserva_il_crlf() {
        let p = tmp_path("crlf");
        std::fs::write(&p, "# uno\r\nAA:BB:CC:DD:EE:01\r\nAA:BB:CC:DD:EE:02\r\n").unwrap();
        assert!(unignore(&p, "AA:BB:CC:DD:EE:01").unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("AA:BB:CC:DD:EE:02\r\n"), "{text:?}");
    }

    #[test]
    fn path_rispetta_la_variabile_d_ambiente() {
        let p = tmp_path("env");
        let prev = std::env::var("BLUESNIFF_BT_IGNORE").ok();
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("BLUESNIFF_BT_IGNORE", &p);
        let got = path();
        match prev {
            Some(v) => std::env::set_var("BLUESNIFF_BT_IGNORE", v),
            None => std::env::remove_var("BLUESNIFF_BT_IGNORE"),
        }
        assert_eq!(got, p);
    }
}
