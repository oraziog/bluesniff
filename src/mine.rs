//! Il MAC che l'utente ha dichiarato essere il suo ("sono io").
//!
//! Un file `is_me.txt`, una riga. Serve a una cosa sola, ma la rende
//! possibile: distinguere il telefono in tasca dall'apparecchio accanto sul
//! tavolo. Senza questo, "e' arrivato qualcosa" e "sono tornato a casa io"
//! sono la stessa frase, e bluesniff non puo' distinguerle: il RSSI di un
//! telefono in tasca e' indistinguibile da quello di un telefolo sul tavolo.
//!
//! **Un MAC alla volta, per scelta.** Il caso d'uso reale e' uno solo (il
//! telefono che porti con te), e tenere una lista aprirebbe il problema di
//! capire quale dei MAC sia "lui" quando ne hai due: l'utente finirebbe per
//! non scegliere nulla. Il file e' quindi sovrascritto a ogni `set`, e la
//! sostituzione e' dichiarata esplicitamente dalla dashboard ("cambia il
//! dispositivo personale") perche' un click non deve sembrare innocuo.
//!
//! Non lo usiamo per silenziare le notifiche: `alerts.rs` continua a
//! notificare tutto cio' che e' in `bt_known.txt`. Un "sono io" silenziato
//! sarebbe una sorpresa (la notifica arriva, smette, e l'utente non sa
//! perché); ignorare il proprio telefono e' invece una scelta esplicita,
//! possibile dalla stessa scheda.

use std::path::{Path, PathBuf};

/// Percorso di `is_me.txt`, con `BLUESNIFF_BT_ISME` come override per i test.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("BLUESNIFF_BT_ISME") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    crate::logging::exe_dir().join("is_me.txt")
}

/// Il MAC dichiarato, normalizzato, o `None` se nessuno l'ha impostato.
///
/// Se il file contiene piu' righe (l'utente ne ha scritte due a mano)
/// prendiamo la prima valida e basta: e' comunque l'unico caso in cui il
/// dato e' ambiguo, e scegliere "l'ultima riga" significherebbe che
/// l'ordine di due righe scritte a mano decide quale telefono e' tuo.
pub fn get(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mac = crate::fsx::normalize_mac(trimmed);
        if !mac.is_empty() {
            return Some(mac);
        }
    }
    None
}

/// Imposta il MAC personale, sostituendo il precedente.
///
/// Il file tiene **un solo MAC**: quindi `set` non aggiunge una riga, toglie
/// quella che c'era (se c'era) e scrive la nuova. I commenti e le righe vuote
/// sopravvivono, e se il file aveva piu' righe-MAC scritte a mano ne resta
/// una — coerente con `get`, che legge la prima, e col check del doctor che
/// segnala il file come ambiguo.
pub fn set(path: &Path, mac: &str) -> std::io::Result<()> {
    let want = crate::fsx::normalize_mac(mac);
    if want.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "MAC non valido",
        ));
    }
    let old = std::fs::read_to_string(path).unwrap_or_default();
    let eol = crate::fsx::detect_eol(&old);
    let mut written = false;
    let mut out = String::with_capacity(old.len() + want.len() + eol.len());
    for line in old.lines() {
        let trimmed = line.trim();
        let is_mac_row = !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !crate::fsx::normalize_mac(trimmed).is_empty();
        if is_mac_row {
            if written {
                // Seconda (o terza...) riga-MAC: scartata. Il file e' "un
                // MAC alla volta" e tenerle tutte significherebbe che
                // `get` e quello che l'utente vede nella UI non coincidono.
                continue;
            }
            out.push_str(&want);
            written = true;
        } else {
            out.push_str(line);
        }
        out.push_str(eol);
    }
    if !written {
        out.push_str(&want);
        out.push_str(eol);
    }
    crate::fsx::write_atomic(path, &out)
}

/// Toglie l'impostazione. True se c'era qualcosa da togliere.
pub fn clear(path: &Path) -> std::io::Result<bool> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(false);
    };
    let eol = crate::fsx::detect_eol(&text);
    let mut out = String::with_capacity(text.len());
    let mut removed = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !removed
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !crate::fsx::normalize_mac(trimmed).is_empty()
        {
            removed = true;
            continue;
        }
        out.push_str(line);
        out.push_str(eol);
    }
    if removed {
        crate::fsx::write_atomic(path, &out)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bluesniff-mine-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("is_me.txt")
    }

    #[test]
    fn set_poi_get() {
        let p = tmp_path("base");
        assert_eq!(get(&p), None, "assenza iniziale");
        set(&p, "aa:bb:cc:dd:ee:01").unwrap();
        assert_eq!(get(&p).as_deref(), Some("AA:BB:CC:DD:EE:01"));
    }

    #[test]
    fn set_rifiuta_un_mac_non_valido() {
        let p = tmp_path("invalido");
        let err = set(&p, "non-un-mac").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!p.exists(), "il file non doveva essere creato");
    }

    #[test]
    fn set_sostituisce_il_mac_precedente_e_terga_i_commenti() {
        let p = tmp_path("sostituisci");
        std::fs::write(&p, "# il mio telefono\nAA:BB:CC:DD:EE:01\n").unwrap();
        set(&p, "AA:BB:CC:DD:EE:02").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.contains("AA:BB:CC:DD:EE:01"),
            "vecchio MAC rimasto: {text}"
        );
        assert!(text.contains("AA:BB:CC:DD:EE:02"), "nuovo assente: {text}");
        assert!(text.contains("# il mio telefono"), "commento perso: {text}");
    }

    #[test]
    fn set_sullo_stesso_mac_non_aggiunge_righe() {
        let p = tmp_path("idem");
        set(&p, "AA:BB:CC:DD:EE:01").unwrap();
        set(&p, "aa-bb-cc-dd-ee-01").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.matches("AA:BB:CC:DD:EE:01").count(), 1, "{text}");
    }

    #[test]
    fn set_collapse_una_riga_mac_scitta_a_mano() {
        // L'utente ha due righe-MAC nel file: dopo un set deve restarne una,
        // altrimenti `get` (prima riga) e la UI (ultimo set) direbbero cose
        // diverse.
        let p = tmp_path("due-righe");
        std::fs::write(&p, "AA:BB:CC:DD:EE:01\n# nota\nAA:BB:CC:DD:EE:09\n").unwrap();
        set(&p, "AA:BB:CC:DD:EE:02").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("AA:BB:CC:DD:EE:01"), "{text}");
        assert!(!text.contains("AA:BB:CC:DD:EE:09"), "{text}");
        assert!(text.contains("# nota"), "{text}");
        assert_eq!(get(&p).as_deref(), Some("AA:BB:CC:DD:EE:02"), "{text}");
    }

    #[test]
    fn get_ignora_commenti_e_righe_vuote() {
        let p = tmp_path("commenti");
        std::fs::write(&p, "# nota\n\nAA:BB:CC:DD:EE:07\n").unwrap();
        assert_eq!(get(&p).as_deref(), Some("AA:BB:CC:DD:EE:07"));
    }

    #[test]
    fn get_usa_la_prima_riga_valida() {
        // L'utente ha scritto due righe a mano: prendiamo la prima e non
        // decidiamo noi quale sia "lui" in base all'ordine di scrittura.
        let p = tmp_path("due");
        std::fs::write(&p, "AA:BB:CC:DD:EE:01\nAA:BB:CC:DD:EE:02\n").unwrap();
        assert_eq!(get(&p).as_deref(), Some("AA:BB:CC:DD:EE:01"));
    }

    #[test]
    fn get_ignora_le_righe_malformate_invece_di_fallire() {
        let p = tmp_path("malformed");
        std::fs::write(&p, "spazzatura\nAA:BB:CC:DD:EE:01\n").unwrap();
        assert_eq!(get(&p).as_deref(), Some("AA:BB:CC:DD:EE:01"));
    }

    #[test]
    fn clear_rimuove_il_mac_e_tiene_i_commenti() {
        let p = tmp_path("clear");
        std::fs::write(&p, "# mio\nAA:BB:CC:DD:EE:01\n").unwrap();
        assert!(clear(&p).unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("AA:BB"), "{text}");
        assert!(text.contains("# mio"), "{text}");
        assert_eq!(get(&p), None);
    }

    #[test]
    fn clear_è_no_op_se_non_cè_era_nulla() {
        let p = tmp_path("noop");
        assert!(!clear(&p).unwrap());
        assert!(!p.exists());
        std::fs::write(&p, "# solo commenti\n").unwrap();
        assert!(!clear(&p).unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "# solo commenti\n");
    }

    #[test]
    fn set_preserva_il_crlf() {
        let p = tmp_path("crlf");
        std::fs::write(&p, "# uno\r\n").unwrap();
        set(&p, "AA:BB:CC:DD:EE:01").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("# uno\r\nAA:BB:CC:DD:EE:01"), "{text:?}");
    }

    #[test]
    fn path_rispetta_la_variabile_d_ambiente() {
        let p = tmp_path("env");
        let prev = std::env::var("BLUESNIFF_BT_ISME").ok();
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("BLUESNIFF_BT_ISME", &p);
        let got = path();
        match prev {
            Some(v) => std::env::set_var("BLUESNIFF_BT_ISME", v),
            None => std::env::remove_var("BLUESNIFF_BT_ISME"),
        }
        assert_eq!(got, p);
    }
}
