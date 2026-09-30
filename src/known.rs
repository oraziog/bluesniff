//! Editing preservante di `bt_known.txt` (follow/unfollow dalla dashboard).
//!
//! Il file e' `BTMAC;Nome;Persona` per riga, `#` per i commenti. L'editing qui
//! **non normalizza e non riscrive** il file: aggiungiamo o rimuoviamo solo la
//! riga del MAC che ci interessa, lasciando intatti commenti, righe vuote,
//! ordine e le persone gia' assegnate.
//!
//! Il motivo e' che il file e' roba dell'utente: puo' averlo aperto con
//! Notepad e averci messo note, righe commentate, ordine scelto per lui. Un
//! "salva tutto riscrivendo" di quelle righe sarebbe una perdita di dati
//! silenziosa, il tipo di bug che l'utente scopre tre settimane dopo, quando
//! non si ricorda piu' cosa aveva scritto.
//!
//! Il percorso e' accanto all'eseguibile, come tutto il resto della
//! configurazione: `logging::exe_dir().join("bt_known.txt")`.

use std::path::{Path, PathBuf};

use crate::btclassic::KnownBt;

/// Percorso di `bt_known.txt`.
///
/// Di default accanto all'eseguibile, dove l'utente lo cerca. La variabile
/// d'ambiente `BLUESNIFF_BT_KNOWN` lo sovrascrive: serve ai test, che altrimenti
/// scriverebbero (e cancellerebbero) il file vero nella cartella dell'exe.
/// E' lo stesso meccanismo di `BLUESNIFF_SHARE_CONFIG` in `share.rs`.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("BLUESNIFF_BT_KNOWN") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    crate::logging::exe_dir().join("bt_known.txt")
}

/// True se il MAC e' gia' nella lista (case-insensitive, ignora il formato:
/// `aa-bb-cc-dd-ee-01` e `AA:BB:CC:DD:EE:01` sono lo stesso indirizzo).
pub fn is_followed(path: &Path, mac: &str) -> bool {
    let want = crate::fsx::normalize_mac(mac);
    if want.is_empty() {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("BTMAC") {
            continue;
        }
        let first = line.split(';').next().unwrap_or("").trim();
        if crate::fsx::normalize_mac(first) == want {
            return true;
        }
    }
    false
}

/// Aggiunge un MAC come `MAC;Nome;` con la colonna Persona vuota.
///
/// La Persona la compila l'utente aprendo il file: e' un'informazione che
/// solo lui ha ("di chi e' questo telefono"), e indovinarla sarebbe falso.
/// Non fa nulla se il MAC e' gia' presente: cosi' un doppio click, o due
/// schede aperte, non creano righe duplicate.
pub fn follow(path: &Path, mac: &str, name: &str) -> std::io::Result<()> {
    let mac = crate::fsx::normalize_mac(mac);
    if mac.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "MAC non valido",
        ));
    }
    if is_followed(path, &mac) {
        return Ok(());
    }
    // Il nome non puo' contenere ';' (separatore del file) ne' andare a capo,
    // altrimenti una riga sola diventa due righe: la seconda verrebbe letta
    // come un dispositivo inesistente e ogni reload la perderebbe.
    let clean_name = name.replace(';', ",").replace(['\n', '\r'], " ");
    let clean_name = clean_name.trim();
    let line = format!("{mac};{clean_name};\n");

    use std::io::Write;
    let existed = path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if !existed {
        // File creato da noi: mettiamo l'intestazione, cosi' l'utente che lo
        // apre sa cosa scrivere nelle tre colonne.
        file.write_all(b"# BTMAC;Nome;Persona  (fill in the Persona column)\n")?;
    }
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Rimuove la riga del MAC. Restituisce true se qualcosa e' stato rimosso.
///
/// Riscriviamo il file solo se la riga c'era davvero: se il MAC non e' nella
/// lista, riscrivere sarebbe una scrittura a vuoto che, se il file intanto
/// cambiava, perderebbe la modifica. Tutto il resto (commenti, righe vuote,
/// ordine) viene preservato riga per riga.
pub fn unfollow(path: &Path, mac: &str) -> std::io::Result<bool> {
    let want = crate::fsx::normalize_mac(mac);
    if want.is_empty() {
        // Non un no-op: se l'utente ha sbagliato a digitare il MAC, dirgli
        // "fatto" lo lascerebbe convinto di aver tolto un dispositivo che
        // invece continua a essere seguito e a notificare.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "MAC non valido",
        ));
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(false);
    };
    // Terminatore di riga del file originale: su Windows quasi sempre CRLF,
    // e su un file salvato da Notepad cambiare a LF si vede (il file risulta
    // modificato per intero). Riusiamo quello che c'era gia'.
    let eol = crate::fsx::detect_eol(&text);
    let mut out = String::with_capacity(text.len());
    let mut removed = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !removed && !trimmed.is_empty() && !trimmed.starts_with('#') {
            let first = trimmed.split(';').next().unwrap_or("").trim();
            if crate::fsx::normalize_mac(first) == want {
                removed = true;
                // Salta questa riga e passa alla successiva: e' l'unica che
                // tocchiamo, tutto il resto viene ricopiato alla lettera.
                continue;
            }
        }
        out.push_str(line);
        out.push_str(eol);
    }
    if removed {
        // Scrittura atomica (temp + rename): se il processo morisse a meta',
        // il file resterebbe troncato e l'utente perderebbe l'elenco dei
        // dispositivi seguiti. Vedi `fsx::write_atomic`.
        crate::fsx::write_atomic(path, &out)?;
    }
    Ok(removed)
}

/// Lista dei dispositivi seguiti, per `GET /api/known`.
pub fn list(path: &Path) -> Vec<KnownBt> {
    crate::btclassic::load_bt_known(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le variabili d'ambiente sono globali al processo: i test che le
    /// toccano vanno serializzati fra loro.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Percorso in una directory unica per test, cosi' i test non si pestano
    /// i piedi e un file lasciato da un test precedente non invalida un altro.
    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bluesniff-known-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("bt_known.txt")
    }

    #[test]
    fn follow_aggiunge_e_preserva_il_resto() {
        let p = tmp_path("follow");
        std::fs::write(&p, "# commento importante\nAA:BB:CC:DD:EE:01;Uno;Mario\n").unwrap();
        follow(&p, "EC:ED:73:65:AC:45", "Moto G73").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.starts_with("# commento importante"),
            "commento perso:\n{text}"
        );
        assert!(
            text.contains("AA:BB:CC:DD:EE:01;Uno;Mario"),
            "riga precedente persa:\n{text}"
        );
        assert!(
            text.contains("EC:ED:73:65:AC:45;Moto G73;"),
            "riga nuova assente:\n{text}"
        );
    }

    #[test]
    fn follow_crea_il_file_con_intestazione() {
        let p = tmp_path("nuovo");
        follow(&p, "AA:BB:CC:DD:EE:01", "Telefono").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("# BTMAC"), "senza header:\n{text}");
        assert!(text.contains("AA:BB:CC:DD:EE:01;Telefono;"));
    }

    #[test]
    fn follow_idempotente() {
        let p = tmp_path("idem");
        follow(&p, "AA:BB:CC:DD:EE:01", "X").unwrap();
        follow(&p, "AA:BB:CC:DD:EE:01", "X").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.matches("AA:BB:CC:DD:EE:01").count(), 1);
    }

    #[test]
    fn follow_rifiuta_un_mac_non_valido() {
        let p = tmp_path("invalido");
        let err = follow(&p, "non-e-un-mac", "X").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!p.exists(), "il file non doveva essere creato");
    }

    #[test]
    fn follow_sanifica_il_nome() {
        let p = tmp_path("sanitize");
        follow(&p, "AA:BB:CC:DD:EE:01", "Nome;con;separatori\nmultiriga").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        // Una sola riga di dati: senza ';' nel nome e senza andare a capo.
        let dati: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim().starts_with('#'))
            .collect();
        assert_eq!(dati.len(), 1, "riga multipla: {text}");
        assert_eq!(dati[0].matches(';').count(), 2, "separatori: {text:?}");
        assert!(!dati[0].contains('\r') && !dati[0].contains('\n'));
    }

    #[test]
    fn unfollow_rimuove_solo_quella_riga() {
        let p = tmp_path("unfollow");
        std::fs::write(
            &p,
            "# c1\nAA:BB:CC:DD:EE:01;Uno;Mario\n\nAA:BB:CC:DD:EE:02;Due;Luigi\n# coda\n",
        )
        .unwrap();
        assert!(unfollow(&p, "AA:BB:CC:DD:EE:01").unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("AA:BB:CC:DD:EE:01"));
        assert!(text.contains("AA:BB:CC:DD:EE:02;Due;Luigi"));
        assert!(text.contains("# c1"));
        assert!(text.contains("# coda"));
        // L'originale aveva 5 righe (il vuoto sta dopo quella rimossa), quindi
        // ne restano 4: la riga vuota viene preservata, non collassata via.
        assert_eq!(text.lines().count(), 4, "righe: {text:?}");
        assert!(
            text.contains("\n\nAA:BB:CC:DD:EE:02"),
            "riga vuota persa: {text:?}"
        );
    }

    #[test]
    fn unfollow_rifiuta_un_mac_non_valido() {
        let p = tmp_path("invalido-unfollow");
        let err = unfollow(&p, "non-un-mac").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!p.exists(), "il file non doveva essere creato");
    }

    #[test]
    fn unfollow_di_mac_assente_non_riscrive_il_file() {
        let p = tmp_path("noop");
        let orig = "AA:BB:CC:DD:EE:01;Uno;Mario\n";
        std::fs::write(&p, orig).unwrap();
        assert!(!unfollow(&p, "FF:FF:FF:FF:FF:FF").unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), orig);
    }

    #[test]
    fn unfollow_tocca_una_riga_per_mac() {
        let p = tmp_path("doppioni");
        std::fs::write(
            &p,
            "AA:BB:CC:DD:EE:01;Uno;\nAA:BB:CC:DD:EE:01;Uno duplicato;\n",
        )
        .unwrap();
        assert!(unfollow(&p, "AA:BB:CC:DD:EE:01").unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        // Il file non era pulito: se ne rimuove solo la prima occurrence, per
        // non fare piu' scritture del necessario su un file che l'utente
        // potrebbe star editando in parallelo.
        assert_eq!(text.matches("AA:BB:CC:DD:EE:01").count(), 1, "{text}");
    }

    #[test]
    fn is_followed_ignora_case_e_formato() {
        let p = tmp_path("isfollowed");
        std::fs::write(&p, "aa-bb-cc-dd-ee-01;Uno;\n").unwrap();
        assert!(is_followed(&p, "AA:BB:CC:DD:EE:01"));
        assert!(is_followed(&p, "aa:bb:cc:dd:ee:01"));
        assert!(is_followed(&p, "AABBCCDDEE01"));
        assert!(!is_followed(&p, "AA:BB:CC:DD:EE:02"));
        assert!(!is_followed(&p, "spazzatura"));
    }

    #[test]
    fn ciclo_follow_unfollow_ritorna_all_originale() {
        let p = tmp_path("ciclo");
        let orig = "# nota\nAA:BB:CC:DD:EE:01;Uno;Mario\n\n";
        std::fs::write(&p, orig).unwrap();
        follow(&p, "AA:BB:CC:DD:EE:02", "Due").unwrap();
        assert!(unfollow(&p, "AA:BB:CC:DD:EE:02").unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), orig);
    }

    #[test]
    fn follow_preserva_file_con_bom_utf8_e_crlf() {
        // Notepad su Windows salva con BOM UTF-8 e CRLF. Se lo riscrivessimo
        // male, l'utente aprirebbe il file e troverbbe i commenti spostati o
        // righe unite: la BOM in testa finirebbe dentro un nome.
        let p = tmp_path("bom");
        let mut content: Vec<u8> = Vec::new();
        content.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        content.extend_from_slice(b"# commento\r\nAA:BB:CC:DD:EE:01;Uno;Mario\r\n");
        std::fs::write(&p, &content).unwrap();

        follow(&p, "EC:ED:73:65:AC:45", "Moto G73").unwrap();

        let after = std::fs::read(&p).unwrap();
        assert_eq!(&after[0..3], &[0xEF, 0xBB, 0xBF], "BOM perso");
        let text = String::from_utf8_lossy(&after);
        assert!(
            text.contains("AA:BB:CC:DD:EE:01;Uno;Mario\r\n"),
            "riga precedente alterata: {text:?}"
        );
        assert!(
            text.contains("EC:ED:73:65:AC:45;Moto G73;"),
            "riga nuova assente: {text:?}"
        );
    }

    #[test]
    fn unfollow_su_file_crlf_preserva_gli_altri_terminatori() {
        // Se riscrivessimo con \n su un file CRLF, l'utente che lo riapre
        // vedrebbe il file cambiato a vista. Preserviamo il terminatore che il
        // file sta gia' usando.
        let p = tmp_path("crlf");
        std::fs::write(
            &p,
            "# uno\r\nAA:BB:CC:DD:EE:01;Uno;\r\nAA:BB:CC:DD:EE:02;Due;\r\n",
        )
        .unwrap();
        assert!(unfollow(&p, "AA:BB:CC:DD:EE:01").unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("AA:BB:CC:DD:EE:02;Due;\r\n"), "{text:?}");
        assert!(!text.contains("AA:BB:CC:DD:EE:01"), "{text:?}");
    }

    #[test]
    fn unfollow_non_tocca_le_righe_con_mac_simili() {
        // Il confronto e' sempre su MAC normalizzati di 12 cifre: una riga
        // con 13 cifre non e' un MAC e non deve essere scambiata per quella che
        // stiamo eliminando (ne' il contrario).
        let p = tmp_path("substring");
        std::fs::write(&p, "AA:BB:CC:DD:EE:01;Uno;\nAA:BB:CC:DD:EE:010;Due;\n").unwrap();
        assert!(unfollow(&p, "AA:BB:CC:DD:EE:01").unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("AA:BB:CC:DD:EE:01;"), "{text:?}");
        assert!(text.contains("AA:BB:CC:DD:EE:010;Due;"), "{text:?}");
    }

    #[test]
    fn path_rispetta_la_variabile_d_ambiente() {
        // Meccanismo usato dai test di integrazione: senza questo, scriverebbero
        // (e cancellerebbero) il bt_known.txt vero nella cartella dell'exe.
        let p = tmp_path("env");
        let prev = std::env::var("BLUESNIFF_BT_KNOWN").ok();
        // SAFETY: i test girano in parallelo su thread diversi, e l'ambiente e'
        // condiviso. Serializziamo con il lock statico qui sotto.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("BLUESNIFF_BT_KNOWN", &p);
        let got = path();
        match prev {
            Some(v) => std::env::set_var("BLUESNIFF_BT_KNOWN", v),
            None => std::env::remove_var("BLUESNIFF_BT_KNOWN"),
        }
        assert_eq!(got, p);
    }

    #[test]
    fn list_legge_le_righe_vere() {
        let p = tmp_path("list");
        std::fs::write(
            &p,
            "# header\n\nAA:BB:CC:DD:EE:01;Uno;Mario\nriga_invalida\n",
        )
        .unwrap();
        let l = list(&p);
        assert_eq!(l.len(), 1, "righe lette: {}", l.len());
        assert_eq!(l[0].mac, "AA:BB:CC:DD:EE:01");
        assert_eq!(l[0].nome, "Uno");
        assert_eq!(l[0].persona, "Mario");
    }
}
