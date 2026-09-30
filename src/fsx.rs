//! Due helper di filesystem condivisi dai file di configurazione editabili a
//! mano (`bt_known.txt`, `ignore.txt`, `is_me.txt`).
//!
//! Stanno qui invece che in `known.rs` perche' quattro moduli ne hanno bisogno
//! (`known`, `ignore`, `mine` e la selezione della radio in `radio.rs`) e
//! nessuno e' il "proprietario" degli altri: duplicare `normalize_mac` in
//! quattro posti significa che un giorno una delle copie accettera un formato
//! di MAC che le altre rifiutano, e il bug si vedra' solo su uno dei file.

use std::path::Path;

/// Normalizza un MAC in `AA:BB:CC:DD:EE:FF` maiuscolo, o stringa vuota se non
/// e' un indirizzo.
///
/// La normalizzazione passa per i soli cifre esadecimali invece che per una
/// sostituzione di separatori: cosi' `aabbccddee01`, `aa-bb-cc-dd-ee-01` e
/// `AA:BB:CC:DD:EE:01` convergono allo stesso valore, e una riga che contiene
/// altro (per esempio un nome) non puo' spacciarsi per un indirizzo con la
/// lunghezza giusta per caso. Il formato non e' forzato quando si *legge* un
/// file scritto a mano, ma lo e' quando si *scrive*: cosi' il file resta
/// editabile e i MAC che aggiungiamo da soli sono tutti uguali.
pub fn normalize_mac(s: &str) -> String {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return String::new();
    }
    let up = hex.to_uppercase();
    (0..6)
        .map(|i| up[i * 2..i * 2 + 2].to_string())
        .collect::<Vec<_>>()
        .join(":")
}

/// Scrive `content` tramite file temporaneo + rename, non con `fs::write`.
///
/// `fs::write` apre il file in truncation e scrive: se il processo muore a
/// meta' (crash, batteria scarica, chiusura della finestra durante
/// l'operazione) il file resta troncato a meta', e per `bt_known.txt`/
/// `ignore.txt` questo significa perdere la lista dei dispositivi seguiti.
/// Il rename, su Windows come su Unix, sostituisce il file in modo che il
/// lettore vede sempre o il vecchio contenuto o il nuovo, mai uno stadio
/// intermedio.
///
/// Il costo e' una rimozione in piu' per scrittura, e i file in questione
/// hanno al massimo qualche centinaia di righe: trascurabile rispetto al
/// rischio che stiamo evitando.
pub fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    // Il nome del temporaneo include il processo: due bluesniff (o due test)
    // che riscrivessero lo stesso file non si pesterebbero il piede.
    let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, content)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Il rename ha fallito: il file originale e' intatto, ma il
            // temporaneo no'. Lo puliamo, cosi' non resta spazzatura accanto
            // al file che l'utente potrebbe aprire.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Sceglie il terminatore di riga del file esistente.
///
/// Su Windows quasi tutti i file salvati da Notepad hanno CRLF, e su un file
/// CRLF riscritto con LF l'utente che lo riapre vede il file modificato per
/// intero. Riusiamo quello che c'era gia'; su un file nuovo (o vuoto) `\n`,
/// che e' quello che produce il resto del progetto.
pub fn detect_eol(text: &str) -> &'static str {
    if text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accetta_i_formati_che_l_utente_scrive_a_mano() {
        for variante in [
            "AA:BB:CC:DD:EE:01",
            "aa:bb:cc:dd:ee:01",
            "aa-bb-cc-dd-ee-01",
            "AABBCCDDEE01",
            "AA BB CC DD EE 01",
            " aa:bb:cc:dd:ee:01 ",
        ] {
            assert_eq!(
                normalize_mac(variante),
                "AA:BB:CC:DD:EE:01",
                "variante non normalizzata: {variante:?}"
            );
        }
    }

    #[test]
    fn normalize_rifiuta_cio_che_non_e_un_mac() {
        // Il caso da proteggere e' il 13-cifre: `normalize_mac` filtrando le
        // cifre esadecimali da "AA:BB:CC:DD:EE:010" ne ricava 14 e lo
        // rifiutava, ma una riga con un numero civico o un anno non deve
        // mai diventare un MAC valido.
        for spazzatura in [
            "",
            "non-un-mac",
            "AA:BB:CC:DD:EE",
            "AA:BB:CC:DD:EE:01:02",
            "Z",
        ] {
            assert_eq!(
                normalize_mac(spazzatura),
                "",
                "accettata la spazzatura: {spazzatura:?}"
            );
        }
    }

    #[test]
    fn write_atomic_crea_il_file_e_le_directory_mancanti() {
        let dir = std::env::temp_dir().join(format!("bluesniff-fsx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("annidato").join("ignore.txt");
        write_atomic(&p, "AA:BB:CC:DD:EE:01\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "AA:BB:CC:DD:EE:01\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_non_lascia_temporanei() {
        let dir = std::env::temp_dir().join(format!("bluesniff-fsx-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bt_known.txt");
        write_atomic(&p, "a\n").unwrap();
        let rimasti: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(rimasti, vec!["bt_known.txt".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_sostituisce_un_file_che_esisteva_gia() {
        let dir = std::env::temp_dir().join(format!("bluesniff-fsx-c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ignore.txt");
        std::fs::write(&p, "vecchio\n").unwrap();
        write_atomic(&p, "nuovo\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "nuovo\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_eol_segue_il_file() {
        assert_eq!(detect_eol("a\r\nb\r\n"), "\r\n");
        assert_eq!(detect_eol("a\nb\n"), "\n");
        // File vuoto o nuovo: nessun terminatore da cui imparare, e il default
        // del progetto e' LF.
        assert_eq!(detect_eol(""), "\n");
    }
}
