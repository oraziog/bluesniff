//! Avvisi per vulnerabilità note dei dispositivi: il dispositivo viene
//! identificato dal Google Fast Pair Model ID (0xFE2C, 3 byte BE) quando
//! disponibile, oppure da pattern case-insensitive su nome/vendor per i
//! dispositivi senza Fast Pair (es. chip ESP32). Il database vive in
//! `fastpair_models.txt` accanto all'eseguibile (stesso schema di names.txt):
//!
//! ```text
//! # key;vendor;model;CVE;description
//! 13911719;Sony;WH-1000XM5;CVE-2025-36911;WhisperPair Fast Pair hijack
//! name:esp32;Espressif;ESP32;CVE-2025-27840;29 comandi HCI nascosti
//! ```
//!
//! `key` numerica = match sul Model ID esatto; `key` che inizia con
//! `name:` = match case-insensitive su nome pubblicizzato + hint + vendor
//! (pensato per i dispositivi che non annunciano Fast Pair); `key` che
//! inizia con `oui:` = match sui primi 3 ottetti del MAC del dispositivo
//! (es. `oui:24:0A:C4` → famiglia chip ESP32 di Espressif), utile per i
//! CVE a livello di chipset documentati nella ricerca Bluetooth

use std::path::PathBuf;

/// Una voce del database vulnerabilità: qualcosa da mostrare quando un
/// dispositivo la matcha (badge ⚠ nella dashboard, avviso [CVE] nel monitor).
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct CveEntry {
    /// Chiave di match: numerica (Model ID Fast Pair) oppure `name:<pattern>`.
    pub key: String,
    pub vendor: String,
    pub model: String,
    pub cve: String,
    pub description: String,
}

/// Percorso del database: `fastpair_models.txt` accanto all'eseguibile.
fn cves_path() -> PathBuf {
    crate::logging::exe_dir().join("fastpair_models.txt")
}

/// Carica `fastpair_models.txt` (righe `key;vendor;model;CVE;descrizione`,
/// `#` = commento). File assente o righe malformate vengono ignorati: l'app
/// resta pienamente funzionante senza database.
pub fn load_cves() -> Vec<CveEntry> {
    match std::fs::read_to_string(cves_path()) {
        Ok(content) => parse_lines(&content),
        Err(_) => Vec::new(),
    }
}

/// Parsea il contenuto del file: commenti (`#`) e righe con meno di 5 campi
/// vengono ignorati; i campi in più dopo la descrizione vengono riuniti.
pub fn parse_lines(content: &str) -> Vec<CveEntry> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(';').collect();
        if f.len() < 5 {
            continue;
        }
        out.push(CveEntry {
            key: f[0].trim().to_string(),
            vendor: f[1].trim().to_string(),
            model: f[2].trim().to_string(),
            cve: f[3].trim().to_string(),
            description: f[4..].join(";").trim().to_string(),
        });
    }
    out
}

/// Un CVE matchera' il dispositivo quando:
/// - la chiave della voce è numerica ed è uguale al Model ID Fast Pair, oppure
/// - la chiave è `name:<pattern>` e il pattern compare (case-insensitive) in
///   nome pubblicizzato, hint o vendor, oppure
/// - la chiave è `oui:<AA:BB:CC>` e il MAC del dispositivo inizia con quel
///   prefisso (match del fornitore/chip dal MAC).
pub fn matches(
    entry: &CveEntry,
    model_id: Option<u32>,
    name: &str,
    vendor: &str,
    hint: &str,
    mac: &str,
) -> bool {
    if let Ok(id) = entry.key.parse::<u32>() {
        return model_id == Some(id);
    }
    if let Some(pattern) = entry.key.strip_prefix("name:") {
        let needle = pattern.to_lowercase();
        let hay = format!("{name} {hint} {vendor}").to_lowercase();
        return hay.contains(&needle);
    }
    if let Some(oui) = entry.key.strip_prefix("oui:") {
        return mac.to_uppercase().starts_with(&oui.to_uppercase());
    }
    false
}

static DB: std::sync::OnceLock<Vec<CveEntry>> = std::sync::OnceLock::new();

/// Database caricato una sola volta (lettura del file al primo uso).
pub fn db() -> &'static [CveEntry] {
    DB.get_or_init(load_cves)
}

/// Percorso della mappa Model ID Fast Pair -> nome prodotto
/// (`model_names.txt` accanto all'eseguibile, generata dal dataset di
/// Bluetooth-LE-Spam / Flipper-XFW Xtreme-Firmware).
fn model_names_path() -> PathBuf {
    crate::logging::exe_dir().join("model_names.txt")
}

static MODEL_NAMES: std::sync::OnceLock<std::collections::HashMap<u32, String>> =
    std::sync::OnceLock::new();

/// Carica `model_names.txt` (righe `model_id;nome`, solo id numerici validi).
pub fn model_name(model_id: u32) -> Option<String> {
    let map = MODEL_NAMES.get_or_init(|| {
        let mut out = std::collections::HashMap::new();
        if let Ok(content) = std::fs::read_to_string(model_names_path()) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut it = line.split(';');
                if let (Some(id), Some(name)) = (it.next(), it.next()) {
                    if let Ok(id) = id.trim().parse::<u32>() {
                        out.insert(id, name.trim().to_string());
                    }
                }
            }
        }
        out
    });
    map.get(&model_id).cloned()
}

/// Ritorna tutte le voci che matchano il dispositivo (in ordine del file).
/// `mac` serve al match `oui:<prefisso>` (viene confrontato in maiuscolo).
pub fn match_cves(
    db: &[CveEntry],
    model_id: Option<u32>,
    name: &str,
    vendor: &str,
    hint: &str,
    mac: &str,
) -> Vec<CveEntry> {
    db.iter()
        .filter(|e| matches(e, model_id, name, vendor, hint, mac))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_key_matches_exact_model_id() {
        let db = vec![CveEntry {
            key: "13911719".into(),
            vendor: "Sony".into(),
            model: "WH-1000XM5".into(),
            cve: "CVE-2025-36911".into(),
            description: "WhisperPair Fast Pair hijack".into(),
        }];
        assert!(matches(&db[0], Some(13911719), "WF-1000XM5", "", "", ""));
        assert!(!matches(&db[0], Some(12499626), "WF-1000XM5", "", "", ""));
        assert!(match_cves(&db, Some(13911719), "WH-1000XM5", "", "", "").len() == 1);
        assert!(match_cves(&db, None, "WH-1000XM5", "", "", "").is_empty());
    }

    #[test]
    fn name_pattern_matches_case_insensitive_across_fields() {
        let db = [CveEntry {
            key: "name:esp32".into(),
            vendor: "Espressif".into(),
            model: "ESP32".into(),
            cve: "CVE-2025-27840".into(),
            description: "hidden HCI commands".into(),
        }];
        // Nome pubblicizzato (i chip ESP32 in genere pubblicizzano "ESP32...").
        assert!(matches(&db[0], None, "ESP32-BLE", "", "", ""));
        // Hint dall'annuncio che cita esp32 nel payload.
        assert!(matches(&db[0], None, "", "", "Google Fast Pair ESP32", ""));
        // "Espressif" (vendor) o nomi generici NON matchano "esp32".
        assert!(!matches(&db[0], None, "", "Espressif", "", ""));
        assert!(!matches(&db[0], None, "Mi Band 7", "", "", ""));
    }

    #[test]
    fn oui_key_matches_mac_prefix_case_insensitive() {
        let db = vec![CveEntry {
            key: "oui:24:0a:c4".into(),
            vendor: "Espressif".into(),
            model: "ESP32".into(),
            cve: "CVE-2025-27840".into(),
            description: "hidden HCI commands (firmware-dependent)".into(),
        }];
        // MAC che inizia con l'OUI (minuscolo o maiuscolo) -> match.
        assert!(matches(&db[0], None, "", "", "", "24:0A:C4:11:22:33"));
        assert!(matches(&db[0], None, "", "", "", "24:0a:c4:11:22:33"));
        // Altri prefissi NON matchano.
        assert!(!matches(&db[0], None, "", "", "", "F4:CF:A2:11:22:33"));
        assert!(match_cves(&db, None, "", "", "", "F4:CF:A2:11:22:33").is_empty());
        assert!(match_cves(&db, None, "", "", "", "24:0A:C4:11:22:33").len() == 1);
    }

    #[test]
    fn load_skips_comments_and_malformed() {
        let dir = std::env::temp_dir().join(format!("bluesniff-cves-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fastpair_models.txt");
        std::fs::write(
            &path,
            "# commento\n\n13911719;Sony;WH-1000XM5;CVE-2025-36911;desc\nname:esp32;Espressif;ESP32\nriga;corta\n",
        )
        .unwrap();
        // load_cves legge da exe_dir; testiamo direttamente la logica via
        // parse_lines per evitare di dipendere dalla posizione dell'exe.
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed = parse_lines(&content);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].cve, "CVE-2025-36911");
    }
}
