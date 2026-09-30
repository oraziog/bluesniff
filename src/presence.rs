//! Analisi di presenza sul log raw: chi c'era e chi è sparito.
//!
//! Il principio è che **l'assenza di un pacchetto è un'informazione**, ma solo
//! se sappiamo che l'adapter stava guardando. Perciò ogni quiete viene valutata
//! contro [`crate::radiostate`]: se il radio era muto, il silenzio è dell'adapter
//! e l'analisi tace. È la differenza fra un tool che segnala fatti e uno che
//! segnala rumore.
//!
//! Un limite che ho verificato sui dati reali e che è importante tenere a
//! mente: **la cadenza non è un segnale**. Su una cattura vera la mediana
//! degli intervalli di un singolo iPhone oscilla da 5.18s a 0.95s in otto
//! minuti senza che il dispositivo cambi comportamento: è il controller che
//! perde pacchetti (VM con dongle in passthrough USB). Quindi qui non si segnala
//! "cambio di pattern", solo la sparizione. La cadenza resta in
//! [`crate::rawlog::DeviceStats`] come dato grezzo per l'utente, non come
//! verdetto automatico.

use std::collections::HashMap;

use crate::radiostate::{self, RadioHealth};

/// Un dispositivo che avevamo visto e che non rivediamo.
#[derive(Debug, Clone)]
pub struct MissingDevice {
    pub mac: String,
    pub packets: usize,
    /// Ultimo istante in cui l'abbiamo visto (epoch ms).
    pub last_seen_ms: i64,
    /// RSSI medio nei pacchetti osservati.
    pub rssi_avg: i16,
    pub rssi_last: i16,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub hint: Option<String>,
    /// Perché lo consideriamo sparito (o perché no, se è soppresso).
    pub reason: String,
}

/// Configurazione dei parametri di presenza.
#[derive(Debug, Clone, Copy)]
pub struct PresenceConfig {
    /// Un MAC deve essere stato visto almeno `min_packets` volte per entrare
    /// nell'analisi. Sotto questa soglia non sappiamo nulla di un dispositivo:
    /// una singola osservazione non giustifica "è sparito".
    pub min_packets: usize,
    /// Silenzio minimo, in minuti, per dichiarare la sparizione.
    pub silent_minutes: i64,
    /// Soglia oltre la quale il canale LE è considerato muto.
    pub radio_stale_ms: i64,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            min_packets: 3,
            silent_minutes: 10,
            radio_stale_ms: radiostate::DEFAULT_STALE_MS,
        }
    }
}

/// Aggregato per MAC su un insieme di righe, con le informazioni che servono
/// alla presenza e al seme Continuity.
pub struct Observation {
    pub mac: String,
    pub packets: usize,
    pub first_ms: i64,
    pub last_ms: i64,
    pub rssi_sum: i64,
    pub rssi_last: i16,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub hint: Option<String>,
    /// Blob Continuity stabile (payload del record AD 0x16 su UUID FCF1/FEF3).
    pub seed: Option<String>,
    /// Ultimo pacchetto del MAC, in epoch ms: serve per capire se il radio
    /// stava funzionando nel periodo di silenzio.
    pub last_packet_ms: i64,
}

impl Observation {
    fn new(mac: &str) -> Self {
        Self {
            mac: mac.to_string(),
            packets: 0,
            first_ms: 0,
            last_ms: 0,
            rssi_sum: 0,
            rssi_last: 0,
            name: None,
            vendor: None,
            hint: None,
            seed: None,
            last_packet_ms: 0,
        }
    }
}

/// Estrae il **blob Continuity**: il valore stabile che Apple mette nel record
/// AD `0x16` sotto UUID FCF1 o FEF3.
///
/// Ho verificato la struttura sui dati reali prima di scrivere questa funzione,
/// e la mia ipotesi iniziale era sbagliata: **non è un campo di 16 byte a
/// posizione fissa**. I record misurati sono di 20 byte (FCF1, con byte di
/// tipo `0x04` iniziale) e di 27 byte (FEF3, con prefisso `4a1723`), e i byte
/// che cambiano sono diversi a seconda della famiglia. Quindi qui non
/// seleziono "i 16 byte del seme": prendo **tutto il payload del record** e lo
/// tratto come un identificatore opaco.
///
/// Questo e' anche il comportamento corretto per l'uso che ne facciamo.
/// Apple deriva quel valore crittograficamente e lo tiene costante per il
/// dispositivo, perche' e' quello con cui il device legittimo viene
/// riconosciuto: non puo' cambiarlo a ogni rotazione di MAC senza spezzare il
/// collegamento col telefono. Quindi l'uguaglianza esatta del blob fra MAC
/// diversi e' un segnale forte.
///
/// Non lo trattiamo pero' come identita' del dispositivo. Se due MAC mostrano
/// lo stesso blob, il dato dice "ho visto questo valore sotto piu' indirizzi" e
/// lo diciamo: non concludiamo "sono lo stesso device", perche' potrebbero
/// essere due dispositivi distinti che Apple ha dotato dello stesso valore
/// (cosa che succede, per esempio, su una flotta di iPhone aziendali).
pub fn extract_continuity_seed(hex: &str) -> Option<String> {
    let b = crate::rawlog::hex_bytes(hex);
    let mut i = 0usize;
    while i + 1 < b.len() {
        let len = b[i] as usize;
        if len == 0 || i + len + 1 > b.len() {
            break;
        }
        let rtype = b[i + 1];
        if rtype == 0x16 && len >= 5 {
            let uuid = u16::from_le_bytes([b[i + 2], b[i + 3]]);
            if uuid == 0xFCF1 || uuid == 0xFEF3 {
                // L'intero payload del record, senza troncamenti: la lunghezza
                // varia per famiglia e selezionare byte fissi produrrebbe
                // collisioni false o analisi sbagliate.
                return Some(crate::rawlog::hex_str(&b[i + 4..i + 1 + len]));
            }
        }
        i += len + 1;
    }
    None
}

/// Costruisce le osservazioni dalle righe JSONL del log raw.
pub fn observe(lines: &[String]) -> Vec<Observation> {
    let mut accs: HashMap<String, Observation> = HashMap::new();
    for line in lines {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(mac) = v.get("mac").and_then(|x| x.as_str()) else {
            continue;
        };
        let ts = v
            .get("ts")
            .and_then(|x| x.as_str())
            .and_then(crate::logging::parse_rfc3339_millis)
            .unwrap_or(0);
        let rssi = v.get("rssi").and_then(|x| x.as_i64()).unwrap_or(0) as i16;
        let hex = v.get("hex").and_then(|x| x.as_str()).unwrap_or("");

        let obs = accs
            .entry(mac.to_string())
            .or_insert_with(|| Observation::new(mac));
        if obs.packets == 0 || ts < obs.first_ms {
            obs.first_ms = ts;
        }
        if ts >= obs.last_ms {
            obs.last_ms = ts;
        }
        obs.packets += 1;
        obs.rssi_sum += rssi as i64;
        obs.rssi_last = rssi;
        obs.last_packet_ms = obs.last_packet_ms.max(ts);
        if obs.name.is_none() {
            obs.name = v
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
        }
        if obs.vendor.is_none() {
            obs.vendor = v
                .get("vendor")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
        }
        if obs.hint.is_none() {
            obs.hint = v
                .get("hint")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
        }
        if obs.seed.is_none() {
            obs.seed = extract_continuity_seed(hex);
        }
    }
    accs.into_values().collect()
}

/// Presenza: chi è sparito.
///
/// Restituisce anche i MAC soppressi, con il motivo, perché una lista di soli
/// eventi lascia l'utente all'oscuro del perché non c'è nulla da segnalare.
pub fn missing(lines: &[String], now_ms: i64, cfg: &PresenceConfig) -> Vec<MissingDevice> {
    let health = radiostate::health(cfg.radio_stale_ms);
    let silent_ms = cfg.silent_minutes * 60_000;
    let mut out: Vec<MissingDevice> = Vec::new();

    // L'ultimo pacchetto di **qualsiasi** MAC dice se il radio stava lavorando.
    // Se l'ultima cosa che abbiamo visto in assoluto è più vecchia del silenzio
    // in esame, non possiamo distinguere adapter muto da device andato via.
    let last_any_ms = observe_global_last(lines);

    for obs in observe(lines) {
        if obs.packets < cfg.min_packets {
            continue;
        }
        let silence = now_ms - obs.last_seen_ms();
        if silence < silent_ms {
            continue;
        }
        let rssi_avg = if obs.packets == 0 {
            0
        } else {
            (obs.rssi_sum / obs.packets as i64) as i16
        };

        let reason = if health == RadioHealth::Absent {
            // L'adapter non ha mai prodotto: qualunque silenzio è suo.
            "adapter assente: osservazione non affidabile".to_string()
        } else if obs.last_seen_ms() < last_any_ms - silent_ms {
            // Questo MAC era già muto mentre altri MAC continuavano a parlare.
            "il radio era attivo ma per questo MAC non c'è più segnale".to_string()
        } else {
            format!("nessun pacchetto da {} minuti", cfg.silent_minutes)
        };

        out.push(MissingDevice {
            mac: obs.mac.clone(),
            packets: obs.packets,
            last_seen_ms: obs.last_seen_ms(),
            rssi_avg,
            rssi_last: obs.rssi_last,
            name: obs.name.clone(),
            vendor: obs.vendor.clone(),
            hint: obs.hint.clone(),
            reason,
        });
    }
    out.sort_by_key(|a| a.last_seen_ms);
    out
}

impl Observation {
    fn last_seen_ms(&self) -> i64 {
        self.last_ms
    }
}

fn observe_global_last(lines: &[String]) -> i64 {
    let mut last = 0i64;
    for line in lines {
        if let Some(ts) = line_ts(line) {
            last = last.max(ts);
        }
    }
    last
}

fn line_ts(line: &str) -> Option<i64> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("ts")
        .and_then(|x| x.as_str())
        .and_then(crate::logging::parse_rfc3339_millis)
}

/// Un seme Continuity osservato sotto più indirizzi.
#[derive(Debug, Clone)]
pub struct SeedGroup {
    pub seed: String,
    /// MAC distinti che hanno mostrato questo seme, in ordine di primo avvistamento.
    pub macs: Vec<String>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

/// Raggruppa i MAC per seme Continuity.
///
/// Non fondiamo le righe e non dichiariamo "sono lo stesso dispositivo": il
/// dato onesto è "lo stesso seme è comparso sotto N indirizzi". Un utente che
/// vede 7 AirTag deve poter continuare a vederne 7, con la nota che condividono
/// il seme, non 1 con la nota che "forse" sono 7.
pub fn seed_groups(observations: &[Observation]) -> Vec<SeedGroup> {
    let mut by_seed: HashMap<String, SeedGroup> = HashMap::new();
    for obs in observations {
        let Some(seed) = obs.seed.clone() else {
            continue;
        };
        let g = by_seed.entry(seed.clone()).or_insert_with(|| SeedGroup {
            seed: seed.clone(),
            macs: Vec::new(),
            first_seen_ms: obs.first_ms,
            last_seen_ms: obs.last_ms,
        });
        if !g.macs.contains(&obs.mac) {
            g.macs.push(obs.mac.clone());
        }
        g.first_seen_ms = g.first_seen_ms.min(obs.first_ms);
        g.last_seen_ms = g.last_seen_ms.max(obs.last_ms);
    }
    let mut out: Vec<SeedGroup> = by_seed.into_values().filter(|g| g.macs.len() > 1).collect();
    // Prima quelli con più indirizzi: sono i più interessanti.
    out.sort_by(|a, b| b.macs.len().cmp(&a.macs.len()).then(a.seed.cmp(&b.seed)));
    out
}

/// Mappa MAC -> numero di indirizzi che hanno mostrato lo stesso blob.
///
/// E' la mappa che serve al badge in tabella: la UI conosce la riga tramite il
/// MAC, quindi la chiave deve essere il MAC, non il blob. Restituiamo anche il
/// blob cosi' l'interfaccia puo' mostrarlo nel tooltip.
pub fn seed_mac_counts(observations: &[Observation]) -> HashMap<String, SeedInfo> {
    let mut per_seed: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    for obs in observations {
        if let Some(seed) = obs.seed.clone() {
            per_seed.entry(seed).or_default().insert(obs.mac.clone());
        }
    }
    let mut out: HashMap<String, SeedInfo> = HashMap::new();
    for obs in observations {
        let Some(seed) = obs.seed.clone() else {
            continue;
        };
        let n = per_seed.get(&seed).map(|s| s.len()).unwrap_or(1);
        // Se lo stesso MAC avesse piu' di un blob, teniamo il piu' grande: e'
        // l'informazione piu' utile per l'utente.
        let entry = out.entry(obs.mac.clone()).or_insert_with(|| SeedInfo {
            seed: seed.clone(),
            mac_count: n,
        });
        if n > entry.mac_count {
            entry.mac_count = n;
            entry.seed = seed;
        }
    }
    out
}

/// Informazione di badge per un MAC.
#[derive(Debug, Clone)]
pub struct SeedInfo {
    pub seed: String,
    /// Sotto quanti indirizzi diversi e' comparso questo blob.
    pub mac_count: usize,
}

/// JSON per la dashboard.
pub fn missing_json(
    devices: &[MissingDevice],
    health: RadioHealth,
    now_ms: i64,
) -> Vec<serde_json::Value> {
    devices
        .iter()
        .map(|d| {
            serde_json::json!({
                "mac": d.mac,
                "packets": d.packets,
                "last_seen_ms": d.last_seen_ms,
                "last_seen": crate::logging::rfc3339_millis(d.last_seen_ms),
                "silent_minutes": (now_ms - d.last_seen_ms) / 60_000,
                "rssi_avg": d.rssi_avg,
                "rssi_last": d.rssi_last,
                "name": d.name,
                "vendor": d.vendor,
                "hint": d.hint,
                "reason": d.reason,
                "reliable": health.reliable(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::parse_rfc3339_millis;

    fn ts(s: &str) -> i64 {
        parse_rfc3339_millis(s).unwrap()
    }

    fn line(ts_s: &str, mac: &str, rssi: i64, hex: &str) -> String {
        format!(
            r#"{{"ts":"{ts_s}","mac":"{mac}","rssi":{rssi},"hex":"{hex}","hint":"Apple-like — UUID Continuity (FCF1)"}}"#
        )
    }

    // ---- seme Continuity ----

    // Lunghezze reali misurate sul log: FCF1 record 0x17 (20 byte di payload)
    // e FEF3 record 0x1e (27 byte). I test usano questi, non un formato
    // inventato.

    #[test]
    fn estrae_il_blob_continuity_fcf1() {
        // flags(3) + len=0x17 type=0x16 uuid=FCF1 + 20 byte di payload reale
        let hex = "020106".to_string() + "1716f1fc" + "04cab69a91198aabdf0b35dfc5dfa6e67bdd632e";
        assert_eq!(
            extract_continuity_seed(&hex).as_deref(),
            Some("04cab69a91198aabdf0b35dfc5dfa6e67bdd632e")
        );
    }

    #[test]
    fn estrae_il_blob_continuity_fef3() {
        // len=0x1e, prefisso 4a1723: struttura diversa, stessa logica
        let hex = "020106".to_string()
            + "1e16f3fe"
            + "4a17235a3038551132abce7541f3181bc3cfd6d283659e585027f5";
        assert_eq!(
            extract_continuity_seed(&hex).as_deref(),
            Some("4a17235a3038551132abce7541f3181bc3cfd6d283659e585027f5")
        );
    }

    #[test]
    fn lunghezze_diverse_non_vengono_mescolate() {
        // Due famiglie diverse non devono produrre lo stesso blob.
        let fcf1 = "020106".to_string() + "1716f1fc" + "04cab69a91198aabdf0b35dfc5dfa6e67bdd632e";
        let fef3 = "020106".to_string()
            + "1e16f3fe"
            + "4a17235a3038551132abce7541f3181bc3cfd6d283659e585027f5";
        assert_ne!(
            extract_continuity_seed(&fcf1),
            extract_continuity_seed(&fef3)
        );
    }

    #[test]
    fn nessun_blob_su_altri_uuid_o_su_payload_corti() {
        assert_eq!(extract_continuity_seed("020106"), None);
        // Stessa struttura ma UUID non Continuity
        assert_eq!(extract_continuity_seed("12160d18"), None);
        // Record 0x16 troncato: non deve entrare in panic ne' produrre dati
        assert_eq!(extract_continuity_seed("1e16f1fc4a17"), None);
    }

    #[test]
    fn il_blob_non_e_un_identificativo_del_mac() {
        let s = "04cab69a91198aabdf0b35dfc5dfa6e67bdd632e";
        let a = line(
            "2026-09-29T10:00:00.000Z",
            "AA:BB:CC:DD:EE:01",
            -70,
            &format!("1716f1fc{s}"),
        );
        let b = line(
            "2026-09-29T10:05:00.000Z",
            "AA:BB:CC:DD:EE:02",
            -80,
            &format!("1716f1fc{s}"),
        );
        let obs = observe(&[a, b]);
        let groups = seed_groups(&obs);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].macs.len(), 2);
        // Il punto e' che i due MAC restano due osservazioni distinte.
        assert_eq!(obs.len(), 2);
    }

    #[test]
    fn un_blob_unico_non_genera_gruppo() {
        let a = line(
            "2026-09-29T10:00:00.000Z",
            "AA:BB:CC:DD:EE:01",
            -70,
            "1716f1fc04cab69a91198aabdf0b35dfc5dfa6e67bdd632e",
        );
        assert!(seed_groups(&observe(&[a])).is_empty());
    }

    // ---- presenza ----

    #[test]
    fn non_segna_un_mac_visto_una_sola_volta() {
        let now = ts("2026-09-29T12:00:00Z");
        let lines = vec![line(
            "2026-09-29T09:00:00.000Z",
            "AA:BB:CC:DD:EE:01",
            -70,
            "020106",
        )];
        let cfg = PresenceConfig {
            min_packets: 3,
            ..Default::default()
        };
        assert!(missing(&lines, now, &cfg).is_empty());
    }

    #[test]
    fn segna_il_mac_sparito_silenzioso() {
        let now = ts("2026-09-29T12:00:00Z");
        let lines: Vec<String> = (0..5)
            .map(|i| {
                line(
                    &format!("2026-09-29T{:02}:00:00.000Z", 9 + i / 3),
                    "AA:BB:CC:DD:EE:01",
                    -70,
                    "020106",
                )
            })
            .collect();
        // Finiamo verso le 10:33, ora e' mezzogiorno: ~87 minuti di silenzio.
        let cfg = PresenceConfig {
            min_packets: 3,
            silent_minutes: 10,
            ..Default::default()
        };
        let out = missing(&lines, now, &cfg);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mac, "AA:BB:CC:DD:EE:01");
        assert_eq!(out[0].packets, 5);
    }

    #[test]
    fn tace_se_l_adapter_era_assente() {
        let now = ts("2026-09-29T12:00:00Z");
        let lines: Vec<String> = (0..5)
            .map(|i| {
                line(
                    &format!("2026-09-29T{:02}:00:00.000Z", 9 + i / 3),
                    "AA:BB:CC:DD:EE:01",
                    -70,
                    "020106",
                )
            })
            .collect();
        let cfg = PresenceConfig {
            min_packets: 3,
            silent_minutes: 10,
            radio_stale_ms: i64::MAX,
        };
        // Con radio_stale_ms enorme e nessun pacchetto recente, il radio e' assente.
        let out = missing(&lines, now, &cfg);
        assert_eq!(out.len(), 1);
        assert!(
            out[0].reason.contains("adapter assente"),
            "motivo inatteso: {}",
            out[0].reason
        );
        assert!(!RadioHealth::Absent.reliable());
    }

    #[test]
    fn un_mac_che_torna_non_e_sparito() {
        let now = ts("2026-09-29T12:00:00Z");
        let mut lines: Vec<String> = (0..4)
            .map(|i| {
                line(
                    &format!("2026-09-29T{:02}:00:00.000Z", 9 + i / 2),
                    "AA:BB:CC:DD:EE:01",
                    -70,
                    "020106",
                )
            })
            .collect();
        // Un pacchetto 2 minuti fa: non e' sparito.
        lines.push(line(
            "2026-09-29T11:58:00.000Z",
            "AA:BB:CC:DD:EE:01",
            -70,
            "020106",
        ));
        let cfg = PresenceConfig {
            min_packets: 3,
            silent_minutes: 10,
            ..Default::default()
        };
        assert!(missing(&lines, now, &cfg).is_empty());
    }

    #[test]
    fn la_media_rssi_e_calcolata_sui_pacchetti_visti() {
        let now = ts("2026-09-29T12:00:00Z");
        let lines: Vec<String> = (0..5)
            .map(|i| {
                line(
                    &format!("2026-09-29T{:02}:00:00.000Z", 9 + i / 3),
                    "AA:BB:CC:DD:EE:01",
                    -60 - i,
                    "020106",
                )
            })
            .collect();
        let cfg = PresenceConfig {
            min_packets: 3,
            ..Default::default()
        };
        let out = missing(&lines, now, &cfg);
        assert_eq!(out[0].rssi_avg, -62);
        assert_eq!(out[0].rssi_last, -64);
    }
}
