//! Sonda SDP classica (semi-attiva, sola lettura) — idea portata da bluing
//! (`br --sdp`).
//!
//! Su Windows 10/11 i socket AF_BTH L2CAP (PSM 0x0001, il PDU SDP fai-da-te)
//! NON sono più supportati (WSAENETDOWN: la pila L2CAP client è rimossa), ma
//! WinRT espone lo stesso client SDP del sistema attraverso
//! `RfcommDeviceService`: per ogni classe di servizio nota si fa una
//! discovery mirata al dispositivo (`GetDeviceSelectorForBluetoothDeviceAndServiceId`)
//! e si legge il canale RFCOMM (`ConnectionServiceName`) e gli attributi SDP
//! grezzi (`GetSdpRawAttributesAsync`, da cui il ServiceName).
//!
//! Solo lettura: nessuna scrittura SDP, nessun pairing richiesto per la
//! discovery (è la stessa SDP browse che fa la UI di Windows). Come per la
//! sonda GATT, gli oggetti WinRT non sono `Send`: si gira su un thread
//! dedicato con mini-runtime tokio e COM MTA.

use std::time::Duration;

/// Un servizio scoperto dal database SDP remoto.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SdpService {
    /// Classe del servizio UUID16 (es. 0x1101 = Serial Port).
    pub uuid: u16,
    pub class_name: String,
    /// ServiceName dichiarato nel record SDP (se leggibile).
    pub service_name: Option<String>,
    /// Canale/protocollo dedotto (es. "RFCOMM ch 3").
    pub protocol: Option<String>,
}

/// Risultato della sonda SDP.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SdpProbe {
    pub mac: String,
    pub error: Option<String>,
    pub services: Vec<SdpService>,
    /// Note di esposizione ricavate dai servizi trovati (badge ⚠ nel pannello).
    pub risks: Vec<SdpRisk>,
}

/// Nota di esposizione associata a una classe di servizio SDP. Le mappature
/// derivano dalla ricerca di sicurezza Bluetooth (BlueToolkit WOOT'25 per MAP,
/// famiglie BlueSnarf/OBEX per i profili legacy): NON sono verdetti — un
/// servizio esposto è normale per un telefono; il rischio nasce se il
/// dispositivo lo accetta senza autenticazione.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SdpRisk {
    pub id: &'static str,
    pub title: &'static str,
    pub note: &'static str,
}

/// Rischio associato a una classe di servizio (None per i profili benigni).
pub fn risk_for(uuid16: u16) -> Option<SdpRisk> {
    Some(match uuid16 {
        0x1131 | 0x1132 => SdpRisk {
            id: "map",
            title: "MAP (SMS/MMS) esposto",
            note: "Possibile hijack account / lettura SMS se accettato senza auth (BlueToolkit WOOT'25)",
        },
        0x1105 => SdpRisk {
            id: "obex-op",
            title: "OBEX Object Push esposto",
            note: "Famiglia BlueSnarf: su stack OBEX datati accesso ai file senza autenticazione",
        },
        0x112f | 0x1130 => SdpRisk {
            id: "pbap",
            title: "PBAP (rubrica) esposto",
            note: "Possibile esfiltrazione della rubrica se la connessione non richiede auth",
        },
        0x1106 => SdpRisk {
            id: "obex-ft",
            title: "OBEX File Transfer esposto",
            note: "Trasferimento file bidirezionale: verificare che richieda autenticazione",
        },
        0x112d | 0x112e => SdpRisk {
            id: "sim-access",
            title: "SIM Access (SAP) esposto",
            note: "Se non protetto, chi si connette può operare sulla SIM",
        },
        _ => return None,
    })
}

/// Rischi deduplicati per i servizi trovati (in ordine del file).
pub fn risks_for(services: &[SdpService]) -> Vec<SdpRisk> {
    let mut out: Vec<SdpRisk> = Vec::new();
    for s in services {
        if let Some(r) = risk_for(s.uuid) {
            if !out.iter().any(|x| x.id == r.id) {
                out.push(r);
            }
        }
    }
    out
}

/// Classi di servizio da sondare (con nome per la UI).
const KNOWN_SERVICES: &[(u16, &str)] = &[
    (0x1101, "Serial Port (SPP)"),
    (0x1102, "LAN Access Using PPP"),
    (0x1104, "A/V Remote Control"),
    (0x1105, "OBEX Object Push"),
    (0x1106, "OBEX File Transfer"),
    (0x1108, "Headset"),
    (0x110a, "Audio Source (A2DP)"),
    (0x110b, "Audio Sink (A2DP)"),
    (0x110c, "A/V Remote Control Target (AVRCP)"),
    (0x110e, "A/V Remote Control Controller (AVRCP)"),
    (0x1112, "Headset Audio Gateway (HSP AG)"),
    (0x1115, "PANU"),
    (0x1116, "NAP"),
    (0x111e, "Handsfree (HFP)"),
    (0x111f, "Handsfree Audio Gateway"),
    (0x1123, "Dial-Up Networking (DUN)"),
    (0x112d, "SIM Access Server (SAP)"),
    (0x112e, "SIM Access Client"),
    (0x112f, "Phonebook Access PSE (PBAP)"),
    (0x1130, "Phonebook Access PCE"),
    (0x1131, "Message Access Server (MAP)"),
    (0x1132, "Message Notification Server (MAP)"),
];
/// Attributi SDP grezzi: estrae la stringa del ServiceName (0x0100 + base
/// dalla LanguageBaseAttributeIDList, o 0x0100 da solo).
#[allow(dead_code)] // usato dal percorso WinRT (compilato solo su Windows)
pub(crate) fn decode_service_name(map: &std::collections::HashMap<u32, Vec<u8>>) -> Option<String> {
    // Passata 1: trova la base linguistica (attributo 0x0006).
    let mut base: Option<u32> = None;
    if let Some(raw) = map.get(&0x0006) {
        if let Some(de) = crate::sdp::parse_raw_de(raw) {
            if let Some(items) = sdp_seq_values(&de) {
                if items.len() >= 3 {
                    if let Some(v) = sdp_u32(&items[2]) {
                        base = Some(v);
                    }
                }
            }
        }
    }
    // Passata 2: ServiceName alla chiave 0x0100 + base (o 0x0100 pulita).
    let key = 0x0100u32.wrapping_add(base.unwrap_or(0));
    let raw = map.get(&key)?;
    if let Some(de) = crate::sdp::parse_raw_de(raw) {
        if let Some(s) = sdp_text(&de) {
            // Windows aggiunge un NUL di terminazione alla stringa SDP.
            let t = s.trim_end_matches('\0').trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn sdp_seq_values(de: &crate::sdp::De) -> Option<&Vec<crate::sdp::De>> {
    if let crate::sdp::De::Seq(items) = de {
        Some(items)
    } else {
        None
    }
}

fn sdp_u32(de: &crate::sdp::De) -> Option<u32> {
    match de {
        crate::sdp::De::U8(v) => Some(*v as u32),
        crate::sdp::De::U16(v) => Some(*v as u32),
        crate::sdp::De::U32(v) => Some(*v),
        _ => None,
    }
}

fn sdp_text(de: &crate::sdp::De) -> Option<&str> {
    if let crate::sdp::De::Text(s) = de {
        Some(s)
    } else {
        None
    }
}

/// Corpo asincrono della sonda (gira nel mini-runtime del thread dedicato).
async fn probe_async(mac: &str) -> Result<SdpProbe, String> {
    use windows::Devices::Bluetooth::BluetoothDevice;
    use windows::Devices::Bluetooth::Rfcomm::{RfcommDeviceService, RfcommServiceId};

    let clean: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == ':')
        .collect::<String>()
        .replace(':', "");
    if clean.len() != 12 {
        return Err("MAC non valido".to_string());
    }
    let addr = u64::from_str_radix(&clean, 16).map_err(|e| format!("MAC non valido: {e}"))?;

    let dev = BluetoothDevice::FromBluetoothAddressAsync(addr)
        .map_err(|e| format!("BluetoothDevice: {e}"))?
        .await
        .map_err(|e| format!("BluetoothDevice await: {e}"))?;

    let mut services: Vec<SdpService> = Vec::new();
    for (uuid16, name) in KNOWN_SERVICES {
        let sid = match RfcommServiceId::FromShortId(*uuid16 as u32) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let selector = match RfcommDeviceService::GetDeviceSelectorForBluetoothDeviceAndServiceId(
            &dev, &sid,
        ) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Discovery mirata al dispositivo: risultati = servizio di QUEL
        // device (se lo offre). Cached=False per SDP fresca.
        let found = match tokio::time::timeout(
            Duration::from_secs(2),
            windows::Devices::Enumeration::DeviceInformation::FindAllAsyncAqsFilter(&selector)
                .map_err(|e| format!("FindAllAsync: {e}"))?,
        )
        .await
        {
            Ok(Ok(c)) => c,
            _ => continue,
        };
        let n = found.Size().unwrap_or(0);
        for i in 0..n {
            let info = match found.GetAt(i) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let svc = match tokio::time::timeout(
                Duration::from_secs(2),
                RfcommDeviceService::FromIdAsync(&info.Id().map_err(|e| format!("id: {e}"))?)
                    .map_err(|e| format!("FromId: {e}"))?,
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => continue,
            };
            // Canale RFCOMM quando disponibile. Nota: su alcune build
            // Windows ConnectionServiceName restituisce l'ID completo del
            // servizio invece del numero di canale — in tal caso mostriamo
            // semplicemente "RFCOMM".
            let protocol = svc
                .ConnectionServiceName()
                .ok()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let t = s.to_string();
                    let t = t.trim();
                    let owned = t.to_string();
                    if owned.parse::<u32>().is_ok() {
                        format!("RFCOMM ch {owned}")
                    } else if owned.contains("RFCOMM") {
                        "RFCOMM".to_string()
                    } else {
                        format!("RFCOMM ({owned})").chars().take(30).collect()
                    }
                });
            // Attributi SDP grezzi per il ServiceName (best-effort).
            let service_name = tokio::time::timeout(
                Duration::from_secs(2),
                svc.GetSdpRawAttributesAsync()
                    .map_err(|e| format!("GetSdpRawAttributes: {e}"))?,
            )
            .await
            .ok()
            .and_then(|r| r.ok())
            .and_then(|m| {
                let mut out = std::collections::HashMap::new();
                let it = m.First().ok()?;
                loop {
                    let pair = match it.Current() {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    if let (Ok(k), Ok(v)) = (pair.Key(), pair.Value()) {
                        if let Ok(reader) = windows::Storage::Streams::DataReader::FromBuffer(&v) {
                            if let Ok(len) = reader.UnconsumedBufferLength() {
                                let mut data = vec![0u8; len as usize];
                                if reader.ReadBytes(&mut data).is_ok() {
                                    out.insert(k, data);
                                }
                            }
                        }
                    }
                    if !it.MoveNext().unwrap_or(false) {
                        break;
                    }
                }
                Some(out)
            })
            .and_then(|map| decode_service_name(&map));

            services.push(SdpService {
                uuid: *uuid16,
                class_name: name.to_string(),
                service_name,
                protocol,
            });
        }
    }

    // Deduplicazione per classe (un device può annunciare 2 volte la stessa
    // classe con servizi diversi — teniamo la prima con canale più specifico).
    services.sort_by_key(|s| (s.uuid, s.protocol.is_none()));
    services.dedup_by_key(|s| (s.uuid, s.protocol.clone()));
    let risks = risks_for(&services);

    Ok(SdpProbe {
        mac: mac.to_string(),
        error: None,
        services,
        risks,
    })
}

/// Esegue la sonda SDP su un thread dedicato (COM MTA + mini-runtime
/// current-thread). Bloccante fino a ~25 s; chiamare in `spawn_blocking`.
pub fn probe(mac: &str) -> SdpProbe {
    const TIMEOUT: Duration = Duration::from_secs(25);
    let (tx, rx) = std::sync::mpsc::channel::<SdpProbe>();
    let mac_timeout = mac.to_string();
    let mac_thread = mac_timeout.clone();
    std::thread::spawn(move || {
        // SAFETY: inizializzazione COM per il thread della sonda (MTA).
        unsafe {
            let _ = windows::Win32::System::Com::CoInitializeEx(
                None,
                windows::Win32::System::Com::COINIT_MULTITHREADED,
            );
        }
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|rt| rt.block_on(probe_async(&mac_thread)));
        let probe = match result {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => SdpProbe {
                mac: mac_thread.clone(),
                error: Some(e),
                services: Vec::new(),
                risks: Vec::new(),
            },
            Err(e) => SdpProbe {
                mac: mac_thread.clone(),
                error: Some(format!("runtime fallito: {e}")),
                services: Vec::new(),
                risks: Vec::new(),
            },
        };
        let _ = tx.send(probe);
    });
    rx.recv_timeout(TIMEOUT).unwrap_or_else(|_| SdpProbe {
        mac: mac_timeout,
        error: Some("sonda SDP in timeout (25s)".to_string()),
        services: Vec::new(),
        risks: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Parser SDP data element (usato per decodificare il ServiceName dagli
// attributi grezzi e coperto dai test).
// ---------------------------------------------------------------------------

/// Data element SDP. Alcune varianti sono parsate ma non ancora consumate
/// dalle estrazioni (signed/bool/uuid128/url) — restano per completezza.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum De {
    Nil,
    U8(u8),
    U16(u16),
    U32(u32),
    U128(u128),
    Int(i64),
    Text(String),
    Bool(bool),
    Uuid16(u16),
    Uuid32(u32),
    Uuid128(u128),
    Seq(Vec<De>),
    Url(String),
}

fn read_u16(b: &[u8], pos: &mut usize) -> Option<u16> {
    if *pos + 2 > b.len() {
        return None;
    }
    let v = u16::from_be_bytes([b[*pos], b[*pos + 1]]);
    *pos += 2;
    Some(v)
}

fn read_u32(b: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > b.len() {
        return None;
    }
    let v = u32::from_be_bytes([b[*pos], b[*pos + 1], b[*pos + 2], b[*pos + 3]]);
    *pos += 4;
    Some(v)
}

/// Parser di un data element SDP (big-endian). Header: i 5 bit alti = tipo,
/// i 3 bassi = size descriptor (0..4 = 1<<size byte, 5 = lunghezza u8 dopo
/// l'header, 6 = u16, 7 = u32). Es. 0x19 = uuid16, 0x35 = seq.
pub(crate) fn parse_raw_de(b: &[u8]) -> Option<De> {
    let mut pos = 0;
    parse_de(b, &mut pos)
}

fn parse_de(b: &[u8], pos: &mut usize) -> Option<De> {
    let hdr = *b.get(*pos)?;
    *pos += 1;
    let typ = hdr >> 3;
    let size = (hdr & 0x07) as usize;
    let len = match size {
        0..=4 => 1usize << size,
        5 => {
            let l = *b.get(*pos)? as usize;
            *pos += 1;
            l
        }
        6 => read_u16(b, pos)? as usize,
        7 => read_u32(b, pos)? as usize,
        _ => return None,
    };
    let end = *pos + len;
    if end > b.len() {
        return None;
    }
    let slice = &b[*pos..end];
    let de = match typ {
        0x00 => De::Nil,
        0x01 => match len {
            1 => De::U8(slice[0]),
            2 => De::U16(u16::from_be_bytes([slice[0], slice[1]])),
            _ => De::U32(read_u32(slice, &mut 0).unwrap_or(0)),
        },
        0x02 => {
            let mut bytes = [0u8; 8];
            let n = len.min(8);
            bytes[8 - n..].copy_from_slice(&slice[..n]);
            De::Int(i64::from_be_bytes(bytes))
        }
        0x03 => match len {
            2 => De::Uuid16(u16::from_be_bytes([slice[0], slice[1]])),
            4 => De::Uuid32(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])),
            16 => {
                let mut b16 = [0u8; 16];
                b16.copy_from_slice(&slice[..16]);
                De::Uuid128(u128::from_be_bytes(b16))
            }
            _ => De::Uuid16(u16::from_be_bytes([slice[0], slice[1]])),
        },
        0x04 => De::Text(String::from_utf8_lossy(slice).to_string()),
        0x05 => De::Bool(slice.first().map(|&x| x != 0).unwrap_or(false)),
        0x06 | 0x07 => {
            let mut items = Vec::new();
            let mut q = *pos;
            while q < end {
                let item = parse_de(b, &mut q)?;
                items.push(item);
            }
            De::Seq(items)
        }
        _ => De::Nil,
    };
    *pos = end;
    Some(de)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_data_elements() {
        // ServiceClassIDList: seq(3) di uuid16 0x1101.
        let bytes = [0x35, 0x03, 0x19, 0x11, 0x01];
        let de = parse_de(&bytes, &mut 0).unwrap();
        assert!(matches!(de, De::Seq(v) if matches!(v[0], De::Uuid16(0x1101))));
    }

    #[test]
    fn parse_text_with_length() {
        // Text "Hi": 0x25 + lunghezza 2.
        let bytes = [0x25, 0x02, b'H', b'i'];
        let de = parse_de(&bytes, &mut 0).unwrap();
        assert!(matches!(de, De::Text(s) if s == "Hi"));
    }

    #[test]
    fn decode_service_name_with_base() {
        // Attributi grezzi simulati: 0x0006 LanguageBase (base 0x0100) +
        // 0x0200 ServiceName.
        let mut base = Vec::new();
        base.push(0x35);
        base.push(0x09);
        base.extend_from_slice(&[0x09, 0x01, 0x00, 0x09, 0x00, 0x00, 0x09, 0x01, 0x00]);
        let mut name = vec![0x25, 0x09];
        name.extend_from_slice(b"OBEX Push");
        let mut map = std::collections::HashMap::new();
        map.insert(0x0006, base);
        map.insert(0x0200, name);
        assert_eq!(decode_service_name(&map).as_deref(), Some("OBEX Push"));
    }

    #[test]
    fn decode_service_name_plain() {
        // Senza base: nome a 0x0100.
        let mut name = vec![0x25, 0x07];
        name.extend_from_slice(b"Headset");
        let mut map = std::collections::HashMap::new();
        map.insert(0x0100, name);
        assert_eq!(decode_service_name(&map).as_deref(), Some("Headset"));
    }
}
