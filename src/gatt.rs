//! Sonda GATT (semi-attiva, sola lettura) — idea portata da bluing (`le --gatt`).
//!
//! Connette al dispositivo BLE, scopre i servizi primari e le relative
//! characteristic (UUID, proprietà, descrizione) e legge — solo per il
//! servizio Device Information e solo dove la proprietà Read è dichiarata —
//! i valori di identificazione (Manufacturer Name 0x2A29, Model Number
//! 0x2A24, Firmware 0x2A26, PnP 0x2A50...). Niente scritture, niente
//! notifiche: è un dump di lettura, come il comando originale.
//!
//! I risultati servono a identificare il modello anche quando l'annuncio
//! BLE non pubblicizza il nome, e matchano il database CVE (cves.rs) per
//! evidenziare modelli con vulnerabilità note.
//!
//! Nota tecnica: gli oggetti WinRT (`BluetoothLEDevice`, Gatt*) NON sono
//! `Send`, quindi la sonda gira su un thread dedicato con un mini-runtime
//! tokio current-thread (e COM inizializzato MTA): completa i soli await
//! WinRT senza intaccare i worker del server.

use std::time::Duration;

use windows::core::GUID;

/// Una characteristic scoperta durante la sonda.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GattChar {
    pub uuid: String,
    /// Nome amichevole se l'UUID rientra nelle mappe note (es. "Model Number").
    pub name: String,
    /// Proprietà in forma compatta: R=read, W=write, Wn=write-no-response,
    /// N=notify, I=indicate, B=broadcast.
    pub props: String,
    /// Valore letto (solo Device Information, se leggibile): testo se
    /// stampabile, altrimenti hex.
    pub value: Option<String>,
}

/// Un servizio primario scoperto durante la sonda.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GattService {
    pub uuid: String,
    pub name: String,
    pub chars: Vec<GattChar>,
}

/// Risultato completo di una sonda GATT.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GattProbe {
    pub mac: String,
    pub device_name: Option<String>,
    pub error: Option<String>,
    pub services: Vec<GattService>,
    /// Riga di identificazione prodotto ricavata dal Device Information
    /// (es. "Sony · WH-1000XM5 (firmware 2.0.1)") — None se non leggibile.
    pub ident: Option<String>,
    /// CVE note che matchano identificazione/vendor (cves.rs).
    pub cves: Vec<crate::cves::CveEntry>,
}

/// UUID bluetooth `0000xxxx-0000-1000-8000-00805f9b34fb` -> parte a 16 bit.
pub fn uuid16(guid: &GUID) -> u16 {
    let b = guid.to_u128().to_be_bytes();
    ((b[2] as u16) << 8) | b[3] as u16
}

/// Stringa UUID canonica.
pub fn uuid_str(guid: &GUID) -> String {
    let b = guid.to_u128().to_be_bytes();
    let h: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        h[8],
        h[9],
        h[10],
        h[11],
        h[12],
        h[13],
        h[14],
        h[15]
    )
}

fn mac_to_u64(mac: &str) -> Option<u64> {
    let clean: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == ':')
        .collect::<String>()
        .replace(':', "");
    if clean.len() != 12 {
        return None;
    }
    u64::from_str_radix(&clean, 16).ok()
}

fn fmt_props(
    p: windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties,
) -> String {
    use windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties as P;
    let mut s = String::new();
    if p.contains(P::Read) {
        s.push('R');
    }
    if p.contains(P::Write) {
        s.push_str(" W");
    }
    if p.contains(P::WriteWithoutResponse) {
        s.push_str(" Wn");
    }
    if p.contains(P::Notify) {
        s.push_str(" N");
    }
    if p.contains(P::Indicate) {
        s.push_str(" I");
    }
    if p.contains(P::Broadcast) {
        s.push_str(" B");
    }
    // strip leading space
    s.trim().to_string()
}

fn pretty(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| (0x20..0x7f).contains(&b) || b == 0) {
        return String::from_utf8_lossy(bytes)
            .trim_end_matches('\0')
            .to_string();
    }
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Nome del servizio GATT per UUID16, se conosciuto (database SIG completo
/// in `gattnames`, importato da blecat).
fn service_name(u: u16) -> Option<&'static str> {
    crate::gattnames::service_name(u)
}

/// Nome della characteristic GATT per UUID16, se conosciuta (database SIG
/// completo in `gattnames`).
fn char_name(u: u16) -> Option<&'static str> {
    crate::gattnames::char_name(u)
}

/// UUID16 leggibili del servizio Device Information (per la lettura valori).
fn is_devinfo_char(u: u16) -> bool {
    // Device Information ufficiale (0x2A23-0x2A2A) + PnP ID 0x2A50. La
    // vecchia mappa leggeva anche 0x2A42-44/0x2A76 credendoli versioni
    // firmware: col database SIG sono Alert Category / UV Index, non li
    // leggiamo piu'.
    matches!(u, 0x2a23..=0x2a2a | 0x2a50)
}

/// Corpo asincrono della sonda (gira nel mini-runtime del thread dedicato).
async fn probe_async(mac: &str) -> Result<GattProbe, String> {
    use windows::Devices::Bluetooth::BluetoothCacheMode;
    use windows::Devices::Bluetooth::BluetoothLEDevice;
    use windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus;

    let addr = mac_to_u64(mac).ok_or_else(|| format!("MAC non valido: {mac}"))?;

    let dev = BluetoothLEDevice::FromBluetoothAddressAsync(addr)
        .map_err(|e| format!("BluetoothLEDevice: {e}"))?
        .await
        .map_err(|e| {
            // Quirk Windows: per un device mai abbinato il factory restituisce
            // un oggetto nullo con HRESULT 0 — diciamolo chiaramente.
            if e.code().is_ok() {
                "Windows non riconosce questo dispositivo come BLE conosciuto: se è tuo, abbinalo da Impostazioni → Bluetooth e riprova".to_string()
            } else {
                format!("BluetoothLEDevice await: {e}")
            }
        })?;

    let device_name = dev
        .Name()
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let svcs_result = tokio::time::timeout(
        Duration::from_secs(8),
        dev.GetGattServicesWithCacheModeAsync(BluetoothCacheMode::Uncached)
            .map_err(|e| format!("GetGattServices: {e}"))?,
    )
    .await
    .map_err(|_| "timeout discovery servizi (8s)".to_string())?
    .map_err(|e| format!("GetGattServices await: {e}"))?;

    let status = svcs_result.Status().map_err(|e| format!("status: {e}"))?;
    if status != GattCommunicationStatus::Success {
        let why = match status {
            GattCommunicationStatus::Unreachable => {
                "dispositivo non raggiungibile (fuori portata o spento)".to_string()
            }
            GattCommunicationStatus::AccessDenied => {
                "accesso negato: abbina il dispositivo da Impostazioni → Bluetooth e riprova"
                    .to_string()
            }
            GattCommunicationStatus::ProtocolError => "errore di protocollo GATT".to_string(),
            _ => format!("{status:?}"),
        };
        return Err(why);
    }

    let services = svcs_result
        .Services()
        .map_err(|e| format!("services: {e}"))?;
    let n = services.Size().unwrap_or(0).min(30);

    let mut out_services: Vec<GattService> = Vec::new();
    let mut ident_parts: Vec<String> = Vec::new();

    for i in 0..n {
        let svc = services.GetAt(i).map_err(|e| format!("GetAt svc: {e}"))?;
        let su16 = uuid16(&svc.Uuid().map_err(|e| format!("svc uuid: {e}"))?);
        let chars_result = match tokio::time::timeout(
            Duration::from_secs(3),
            svc.GetCharacteristicsAsync()
                .map_err(|e| format!("GetChars: {e}"))?,
        )
        .await
        {
            Ok(Ok(r)) => r,
            _ => continue,
        };
        if chars_result
            .Status()
            .unwrap_or(GattCommunicationStatus::Unreachable)
            != GattCommunicationStatus::Success
        {
            continue;
        }
        let chars = match chars_result.Characteristics() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let m = chars.Size().unwrap_or(0).min(40);
        let mut out_chars: Vec<GattChar> = Vec::new();
        for j in 0..m {
            let ch = chars.GetAt(j).map_err(|e| format!("GetAt ch: {e}"))?;
            let cu16 = uuid16(&ch.Uuid().map_err(|e| format!("ch uuid: {e}"))?);
            let props = ch
                .CharacteristicProperties()
                .map_err(|e| format!("props: {e}"))?;
            let desc = ch
                .UserDescription()
                .ok()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let mut value: Option<String> = None;
            // Lettura solo per Device Information, solo con proprietà Read:
            // pochi byte, massimo 1.5s per caratteristica.
            if is_devinfo_char(cu16)
                && props.contains(
                    windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties::Read,
                )
            {
                let result = tokio::time::timeout(
                    Duration::from_millis(1500),
                    ch.ReadValueAsync().map_err(|e| format!("ReadValue: {e}"))?,
                )
                .await;
                if let Ok(Ok(r)) = result {
                    if r.Status().unwrap_or(GattCommunicationStatus::ProtocolError)
                        == GattCommunicationStatus::Success
                    {
                        if let Ok(buf) = r.Value() {
                            if let Ok(reader) =
                                windows::Storage::Streams::DataReader::FromBuffer(&buf)
                            {
                                if let Ok(len) = reader.UnconsumedBufferLength() {
                                    let mut data = vec![0u8; len as usize];
                                    if reader.ReadBytes(&mut data).is_ok() {
                                        let s = pretty(&data);
                                        value = Some(s.clone());
                                        if matches!(cu16, 0x2a29 | 0x2a24) && !s.is_empty() {
                                            ident_parts.push(s);
                                        } else if cu16 == 0x2a26 && !s.is_empty() {
                                            ident_parts.push(format!("firmware {s}"));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let name = match char_name(cu16) {
                Some(n) if desc.is_empty() => n.to_string(),
                Some(n) => format!("{n} ({desc})"),
                None if !desc.is_empty() => desc,
                None => "characteristic".to_string(),
            };
            out_chars.push(GattChar {
                uuid: uuid_str(&ch.Uuid().unwrap_or(GUID::zeroed())),
                name,
                props: fmt_props(props),
                value,
            });
        }
        let name = match service_name(su16) {
            Some(n) => n.to_string(),
            None => format!("service 0x{su16:04x}"),
        };
        out_services.push(GattService {
            uuid: uuid_str(&svc.Uuid().unwrap_or(GUID::zeroed())),
            name,
            chars: out_chars,
        });
    }

    let ident = if ident_parts.is_empty() {
        None
    } else {
        Some(ident_parts.join(" · "))
    };

    // Match CVE: il DB cerca pattern `name:` su nome/vendor — con
    // identificazione prodotto reale le corrispondenze diventano precise.
    let cves = {
        let ident_s = ident.clone().unwrap_or_default();
        crate::cves::match_cves(crate::cves::db(), None, &ident_s, &ident_s, "", mac)
    };

    Ok(GattProbe {
        mac: mac.to_string(),
        device_name,
        error: None,
        services: out_services,
        ident,
        cves,
    })
}

/// Esegue la sonda GATT su un thread dedicato (COM MTA + mini-runtime
/// current-thread) perché gli oggetti WinRT non sono `Send`. Bloccante fino
/// a 12 s; il chiamante dovrebbe usarla in `spawn_blocking`.
pub fn probe(mac: &str) -> GattProbe {
    const TIMEOUT: Duration = Duration::from_secs(12);
    let (tx, rx) = std::sync::mpsc::channel::<GattProbe>();
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
            Ok(Err(e)) => GattProbe {
                mac: mac_thread.clone(),
                device_name: None,
                error: Some(e),
                services: Vec::new(),
                ident: None,
                cves: Vec::new(),
            },
            Err(e) => GattProbe {
                mac: mac_thread.clone(),
                device_name: None,
                error: Some(format!("runtime fallito: {e}")),
                services: Vec::new(),
                ident: None,
                cves: Vec::new(),
            },
        };
        let _ = tx.send(probe);
    });
    rx.recv_timeout(TIMEOUT).unwrap_or_else(|_| GattProbe {
        mac: mac_timeout,
        device_name: None,
        error: Some("sonda GATT in timeout (12s)".to_string()),
        services: Vec::new(),
        ident: None,
        cves: Vec::new(),
    })
}

// Il percorso non-Windows: stub inerte (la dashboard è Windows-only).
#[cfg(not(windows))]
pub fn probe(_mac: &str) -> GattProbe {
    GattProbe {
        mac: _mac.to_string(),
        device_name: None,
        error: Some("sonda GATT disponibile solo su Windows".to_string()),
        services: Vec::new(),
        ident: None,
        cves: Vec::new(),
    }
}

/// Mappa per i test: serve solo a verificare le utility di formattazione.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_helpers_and_names() {
        let guid = GUID::from_u128(0x00002a2900001000800000805f9b34fb);
        assert_eq!(uuid16(&guid), 0x2a29);
        assert_eq!(uuid_str(&guid), "00002a29-0000-1000-8000-00805f9b34fb");
        assert_eq!(char_name(0x2a29), Some("Manufacturer Name"));
        assert_eq!(service_name(0x180a), Some("Device Information"));
        // Spot-check sul database SIG (blecat) importato in gattnames.
        assert_eq!(service_name(0x180f), Some("Battery Service"));
        assert_eq!(service_name(0x180d), Some("Heart Rate"));
        assert_eq!(service_name(0x1811), Some("Alert Notification"));
        assert_eq!(service_name(0x1814), Some("Running Speed and Cadence"));
        assert_eq!(service_name(0x183a), Some("Insulin Delivery"));
        assert_eq!(service_name(0xfe2c), Some("Google Fast Pair"));
        assert_eq!(char_name(0x2a19), Some("Battery Level"));
        assert_eq!(char_name(0x2a37), Some("Heart Rate Measurement"));
        assert_eq!(char_name(0x2a24), Some("Model Number"));
        // Nomi estesi arrivati col database SIG ma assenti nella vecchia mappa.
        assert_eq!(char_name(0x2a02), Some("Peripheral Privacy Flag"));
        assert_eq!(service_name(0x1806), Some("Reference Time Update"));
    }

    #[test]
    fn pretty_formats_ascii_and_hex() {
        assert_eq!(pretty(b"Sony\0"), "Sony");
        assert_eq!(pretty(&[0xDE, 0xAD]), "de ad");
    }
}
