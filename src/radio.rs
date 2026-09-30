//! Selezione e stato della radio Bluetooth locale.
//!
//! `list_radios()` enumera le radio viste dallo stack Classic (Win32
//! `BluetoothFindFirstRadio`); `resolve()` traduce il selettore di `--radio`
//! (indice 1-based come nel banner di avvio, MAC oppure nome) in una
//! `RadioInfo`; `selected()` espone la radio attiva al resto del processo,
//! così l'inquiry Classic e le probe RFCOMM sanno da quale adattatore partire.
//!
//! Nota di piattaforma: il watcher BLE di WinRT
//! (`BluetoothLEAdvertisementWatcher`) scansiona **sempre** l'adattatore
//! predefinito di sistema e non espone alcuna API per sceglierne un altro.
//! La selezione quindi è operativa sul Classic (dove `hRadio` in
//! `BLUETOOTH_DEVICE_SEARCH_PARAMS` e `bind()` su AF_BTH la rispettano) e per
//! il BLE vale come verifica: se la radio scelta non è quella predefinita lo
//! diciamo a voce alta, invece di far credere che la scansione LE la usi.

use std::mem::size_of;
use std::sync::OnceLock;

/// Una radio Bluetooth locale, con l'indice 1-based con cui viene mostrata
/// nel banner di avvio (lo stesso accettato da `--radio`).
#[derive(Clone, Debug)]
pub struct RadioInfo {
    pub index: usize,
    pub name: String,
    pub address: String,
}

impl RadioInfo {
    /// Etichetta compatta per log e banner: `[2] AA:BB:CC:DD:EE:FF (Nome)`.
    pub fn label(&self) -> String {
        format!("[{}] {} ({})", self.index, self.address, self.name)
    }
}

/// Enumerate the local Bluetooth radios (name + MAC) using the Win32
/// `BluetoothFindFirstRadio` / `BluetoothGetRadioInfo` APIs.
#[cfg(windows)]
pub fn list_radios() -> Vec<RadioInfo> {
    use windows::Win32::Devices::Bluetooth::{
        BluetoothFindFirstRadio, BluetoothFindNextRadio, BluetoothFindRadioClose,
        BluetoothGetRadioInfo, BLUETOOTH_FIND_RADIO_PARAMS, BLUETOOTH_RADIO_INFO,
    };
    use windows::Win32::Foundation::HANDLE;

    let mut out = Vec::new();

    // SAFETY: plain Win32 calls with valid, properly-sized buffers.
    unsafe {
        let params = BLUETOOTH_FIND_RADIO_PARAMS {
            dwSize: size_of::<BLUETOOTH_FIND_RADIO_PARAMS>() as u32,
        };
        let mut radio = HANDLE(std::ptr::null_mut());
        let find = match BluetoothFindFirstRadio(&params, &mut radio) {
            Ok(handle) => handle,
            Err(_) => return out,
        };

        loop {
            let mut info = BLUETOOTH_RADIO_INFO {
                dwSize: size_of::<BLUETOOTH_RADIO_INFO>() as u32,
                ..Default::default()
            };
            if BluetoothGetRadioInfo(radio, &mut info) == 0 {
                out.push(RadioInfo {
                    index: out.len() + 1,
                    name: utf16_to_string(&info.szName),
                    address: address_to_mac(&info.address),
                });
            }

            let mut next = HANDLE(std::ptr::null_mut());
            if BluetoothFindNextRadio(find, &mut next).is_err() {
                break;
            }
            radio = next;
        }

        let _ = BluetoothFindRadioClose(find);
    }

    out
}

#[cfg(not(windows))]
pub fn list_radios() -> Vec<RadioInfo> {
    Vec::new()
}

/// Normalizza un MAC in `AA:BB:CC:DD:EE:FF` (maiuscolo) accettando anche
/// `aa-bb-...`, `aabbccddeeff` e spazi. `None` se non sono esattamente 12
/// cifre esadecimali.
///
/// Delega a `fsx::normalize_mac`: la definizione di "che cos'e' un MAC
/// valido" e' unica nel progetto, altrimenti i file di configurazione
/// (`bt_known.txt`, `ignore.txt`, `is_me.txt`) e la selezione della radio
/// potrebbero accettare MAC diversi per lo stesso input.
pub fn normalize_mac(s: &str) -> Option<String> {
    let mac = crate::fsx::normalize_mac(s);
    if mac.is_empty() {
        None
    } else {
        Some(mac)
    }
}

/// Risolve il selettore di `--radio`: indice 1-based, MAC (`AA:BB:..` o
/// `aabb..`) oppure nome (match esatto o parziale, case-insensitive).
/// L'errore è già pronto per l'utente e spiega cosa era accettato.
pub fn resolve(selector: &str) -> Result<RadioInfo, String> {
    let radios = list_radios();
    let sel = selector.trim();
    if radios.is_empty() {
        return Err("nessuna radio Bluetooth rilevata dal sistema".to_string());
    }

    // 1) Indice 1-based, lo stesso mostrato nel banner di avvio.
    if let Ok(idx) = sel.parse::<usize>() {
        if idx >= 1 && idx <= radios.len() {
            return Ok(radios[idx - 1].clone());
        }
        return Err(format!(
            "indice {idx} fuori intervallo: ci sono {} radio (1..{})",
            radios.len(),
            radios.len()
        ));
    }

    // 2) MAC, in qualunque formato ragionevole.
    if let Some(mac) = normalize_mac(sel) {
        if let Some(r) = radios
            .into_iter()
            .find(|r| r.address.eq_ignore_ascii_case(&mac))
        {
            return Ok(r);
        }
        return Err(format!("nessuna radio con MAC {mac}"));
    }

    // 3) Nome (esatto o parziale, case-insensitive).
    let needle = sel.to_lowercase();
    let matches: Vec<RadioInfo> = radios
        .iter()
        .filter(|r| r.name.to_lowercase().contains(&needle))
        .cloned()
        .collect();
    match matches.len() {
        1 => Ok(matches[0].clone()),
        0 => Err(format!(
            "nessuna radio corrisponde a '{sel}' (usa indice, MAC o nome)"
        )),
        _ => Err(format!(
            "'{sel}' corrisponde a {} radio: usa indice o MAC per scegliere",
            matches.len()
        )),
    }
}

/// Radio attiva per il processo corrente. Viene impostata una sola volta
/// all'avvio (da `main`) e letta da `btclassic` per inquiry e probe.
static SELECTED: OnceLock<Option<RadioInfo>> = OnceLock::new();

/// Registra la radio attiva. Le chiamate successive alla prima sono ignorate:
/// la scelta si fa una volta sola all'avvio.
pub fn set_selected(info: Option<RadioInfo>) {
    let _ = SELECTED.set(info);
}

/// La radio scelta dall'utente (`--radio`). `None` = unica radio rilevata
/// (nessuna scelta da fare) oppure più radio senza selezione: in entrambi i
/// casi vale la radio predefinita di sistema.
pub fn selected() -> Option<&'static RadioInfo> {
    SELECTED.get().and_then(|o| o.as_ref())
}

/// MAC della radio scelta, in forma normalizzata. `None` se non c'è selezione.
pub fn selected_mac() -> Option<String> {
    selected().map(|r| r.address.clone())
}

#[cfg(windows)]
fn utf16_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

#[cfg(windows)]
fn address_to_mac(addr: &windows::Win32::Devices::Bluetooth::BLUETOOTH_ADDRESS) -> String {
    // The radio address is a 64-bit little-endian value; print it MSB-first.
    //
    // SAFETY: `addr` è un riferimento valido a una BLUETOOTH_ADDRESS, e il
    // campo `Anonymous` è un'union di interi copiabili: la lettura non tocca
    // memoria non inizializzata e non ha effetti collaterali.
    let v = unsafe { addr.Anonymous.ullLong };
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        ((v >> 40) & 0xFF) as u8,
        ((v >> 32) & 0xFF) as u8,
        ((v >> 24) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        (v & 0xFF) as u8,
    )
}

/// Apre l'handle della radio con questo MAC, da chiudere con `CloseHandle`.
/// La ricerca usa la stessa enumerazione di `list_radios()`, quindi accetta
/// il MAC nel formato mostrato nel banner di avvio. `None` se la radio non
/// c'è (o è stata rimossa dopo la selezione): in quel caso il chiamante
/// ripiega sulla radio predefinita di sistema.
#[cfg(windows)]
pub fn open_handle_for(mac: &str) -> Option<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::Devices::Bluetooth::{
        BluetoothFindFirstRadio, BluetoothFindNextRadio, BluetoothFindRadioClose,
        BluetoothGetRadioInfo, BLUETOOTH_FIND_RADIO_PARAMS, BLUETOOTH_RADIO_INFO,
    };
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    let want = normalize_mac(mac)?;
    let mut opened: Option<HANDLE> = None;

    // SAFETY: enumerazione Win32 con buffer inizializzati e dimensionati (i
    // `dwSize` sono obbligatori, altrimenti le API rifiutano la chiamata).
    // Ogni handle non scelto viene chiuso prima di proseguire, e l'unico
    // `?` che interrompe presto (il fallimento di `BluetoothFindFirstRadio`)
    // avviene prima che qualsiasi handle venga aperto: nessun handle resta
    // appeso.
    unsafe {
        let params = BLUETOOTH_FIND_RADIO_PARAMS {
            dwSize: size_of::<BLUETOOTH_FIND_RADIO_PARAMS>() as u32,
        };
        let mut radio = HANDLE(std::ptr::null_mut());
        let find = BluetoothFindFirstRadio(&params, &mut radio).ok()?;

        loop {
            let mut info = BLUETOOTH_RADIO_INFO {
                dwSize: size_of::<BLUETOOTH_RADIO_INFO>() as u32,
                ..Default::default()
            };
            if BluetoothGetRadioInfo(radio, &mut info) == 0
                && address_to_mac(&info.address).eq_ignore_ascii_case(&want)
            {
                opened = Some(radio);
                break;
            }

            let mut next = HANDLE(std::ptr::null_mut());
            if BluetoothFindNextRadio(find, &mut next).is_err() {
                let _ = CloseHandle(radio);
                break;
            }
            let _ = CloseHandle(radio);
            radio = next;
        }

        let _ = BluetoothFindRadioClose(find);
    }

    opened
}

/// Converte un MAC normalizzato nel valore a 64 bit usato da `SOCKADDR_BTH`.
#[cfg(windows)]
pub fn mac_to_u64(mac: &str) -> Option<u64> {
    let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 12 {
        return None;
    }
    u64::from_str_radix(&clean, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mac_accetta_formati_diversi() {
        assert_eq!(
            normalize_mac("aa:bb:cc:dd:ee:ff").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            normalize_mac("aabbccddeeff").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            normalize_mac(" 8c:88:2b:31:5b:74 ").as_deref(),
            Some("8C:88:2B:31:5B:74")
        );
    }

    #[test]
    fn normalize_mac_rifiuta_input_invalidi() {
        assert_eq!(normalize_mac(""), None);
        assert_eq!(normalize_mac("aa:bb:cc"), None);
        assert_eq!(normalize_mac("nome-radio"), None);
        assert_eq!(normalize_mac("aabbccddeeff00"), None);
    }

    #[test]
    fn resolve_con_nessuna_radio_e_un_errore_leggibile() {
        // In CI (nessuna radio) l'errore deve essere descrittivo, non un panic.
        if list_radios().is_empty() {
            let e = resolve("1").unwrap_err();
            assert!(e.contains("nessuna radio"), "errore inatteso: {e}");
        }
    }

    #[test]
    fn resolve_rifiuta_indici_fuori_intervallo() {
        if let Some(_first) = list_radios().first() {
            let e = resolve("9999").unwrap_err();
            assert!(e.contains("fuori intervallo"), "errore inatteso: {e}");
        }
    }

    #[test]
    fn label_include_indice_e_indirizzo() {
        let r = RadioInfo {
            index: 2,
            name: "dongle".to_string(),
            address: "AA:BB:CC:DD:EE:FF".to_string(),
        };
        assert_eq!(r.label(), "[2] AA:BB:CC:DD:EE:FF (dongle)");
    }
}
