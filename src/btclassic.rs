//! Active Bluetooth Classic probing (Windows).
//!
//! Phase 2 of the passive/active strategy: while the BLE radio passively
//! collects advertisements, this module actively PAGES the *known* phones
//! (their real Bluetooth Classic MACs, from `bt_known.txt`). A phone with BT
//! on is page-scannable even with the screen off, so a page attempt tells us
//! PRESENT vs ABSENT without the phone advertising anything.
//!
//! Presence semantics (the same rule netmonloc uses for L2):
//! - connect OK / WSAECONNREFUSED / WSAECONNRESET  -> page answered -> PRESENT
//! - WSAETIMEDOUT / WSAEHOSTUNREACH / poll timeout  -> no answer     -> ABSENT
//!
//! The probe is an RFCOMM (AF_BTH) connect on channel 1 with the Serial Port
//! Profile UUID: a pure page + RFCOMM handshake — no pairing, no SDP query,
//! no data exchange. Non-blocking socket + WSAPoll bound the wait per device,
//! and every known device is probed in its own thread (parallel).
//!
//! On non-Windows builds these functions are inert stubs, so the crate still
//! compiles; a future BlueZ/HCI backend can replace them behind the same API.

use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

/// A device we deliberately probe: real BT Classic MAC + readable name + the
/// person it belongs to (from `bt_known.txt`).
#[derive(Clone)]
pub struct KnownBt {
    pub mac: String,
    pub nome: String,
    pub persona: String,
}

/// Outcome of one page probe.
#[derive(Debug)]
pub struct ProbeResult {
    pub mac: String,
    pub present: bool,
    pub detail: String,
    pub elapsed_ms: u64,
}

/// A device discovered by enumeration/inquiry (remembered, authenticated or
/// currently discoverable).
#[derive(Debug, Clone)]
pub struct ClassicDevice {
    pub mac: String,
    pub nome: String,
    pub class_of_device: u32,
    pub flags: String,
}

/// Serial Port Profile UUID 00001101-0000-1000-8000-00805f9b34fb (0x1101).
fn spp_guid() -> windows::core::GUID {
    windows::core::GUID::from_u128(0x0000_1101_0000_1000_8000_0080_5f9b_34fb)
}

/// One-time Winsock initialisation (idempotent).
fn wsa_started() {
    static STARTED: OnceLock<()> = OnceLock::new();
    // SAFETY: WSAStartup scrive una WSADATA nel buffer ricevuto, che qui e' uno
    // MaybeUninit valido e grande quanto la struttura. Non lo leggiamo: il
    // valore di ritorno (0 = successo) basta, e resta valido per tutta la
    // vita del processo. OnceLock garantisce che venga chiamata una volta sola.
    STARTED.get_or_init(|| unsafe {
        use windows::Win32::Networking::WinSock::{WSAStartup, WSADATA};
        let mut data = std::mem::MaybeUninit::<WSADATA>::uninit();
        // MAKEWORD(2,2) = 0x0202
        let _ = WSAStartup(0x0202, data.as_mut_ptr());
    });
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

/// Page a single MAC over RFCOMM channel 1. Blocking, bounded by WSAPoll.
#[cfg(windows)]
fn probe_one(mac: &str) -> ProbeResult {
    use std::mem::size_of;
    use windows::Win32::Devices::Bluetooth::{AF_BTH, BTHPROTO_RFCOMM, SOCKADDR_BTH};
    use windows::Win32::Networking::WinSock::{
        bind, closesocket, connect, ioctlsocket, WSAGetLastError, WSAPoll, WSASocketW, FIONBIO,
        POLLERR, POLLWRNORM, SOCKADDR, SOCK_STREAM, WSAECONNREFUSED, WSAECONNRESET,
        WSAEHOSTUNREACH, WSAETIMEDOUT, WSAEWOULDBLOCK, WSAPOLLFD,
    };

    const PROBE_TIMEOUT_MS: i32 = 8_000;

    let start = Instant::now();
    let el = |s: &str, p: bool| ProbeResult {
        mac: mac.to_string(),
        present: p,
        detail: s.to_string(),
        elapsed_ms: start.elapsed().as_millis() as u64,
    };

    let Some(addr) = mac_to_u64(mac) else {
        return el("bad MAC", false);
    };
    wsa_started();

    // SAFETY: Win32 socket calls with a properly-sized SOCKADDR_BTH.
    let sock = match unsafe {
        WSASocketW(
            AF_BTH as i32,
            SOCK_STREAM.0,
            BTHPROTO_RFCOMM as i32,
            None,
            0,
            0,
        )
    } {
        Ok(s) => s,
        Err(e) => return el(&format!("socket() failed: {e}"), false),
    };
    if sock.is_invalid() {
        return el("socket() failed (invalid)", false);
    }

    // Non-blocking so the page wait is bounded by WSAPoll, not the OS stack.
    let mut one: u32 = 1;
    // SAFETY: `sock` e' un socket appena creato e ancora aperto; ioctlsocket
    // con FIONBIO scrive un u32 nel puntatore ricevuto, che qui e' valido e
    // vive piu' della chiamata. Un errore e' ignorato di proposito: il socket
    // resta utilizzabile in modalita' bloccante, solo piu' lento.
    unsafe {
        let _ = ioctlsocket(sock, FIONBIO, &mut one);
    }

    // Se l'utente ha scelto una radio con --radio, leghiamo il socket a
    // quell'adattatore locale: su AF_BTH è il `bind` a fissare la radio
    // sorgente (senza bind la pagina partirebbe da quella predefinita).
    if let Some(local) = crate::radio::selected().and_then(|r| crate::radio::mac_to_u64(&r.address))
    {
        let local_sa = SOCKADDR_BTH {
            addressFamily: AF_BTH,
            btAddr: local,
            serviceClassId: windows::core::GUID::from_u128(0),
            port: 0,
        };
        // SAFETY: stesso layout SOCKADDR_BTH, dimensionato correttamente.
        let rc = unsafe {
            bind(
                sock,
                &local_sa as *const SOCKADDR_BTH as *const SOCKADDR,
                size_of::<SOCKADDR_BTH>() as i32,
            )
        };
        if rc != 0 {
            // Non fatale: si prova comunque, con la radio predefinita.
            static BIND_WARNED: OnceLock<()> = OnceLock::new();
            BIND_WARNED.get_or_init(|| {
                crate::be!(
                    "[BLUESNIFF] btclassic: bind sulla radio locale fallito, uso la predefinita"
                );
            });
        }
    }

    let sa = SOCKADDR_BTH {
        addressFamily: AF_BTH,
        btAddr: addr,
        serviceClassId: spp_guid(),
        port: 1,
    };
    // SAFETY: the BTH address is cast to the generic SOCKADDR pointer; the
    // stack reads the address family first, then the BTH-specific layout.
    let rc = unsafe {
        connect(
            sock,
            &sa as *const SOCKADDR_BTH as *const SOCKADDR,
            size_of::<SOCKADDR_BTH>() as i32,
        )
    };

    let detail = if rc == 0 {
        "PRESENT (connected)".to_string()
    } else {
        // SAFETY: WSAGetLastError e' una semplice lettura del thread-local
        // di Winsock, priva di argomenti e di effetti collaterali.
        let err = unsafe { WSAGetLastError() };
        if err == WSAEWOULDBLOCK {
            // Page pending: wait for the connect to complete.
            let mut pfd = WSAPOLLFD {
                fd: sock,
                events: POLLWRNORM | POLLERR,
                revents: Default::default(),
            };
            // SAFETY: `pfd` e' uno stack-alloc valido e WSAPoll non lo
            // conserva oltre la chiamata: scrive solo il campo `revents`
            // dell'unico elemento dell'array di lunghezza 1 che gli passiamo.
            let prc = unsafe { WSAPoll(&mut pfd as *mut WSAPOLLFD, 1, PROBE_TIMEOUT_MS) };
            if prc == 0 {
                "ABSENT (no page response)".to_string()
            } else if prc < 0 {
                // SAFETY: lettura del thread-local, nessun argomento.
                format!("ERR poll ({})", unsafe { WSAGetLastError() }.0)
            } else {
                // connect() again on a non-blocking socket returns the result
                // of the pending connection: 0 = connected, else the error.
                // SAFETY: `sock` e' aperto e `sa` e' uno stack-alloc valido;
                // connect() copia dal buffer senza trattenerlo. Restituisce 0
                // se nel frattempo la connessione e' stata completata.
                let rc2 = unsafe {
                    connect(
                        sock,
                        &sa as *const SOCKADDR_BTH as *const SOCKADDR,
                        size_of::<SOCKADDR_BTH>() as i32,
                    )
                };
                if rc2 == 0 {
                    "PRESENT (connected)".to_string()
                } else {
                    // SAFETY: lettura del thread-local, nessun argomento.
                    let e2 = unsafe { WSAGetLastError() };
                    if e2 == WSAECONNREFUSED || e2 == WSAECONNRESET {
                        "PRESENT (page ok, refused)".to_string()
                    } else if e2 == WSAETIMEDOUT || e2 == WSAEHOSTUNREACH {
                        "ABSENT".to_string()
                    } else {
                        // The page completed (no timeout), so the device is
                        // there even if the RFCOMM channel rejected us.
                        format!("PRESENT (page ok, err {})", e2.0)
                    }
                }
            }
        } else if err == WSAECONNREFUSED || err == WSAECONNRESET {
            "PRESENT (refused)".to_string()
        } else if err == WSAETIMEDOUT || err == WSAEHOSTUNREACH {
            "ABSENT".to_string()
        } else {
            format!("ERR {}", err.0)
        }
    };

    // SAFETY: `sock` e' stato creato qui e non e' mai stato chiuso: questa e'
    // l'unica uscita del percorso, quindi l'handle non resta appeso. L'errore
    // e' ignorato perche' il socket e' comunque abbandonato.
    unsafe {
        let _ = closesocket(sock);
    }
    el(&detail, detail.starts_with("PRESENT"))
}

#[cfg(not(windows))]
fn probe_one(_mac: &str) -> ProbeResult {
    ProbeResult {
        mac: String::new(),
        present: false,
        detail: "no win32 backend".to_string(),
        elapsed_ms: 0,
    }
}

/// Probe every known device in parallel (one std thread each) and return all
/// outcomes. Bounded: every thread waits at most ~8s inside WSAPoll.
pub fn probe_macs(known: &[KnownBt]) -> Vec<ProbeResult> {
    let handles: Vec<_> = known
        .iter()
        .map(|k| {
            let mac = k.mac.clone();
            std::thread::spawn(move || probe_one(&mac))
        })
        .collect();
    handles
        .into_iter()
        .map(|h| {
            h.join().unwrap_or_else(|_| ProbeResult {
                mac: "?".to_string(),
                present: false,
                detail: "probe thread panicked".to_string(),
                elapsed_ms: 0,
            })
        })
        .collect()
}

fn bt_addr_to_mac(addr: &windows::Win32::Devices::Bluetooth::BLUETOOTH_ADDRESS) -> String {
    // The address is a 64-bit little-endian value; print it MSB-first.
    //
    // SAFETY: `addr` e' un riferimento valido a una BLUETOOTH_ADDRESS e
    // `Anonymous` e' un'union di interi copiabili: lettura pura, senza
    // accesso a memoria non inizializzata ne' effetti collaterali.
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

fn utf16_trim(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end]).trim().to_string()
}

fn bool_str(b: windows::core::BOOL, tag: &str) -> String {
    if b.as_bool() {
        format!(" {tag}")
    } else {
        String::new()
    }
}

fn enumerate_devices(issue_inquiry: bool, timeout_mult: u8) -> Vec<ClassicDevice> {
    // Se l'utente ha scelto una radio con --radio, apriamo l'handle di quella
    // radio e lo passiamo come `hRadio`: l'inquiry (e la lettura dei
    // dispositivi ricordati) parte da lì. Senza selezione l'handle resta
    // NULL, che per lo stack significa "radio predefinita di sistema".
    let handle = selected_radio_handle();
    // Handle NULL = radio predefinita di sistema.
    let h_radio = handle.unwrap_or(windows::Win32::Foundation::HANDLE(std::ptr::null_mut()));
    let out = enumerate_devices_on(issue_inquiry, timeout_mult, h_radio);
    if let Some(h) = handle {
        // SAFETY: handle aperto da `radio::open_handle_for`, non più in uso.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(h);
        }
    }
    out
}

/// Apre l'handle della radio scelta con `--radio`, da chiudere con
/// `CloseHandle`. `None` = usa la radio predefinita (nessuna selezione,
/// oppure la radio scelta non è più disponibile).
fn selected_radio_handle() -> Option<windows::Win32::Foundation::HANDLE> {
    let mac = crate::radio::selected_mac()?;
    match crate::radio::open_handle_for(&mac) {
        Some(h) => {
            // L'adapter e' stato aperto: da qui in poi "assente" non puo'
            // piu' significare "non l'ho mai trovato", ma "l'ho perso".
            crate::radiostate::note_radio_ready();
            Some(h)
        }
        None => {
            // Avvisa una sola volta: poi si continua con la predefinita.
            static WARNED: OnceLock<()> = OnceLock::new();
            WARNED.get_or_init(|| {
                crate::be!(
                    "[BLUESNIFF] btclassic: radio selezionata {mac} non disponibile, uso la predefinita"
                );
            });
            None
        }
    }
}

/// Enumerazione su una radio specifica: `h_radio` NULL significa la radio
/// predefinita di sistema.
fn enumerate_devices_on(
    issue_inquiry: bool,
    timeout_mult: u8,
    h_radio: windows::Win32::Foundation::HANDLE,
) -> Vec<ClassicDevice> {
    use std::mem::size_of;
    use windows::Win32::Devices::Bluetooth::{
        BluetoothFindDeviceClose, BluetoothFindFirstDevice, BluetoothFindNextDevice,
        BLUETOOTH_DEVICE_INFO, BLUETOOTH_DEVICE_SEARCH_PARAMS,
    };

    let mut out = Vec::new();
    // SAFETY: enumerazione Win32 con strutture inizializzate e dimensionate
    // (i `dwSize` sono obbligatori, altrimenti le API rifiutano la chiamata).
    // L'handle di ricerca viene sempre chiuso con BluetoothFindDeviceClose e
    // i buffer vivono fino alla fine del blocco, quindi nessun puntatore
    // fuggisce.
    unsafe {
        let mut info = BLUETOOTH_DEVICE_INFO {
            dwSize: size_of::<BLUETOOTH_DEVICE_INFO>() as u32,
            ..Default::default()
        };
        let params = BLUETOOTH_DEVICE_SEARCH_PARAMS {
            dwSize: size_of::<BLUETOOTH_DEVICE_SEARCH_PARAMS>() as u32,
            fReturnAuthenticated: true.into(),
            fReturnRemembered: true.into(),
            fReturnUnknown: issue_inquiry.into(),
            fReturnConnected: true.into(),
            fIssueInquiry: issue_inquiry.into(),
            cTimeoutMultiplier: timeout_mult,
            hRadio: h_radio,
        };
        let find = match BluetoothFindFirstDevice(&params, &mut info) {
            Ok(h) => h,
            Err(_) => return out,
        };
        loop {
            out.push(ClassicDevice {
                mac: bt_addr_to_mac(&info.Address),
                nome: utf16_trim(&info.szName),
                class_of_device: info.ulClassofDevice,
                flags: format!(
                    "{}{}{}",
                    bool_str(info.fConnected, "con"),
                    bool_str(info.fAuthenticated, "auth"),
                    bool_str(info.fRemembered, "rem"),
                ),
            });
            if out.len() >= 128 {
                break;
            }
            let mut next = BLUETOOTH_DEVICE_INFO {
                dwSize: size_of::<BLUETOOTH_DEVICE_INFO>() as u32,
                ..Default::default()
            };
            if BluetoothFindNextDevice(find, &mut next).is_err() {
                break;
            }
            info = next;
        }
        let _ = BluetoothFindDeviceClose(find);
    }
    out
}

#[cfg(windows)]
/// Devices the OS remembers (paired/authenticated/connected before): the
/// natural bootstrap for `bt_known.txt`.
pub fn remembered_devices() -> Vec<ClassicDevice> {
    enumerate_devices(false, 0)
}

#[cfg(not(windows))]
pub fn remembered_devices() -> Vec<ClassicDevice> {
    Vec::new()
}

#[cfg(windows)]
/// Run an active inquiry (GIAC) for the given number of 1.28 s time slices
/// (~6.4 s with multiplier 5). Returns the devices that answered, with their
/// names when Windows resolved them.
pub fn inquiry(timeout_mult: u8) -> Vec<ClassicDevice> {
    enumerate_devices(true, timeout_mult)
}

#[cfg(not(windows))]
pub fn inquiry(_timeout_mult: u8) -> Vec<ClassicDevice> {
    Vec::new()
}

pub fn looks_like_mac(s: &str) -> bool {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex.len() == 12
}

/// Parse `bt_known.txt` (`BTMAC;Nome;Persona`, one per line, `#` comments).
pub fn load_bt_known(path: &Path) -> Vec<KnownBt> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("BTMAC") {
            continue;
        }
        let parts: Vec<&str> = line.split(';').collect();
        let mac = parts[0].trim().to_uppercase();
        if !looks_like_mac(&mac) {
            continue;
        }
        out.push(KnownBt {
            mac,
            nome: parts
                .get(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
            persona: parts
                .get(2)
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
        });
    }
    out
}

/// Write the bootstrap `bt_known.txt` from the remembered devices (Persona
/// left empty for the user to fill in).
pub fn write_bootstrap(path: &Path, devices: &[ClassicDevice]) {
    let mut text = String::from("# BTMAC;Nome;Persona  (fill in the Persona column)\n");
    for d in devices {
        text.push_str(&format!("{};{};\n", d.mac, d.nome));
    }
    let _ = std::fs::write(path, text);
}
