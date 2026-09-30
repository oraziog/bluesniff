use std::collections::HashMap;
use std::error::Error;

use btleplug::api::{
    AddressType, BDAddr, Central, CentralState, CharPropFlags, Manager as _, Peripheral as _,
    ScanFilter,
};
use btleplug::platform::Manager;

use crate::logging::Logger;

pub struct BleDevice {
    pub mac: String,
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub vendor: Option<String>,
    pub hint: Option<String>,
    /// Stable identity from the advertisement (manufacturer payload / service
    /// UUIDs). Survives the MAC rotation that BLE privacy imposes.
    pub fingerprint: Option<String>,
    /// Google Fast Pair Model ID (0xFE2C service data, first 3 bytes BE):
    /// identifies the exact product model (e.g. 13911719 = Sony WH-1000XM5),
    /// used to warn about known CVEs (WhisperPair, CVE-2025-36911).
    pub model_id: Option<u32>,
}

pub async fn scan(logger: &Logger) -> Result<(), Box<dyn Error>> {
    scan_collect(logger).await.map(|_| ())
}

/// Scan and return the discovered devices (while still printing them).
pub async fn scan_collect(logger: &Logger) -> Result<Vec<BleDevice>, Box<dyn Error>> {
    let manager = Manager::new()
        .await
        .map_err(|e| log_err(logger, "creating manager", e))?;

    let adapters = manager
        .adapters()
        .await
        .map_err(|e| log_err(logger, "listing adapters", e))?;
    logger.log(&format!("found {} adapter(s)", adapters.len()));

    if adapters.is_empty() {
        logger.log("no Bluetooth adapter available, aborting scan");
        crate::bn!(
            "\x1b[31m[BLUESNIFF]\x1b[0m No Bluetooth adapter found. Make sure Bluetooth is enabled and at least one adapter is connected."
        );
        return Ok(Vec::new());
    }

    for (i, adapter) in adapters.iter().enumerate() {
        let info = adapter.adapter_info().await.unwrap_or_else(|e| {
            logger.log(&format!("adapter[{}] info error: {e}", i + 1));
            "unknown".to_string()
        });
        let state = adapter.adapter_state().await.unwrap_or_else(|e| {
            logger.log(&format!("adapter[{}] state error: {e}", i + 1));
            CentralState::Unknown
        });
        logger.log(&format!(
            "adapter[{}] info={} state={}",
            i + 1,
            info,
            central_state_name(&state)
        ));
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m   [{}] {} (state: {})",
            i + 1,
            info,
            central_state_name(&state)
        );
    }

    for (i, adapter) in adapters.iter().enumerate() {
        logger.log(&format!("starting scan on adapter[{}]", i + 1));
        adapter
            .start_scan(ScanFilter::default())
            .await
            .map_err(|e| log_err(logger, "start_scan", e))?;
    }

    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Scanning for Bluetooth devices...");
    logger.log("scanning for 5 seconds");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    logger.log("scan window complete, collecting peripherals");

    let mut devices: HashMap<String, BleDevice> = HashMap::new();
    for (i, adapter) in adapters.iter().enumerate() {
        let peripherals = adapter
            .peripherals()
            .await
            .map_err(|e| log_err(logger, "peripherals", e))?;
        logger.log(&format!(
            "adapter[{}] reported {} peripheral(s)",
            i + 1,
            peripherals.len()
        ));
        for peripheral in peripherals {
            let addr = peripheral.address();
            let properties = peripheral
                .properties()
                .await
                .map_err(|e| log_err(logger, "properties", e))?;

            let name = properties.as_ref().and_then(|p| p.local_name.clone());
            let rssi = properties.as_ref().and_then(|p| p.rssi);
            let tx_power = properties.as_ref().and_then(|p| p.tx_power_level);
            let address_type = properties.as_ref().and_then(|p| p.address_type);
            let class = properties.as_ref().and_then(|p| p.class);
            let manufacturer = properties
                .as_ref()
                .map(|p| p.manufacturer_data.clone())
                .unwrap_or_default();
            let services = properties
                .as_ref()
                .map(|p| p.services.clone())
                .unwrap_or_default();
            let service_data = properties
                .as_ref()
                .map(|p| p.service_data.clone())
                .unwrap_or_default();

            let mut manufacturer_ids: Vec<u16> = manufacturer.keys().copied().collect();
            manufacturer_ids.sort_unstable();
            let vendor = manufacturer_ids
                .iter()
                .find_map(|&id| company_name(id))
                .map(|n| n.to_string());

            let hint = classify(&manufacturer, &services, &service_data);
            let fingerprint = stable_fingerprint(&manufacturer, &services, &service_data);

            logger.log(&format!(
                "device {} name={:?} rssi={:?} tx_power={:?} address_type={} class={:?} vendor_hint={:?} device_hint={:?} manufacturer={} services={} service_data={}",
                addr,
                name,
                rssi,
                tx_power,
                address_type_name(address_type),
                class,
                vendor,
                hint,
                fmt_manufacturer(&manufacturer),
                fmt_services(&services),
                fmt_service_data_keys(&service_data),
            ));

            let mac = addr.to_string();
            let hint_label = hint.as_ref().map(|(s, _)| s.clone());
            devices.entry(mac.clone()).or_insert(BleDevice {
                mac,
                name,
                rssi,
                vendor,
                hint: hint_label,
                fingerprint,
                model_id: fastpair_model_id(&service_data),
                // btleplug non espone i flags AD 0x01: la connettibilità
                // arriva dal path WinRT (blewatcher), qui resta sconosciuta.
            });
        }
    }

    let mut list: Vec<BleDevice> = devices.into_values().collect();
    list.sort_by(|a, b| a.mac.cmp(&b.mac));

    if list.is_empty() {
        logger.log("no devices detected across all adapters");
        crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m No devices detected.");
    } else {
        logger.log(&format!("{} unique device(s) detected", list.len()));
        for d in &list {
            crate::bn!(
                "\x1b[34m[BLUESNIFF]\x1b[0m Address: \x1b[33m{}\x1b[0m, Name: \x1b[36m{}\x1b[0m, RSSI: {}, Vendor: {}, Type: {}",
                d.mac,
                d.name.as_deref().unwrap_or("<none>"),
                d.rssi
                    .map(|v| format!("{v} dBm"))
                    .unwrap_or_else(|| "-".to_string()),
                d.vendor.as_deref().unwrap_or("-"),
                d.hint.as_deref().unwrap_or("-"),
            );
            if let Some(mid) = d.model_id {
                crate::bn!("    Model ID Fast Pair: \x1b[33m{mid}\x1b[0m");
            }
        }
    }

    Ok(list)
}

/// Connect to a specific device and enumerate its GATT services/characteristics,
/// attempting to read the standard Battery Level characteristic if present.
pub async fn inspect(logger: &Logger, mac: &str) -> Result<(), Box<dyn Error>> {
    let target: BDAddr = match mac.parse() {
        Ok(addr) => addr,
        Err(e) => {
            logger.log(&format!("invalid MAC '{mac}': {e}"));
            crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m Invalid MAC address '{mac}': {e}");
            return Ok(());
        }
    };

    let manager = Manager::new()
        .await
        .map_err(|e| log_err(logger, "creating manager", e))?;
    let adapters = manager
        .adapters()
        .await
        .map_err(|e| log_err(logger, "listing adapters", e))?;
    if adapters.is_empty() {
        logger.log("no Bluetooth adapter available");
        crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m No Bluetooth adapter found.");
        return Ok(());
    }
    let adapter = &adapters[0];

    logger.log(&format!("starting scan to locate {mac}"));
    adapter
        .start_scan(ScanFilter::default())
        .await
        .map_err(|e| log_err(logger, "start_scan", e))?;

    let mut peripheral = None;
    for attempt in 1..=6 {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let peripherals = adapter
            .peripherals()
            .await
            .map_err(|e| log_err(logger, "peripherals", e))?;
        if let Some(p) = peripherals.into_iter().find(|p| p.address() == target) {
            peripheral = Some(p);
            break;
        }
        logger.log(&format!("target not seen yet (attempt {attempt})"));
    }

    let Some(peripheral) = peripheral else {
        let _ = adapter.stop_scan().await;
        logger.log(&format!("device {mac} not seen in the scan window"));
        crate::bn!(
            "\x1b[31m[BLUESNIFF]\x1b[0m Device {mac} not seen. BLE addresses rotate: re-scan and pass the current address."
        );
        return Ok(());
    };

    let _ = adapter.stop_scan().await;

    if let Ok(Some(props)) = peripheral.properties().await {
        logger.log(&format!(
            "target properties name={:?} rssi={:?} address_type={:?}",
            props.local_name, props.rssi, props.address_type
        ));
        crate::bn!(
            "\x1b[34m[BLUESNIFF]\x1b[0m Target: {} (name: {}, RSSI: {:?})",
            target,
            props.local_name.as_deref().unwrap_or("<none>"),
            props.rssi
        );
    }

    logger.log(&format!("connecting to {target}"));
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Connecting to {target} ...");
    if let Err(e) = peripheral.connect().await {
        logger.log(&format!("connect failed: {e}"));
        crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m Connect failed: {e}");
        return Ok(());
    }
    logger.log("connected");
    crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Connected.");

    let mut readable: Vec<btleplug::api::Characteristic> = Vec::new();

    match peripheral.discover_services().await {
        Ok(()) => {
            let services = peripheral.services();
            logger.log(&format!("discovered {} service(s)", services.len()));
            crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m {} service(s):", services.len());
            for service in &services {
                logger.log(&format!(
                    "service {} primary={}",
                    service.uuid, service.primary
                ));
                crate::bn!("  Service {} (primary: {})", service.uuid, service.primary);
                for ch in &service.characteristics {
                    logger.log(&format!(
                        "    characteristic {} props={:?}",
                        ch.uuid, ch.properties
                    ));
                    crate::bn!("    - {} [{:?}]", ch.uuid, ch.properties);
                    if ch.properties.contains(CharPropFlags::READ) {
                        readable.push(ch.clone());
                    }
                }
            }
        }
        Err(e) => {
            logger.log(&format!("discover_services failed: {e}"));
            crate::bn!("\x1b[31m[BLUESNIFF]\x1b[0m Service discovery failed: {e}");
        }
    }

    for ch in &readable {
        match peripheral.read(ch).await {
            Ok(value) => {
                if is_battery_uuid(&ch.uuid) {
                    let level = value.first().copied().unwrap_or(0);
                    logger.log(&format!(
                        "read {} (battery) = {level}% raw={:?}",
                        ch.uuid, value
                    ));
                    crate::bn!("    Battery: {level}%");
                } else if is_device_name_uuid(&ch.uuid) {
                    let name = ascii_or_hex(&value);
                    logger.log(&format!("read {} (device name) = {name}", ch.uuid));
                    crate::bn!("    Device Name: {name}");
                } else {
                    let text = ascii_or_hex(&value);
                    logger.log(&format!(
                        "read {} = {} ({} bytes)",
                        ch.uuid,
                        text,
                        value.len()
                    ));
                    crate::bn!("    read {} = {} ({} bytes)", ch.uuid, text, value.len());
                }
            }
            Err(e) => {
                logger.log(&format!("read {} failed: {e}", ch.uuid));
                crate::bn!("    read {} failed: {e}", ch.uuid);
            }
        }
    }

    match peripheral.disconnect().await {
        Ok(()) => {
            logger.log("disconnected");
            crate::bn!("\x1b[34m[BLUESNIFF]\x1b[0m Disconnected.");
        }
        Err(e) => {
            logger.log(&format!("disconnect failed: {e}"));
        }
    }

    Ok(())
}

fn log_err<E: std::fmt::Display>(logger: &Logger, context: &str, error: E) -> E {
    logger.log(&format!("ERROR {context}: {error}"));
    error
}

fn central_state_name(state: &CentralState) -> &'static str {
    match state {
        CentralState::Unknown => "unknown",
        CentralState::PoweredOn => "powered on",
        CentralState::PoweredOff => "powered off",
    }
}

fn address_type_name(t: Option<AddressType>) -> &'static str {
    match t {
        Some(AddressType::Public) => "public",
        Some(AddressType::Random) => "random",
        None => "none",
    }
}

/// Stable identity hint built from the advertisement content itself, not the
/// (rotating) MAC. Prefers the manufacturer payload (company ID + bytes — the
/// part observed to stay constant across scans, e.g. Samsung SmartThings
/// Find), then falls back to the first announced service UUID.
pub fn stable_fingerprint<S: ToString>(
    manufacturer: &HashMap<u16, Vec<u8>>,
    services: &[S],
    service_data: &HashMap<S, Vec<u8>>,
) -> Option<String> {
    let mut ids: Vec<u16> = manufacturer.keys().copied().collect();
    ids.sort_unstable();
    if let Some(&id) = ids.first() {
        let payload = &manufacturer[&id];
        return Some(format!("mfr:{id:04X}:{}", hex_str(payload, 64)));
    }
    if let Some(first) = services.first() {
        return Some(format!("svc:{}", ToString::to_string(first)));
    }
    if let Some((k, _)) = service_data.iter().next() {
        return Some(format!("svcdata:{}", ToString::to_string(k)));
    }
    None
}

/// Google Fast Pair Model ID from the 0xFE2C service data: the first three
/// bytes of the payload are the Model ID (big-endian 24-bit) identifying the
/// exact product model (see the WhisperPair dataset / Fast Pair Model IDs
/// list). None when the key or payload is missing.
pub fn fastpair_model_id<S: ToString>(service_data: &HashMap<S, Vec<u8>>) -> Option<u32> {
    let payload = service_data
        .iter()
        .find(|(k, _)| u16_uuid_matches(*k, 0xFE2C))
        .map(|(_, v)| v.as_slice())?;
    if payload.len() < 3 {
        return None;
    }
    Some(((payload[0] as u32) << 16) | ((payload[1] as u32) << 8) | (payload[2] as u32))
}

/// Indica se l'annuncio appartiene a una famiglia "popup/spoof" oppure di
/// "tracker" — i payload usati dai phantom BLE advertisement (Bluetooth-LE-
/// Spam, Flipper Zero) e dai localizzatori commerciali (AirTag, Tile,
/// Chipolo, Pebblebee, Samsung SmartTag, Google Find My Device Network):
/// Apple Continuity ProximityPair "New Device" (0x004C/0x07), Apple Find My
/// (0x004C/0x12 — AirTag e accessori), Microsoft Swift Pair (0x0006 tipo
/// 0x01 o prefisso 03 00 80), Samsung Easy Setup (0x0075 payload che inizia
/// con 42 09), Samsung SmartTag (0xFD5A service data 0x10-prefisso),
/// Samsung Find My Mobile (0xFD69), Chipolo (0xFE33), Pebblebee (0xFA25),
/// Google Find My Device Network (0xFEAA frame type 0x40/0x41), Tile
/// (0xFEED) e Google Fast Pair (0xFE2C).
/// Ritorna una breve etichetta del tipo o None per gli annunci normali.
/// NB: la presenza di UNO di questi annunci NON significa spam — il
/// rilevamento del vero spammer usa la quantità (burst) e gli indizi di
/// rotazione MAC (`spam::`), non il singolo pacchetto.
pub fn phantom_kind<S: ToString>(
    manufacturer: &HashMap<u16, Vec<u8>>,
    services: &[S],
    service_data: &HashMap<S, Vec<u8>>,
) -> Option<&'static str> {
    if let Some(payload) = manufacturer.get(&0x004C) {
        match payload.first() {
            Some(0x07) => return Some("apple-popup"),
            // 0x12 = payload non connesso della rete Find My (AirTag, Chipolo
            // ONE Spot, Pebblebee Find My...), come da AirGuard/OpenHaystack.
            Some(0x12) => return Some("apple-findmy"),
            _ => {}
        }
    }
    if let Some(payload) = manufacturer.get(&0x0006) {
        let is_swift = payload.first() == Some(&0x01)
            || (payload.len() >= 3 && payload[..3] == [0x03, 0x00, 0x80]);
        if is_swift {
            return Some("swift-pair");
        }
    }
    if let Some(payload) = manufacturer.get(&0x0075) {
        if payload.len() >= 2 && payload[0] == 0x42 && payload[1] == 0x09 {
            return Some("samsung-easysetup");
        }
    }
    // Samsung SmartTag / SmartTag+ / SmartTag 2 / Solum: servizio di
    // localizzazione offline 0xFD5A con service data 0x10-prefisso
    // (mask 0xF8, come il filtro di AirGuard).
    if let Some(d) = service_data_for(service_data, 0xFD5A) {
        if d.first().is_some_and(|b| b & 0xF8 == 0x10) {
            return Some("samsung-smarttag");
        }
    }
    // Samsung Find My Mobile (beacon SmartThings Find): servizio 0xFD69.
    if has_service(services, 0xFD69) || has_service_data(service_data, 0xFD69) {
        return Some("samsung-fmm");
    }
    // Chipolo (app Chipolo): servizio 0xFE33.
    if has_service(services, 0xFE33) || has_service_data(service_data, 0xFE33) {
        return Some("chipolo");
    }
    // Pebblebee (app Pebblebee): servizio 0xFA25.
    if has_service(services, 0xFA25) || has_service_data(service_data, 0xFA25) {
        return Some("pebblebee");
    }
    // Google Find My Device Network (Chipolo One Point, Pebblebee, Motorola,
    // Hama, Eufy, Jio, Rolling Square): service data 0xFEAA con frame type
    // 0x40 (normale) o 0x41 (protezione anti-stalking, MAC fisso 24 h).
    // NB: 0xFEAA è anche Eddystone (primo byte 0x00/0x10/0x20/0x30): il primo
    // byte del payload distingue le due cose (spec Google FHN).
    if let Some(d) = service_data_for(service_data, 0xFEAA) {
        if matches!(d.first(), Some(0x40) | Some(0x41)) {
            return Some("google-findmy");
        }
    }
    // Tile tracker: service UUID 0xFEED (riferimento reelyActive/Sniffypedia).
    if has_service(services, 0xFEED) || has_service_data(service_data, 0xFEED) {
        return Some("tile");
    }
    if has_service(services, 0xFE2C) || has_service_data(service_data, 0xFE2C) {
        return Some("fast-pair");
    }
    None
}

/// Tx Power dichiarata nel payload iBeacon Apple (0x004C): il byte 22
/// (measured power, dBm) dopo uuid/major/minor. Ritorna None se l'annuncio
/// non è un iBeacon o il payload è troppo corto. Usata come riferimento di
/// distanza quando l'AD type 0x0A (Tx Power Level) non è annunciato.
pub fn apple_ibeacon_tx(manufacturer: &HashMap<u16, Vec<u8>>) -> Option<i8> {
    let payload = manufacturer.get(&0x004C)?;
    if payload.len() >= 23 && payload[0] == 0x02 && payload[1] == 0x15 {
        Some(payload[22] as i8)
    } else {
        None
    }
}

/// Best-effort classification from the advertisement. Returns a human-readable
/// hint plus a confidence in 0..1 (same spirit as netmonloc's fingerprint_hint).
pub(crate) fn classify<S: ToString>(
    manufacturer: &HashMap<u16, Vec<u8>>,
    services: &[S],
    service_data: &HashMap<S, Vec<u8>>,
) -> Option<(String, f32)> {
    if let Some(payload) = manufacturer.get(&0x004C) {
        // iBeacon: 0x02 0x15 + 16B uuid + 2B major + 2B minor + 1B measured power.
        if payload.len() >= 23 && payload[0] == 0x02 && payload[1] == 0x15 {
            let uuid = uuid_str(&payload[2..18]);
            let major = u16::from_be_bytes([payload[18], payload[19]]);
            let minor = u16::from_be_bytes([payload[20], payload[21]]);
            let tx = payload[22] as i8;
            return Some((
                format!("Apple iBeacon (uuid={uuid}, major={major}, minor={minor}, tx={tx} dBm)"),
                0.95,
            ));
        }
        // Apple Nearby (AirDrop/Continuity discovery) vs Find My accessories.
        if let Some(&first) = payload.first() {
            if first == 0x10 {
                return Some(("Apple device — AirDrop/Nearby".to_string(), 0.9));
            }
            if first == 0x12 {
                return Some(("Apple Find My accessory".to_string(), 0.9));
            }
            // ProximityPair type 0x07 with the "New Device" prefix is the
            // advertisement used by the phantom/==spoof== popups (the BLE-Spam
            // attack, Flipper Zero etc). A single one is not necessarily a
            // spammer (real Apple devices in pairing mode use it too), so the
            // hint is an honest flag, not a verdict.
            if first == 0x07 {
                let prefix = payload.get(2);
                let kind = match prefix {
                    Some(0x07) => "popup New Device (phantom)",
                    Some(0x01) => "popup Not Your Device",
                    Some(0x05) => "popup Action Modal",
                    _ => "proximity-pair",
                };
                return Some((format!("Apple Continuity — {kind}"), 0.7));
            }
        }
    }

    if let Some(payload) = manufacturer.get(&0x0006) {
        // Swift Pair / Nearby Share: Microsoft company ID with type byte 0x01.
        if let Some(&first) = payload.first() {
            if first == 0x01 {
                return Some((
                    "Microsoft device — Swift Pair / Nearby Share".to_string(),
                    0.75,
                ));
            }
        }
        return Some(("Microsoft device".to_string(), 0.6));
    }

    if manufacturer.contains_key(&0x0075) {
        return Some((
            "Samsung device — SmartThings Find (Galaxy phone or SmartTag)".to_string(),
            0.8,
        ));
    }

    if has_service(services, 0xFEAA) || has_service_data(service_data, 0xFEAA) {
        let frame = service_data
            .iter()
            .find(|(k, _)| u16_uuid_matches(*k, 0xFEAA))
            .and_then(|(_, v)| v.first())
            .map(|&b| match b {
                0x00 => "UID",
                0x10 => "URL",
                0x20 => "TLM",
                0x30 => "EID",
                _ => "unknown",
            })
            .unwrap_or("unknown");
        return Some((format!("Google Eddystone-{frame}"), 0.9));
    }

    if has_service(services, 0xFE2C) {
        return Some(("Google Fast Pair device".to_string(), 0.85));
    }

    if has_service(services, 0xFD6F) {
        return Some(("Exposure Notification (GAEN)".to_string(), 0.9));
    }

    // FEF3 / FCF1 are Apple's Continuity UUIDs, but the UUID alone is NOT a
    // reliable Apple fingerprint: many Android phones (incl. Motorola) include
    // them in their BLE advertisements. Only label "Apple device" when the
    // strong Apple manufacturer signature (0x004C, handled above) is present;
    // otherwise flag the advertisement as merely Apple-like, low confidence.
    if has_service(services, 0xFEF3) || has_service_data(service_data, 0xFEF3) {
        return Some(("Apple-like — UUID Continuity (FEF3)".to_string(), 0.35));
    }

    if has_service(services, 0xFCF1) || has_service_data(service_data, 0xFCF1) {
        return Some(("Apple-like — UUID Continuity (FCF1)".to_string(), 0.35));
    }

    None
}

/// Ritorna il payload del service data per lo UUID 16-bit richiesto,
/// se presente (le chiavi della mappa possono essere UUID completi).
fn service_data_for<S: ToString>(data: &HashMap<S, Vec<u8>>, id: u16) -> Option<&Vec<u8>> {
    data.iter()
        .find(|(u, _)| u16_uuid_matches(*u, id))
        .map(|(_, v)| v)
}

fn has_service<S: ToString>(services: &[S], id: u16) -> bool {
    services.iter().any(|u| u16_uuid_matches(u, id))
}

fn has_service_data<S: ToString>(data: &HashMap<S, Vec<u8>>, id: u16) -> bool {
    data.keys().any(|u| u16_uuid_matches(u, id))
}

fn u16_uuid_matches<T: ToString>(u: &T, id: u16) -> bool {
    let target = format!("0000{id:04x}-0000-1000-8000-00805f9b34fb");
    ToString::to_string(u).eq_ignore_ascii_case(&target)
}

fn fmt_manufacturer(data: &HashMap<u16, Vec<u8>>) -> String {
    if data.is_empty() {
        return "none".to_string();
    }
    let mut ids: Vec<u16> = data.keys().copied().collect();
    ids.sort_unstable();
    ids.iter()
        .map(|&id| {
            let vendor = company_name(id)
                .map(|n| format!("({n})"))
                .unwrap_or_default();
            let payload = &data[&id];
            format!(
                "0x{id:04X}{vendor}[{}B]={}",
                payload.len(),
                hex_str(payload, 32)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn fmt_services<T: ToString>(services: &[T]) -> String {
    if services.is_empty() {
        return "none".to_string();
    }
    let shown = services
        .iter()
        .take(8)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if services.len() > 8 {
        format!("{shown},…({} total)", services.len())
    } else {
        shown
    }
}

fn fmt_service_data_keys<T: ToString>(data: &HashMap<T, Vec<u8>>) -> String {
    if data.is_empty() {
        return "none".to_string();
    }
    let mut keys: Vec<String> = data.keys().map(ToString::to_string).collect();
    keys.sort();
    keys.join(",")
}

fn hex_str(bytes: &[u8], max: usize) -> String {
    let truncated = bytes.len() > max;
    let shown = &bytes[..bytes.len().min(max)];
    let mut s = shown.iter().map(|b| format!("{b:02X}")).collect::<String>();
    if truncated {
        s.push('…');
    }
    s
}

fn uuid_str(bytes: &[u8]) -> String {
    let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn is_battery_uuid<T: ToString>(u: &T) -> bool {
    let target = "00002a19-0000-1000-8000-00805f9b34fb";
    ToString::to_string(u).eq_ignore_ascii_case(target)
}

fn is_device_name_uuid<T: ToString>(u: &T) -> bool {
    let target = "00002a00-0000-1000-8000-00805f9b34fb";
    ToString::to_string(u).eq_ignore_ascii_case(target)
}

fn ascii_or_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }
    if bytes.iter().all(|b| (0x20..=0x7E).contains(b)) {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        hex_str(bytes, 64)
    }
}

pub(crate) fn company_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0002 => "Intel",
        0x0006 => "Microsoft",
        0x004C => "Apple",
        0x0059 => "Nordic Semiconductor",
        0x0075 => "Samsung",
        0x00E0 => "Google",
        0x012D => "Sony",
        0x0131 => "Huawei",
        0x027D => "Fitbit",
        0x02E5 => "Espressif",
        _ => return None,
    })
}

/// Read the GATT Device Name (0x2A00) of a connected peripheral. Most phones
/// hide their name from the BLE advertisement but expose it here — e.g. a
/// Samsung Galaxy reads back "Galaxy A41 di Salvatore". Returns None when the
/// device does not expose a readable name.
async fn read_device_name(
    peripheral: &btleplug::platform::Peripheral,
) -> Result<Option<String>, Box<dyn Error>> {
    peripheral.connect().await?;

    let name = match peripheral.discover_services().await {
        Ok(()) => {
            let mut found: Option<String> = None;
            for service in peripheral.services() {
                for ch in &service.characteristics {
                    if is_device_name_uuid(&ch.uuid) && ch.properties.contains(CharPropFlags::READ)
                    {
                        if let Ok(value) = peripheral.read(ch).await {
                            if !value.is_empty() && value.iter().all(|b| (0x20..=0x7E).contains(b))
                            {
                                found = Some(String::from_utf8_lossy(&value).into_owned());
                            }
                        }
                    }
                }
            }
            found
        }
        Err(e) => {
            let _ = peripheral.disconnect().await;
            return Err(e.to_string().into());
        }
    };

    let _ = peripheral.disconnect().await;
    Ok(name)
}

/// Enrich the BLE device list with real names read over GATT. Only Samsung
/// SmartThings Find devices (manufacturer 0x0075) are touched: those phones
/// hide the name from the advertisement but expose it in Generic Access, and
/// connecting to them is proven safe and fast. The GATT name is the strongest
/// BLE<->LAN matching key ("Galaxy A41 di Salvatore" <-> "Galaxy:A41").
/// Apple devices do not reveal their name this way, so they are left alone.
pub async fn enrich_names(logger: &Logger, devices: &mut [BleDevice]) {
    let targets: Vec<(String, String)> = devices
        .iter()
        .filter(|d| d.name.is_none())
        .filter_map(|d| {
            let f = d.fingerprint.as_deref()?;
            if f.starts_with("mfr:0075:") {
                Some((d.mac.clone(), f.to_string()))
            } else {
                None
            }
        })
        .collect();

    if targets.is_empty() {
        logger.log("enrich: no Samsung SmartThings device to name");
        return;
    }

    let manager = match Manager::new().await {
        Ok(m) => m,
        Err(e) => {
            logger.log(&format!("enrich: creating manager: {e}"));
            return;
        }
    };
    let adapters = match manager.adapters().await {
        Ok(a) => a,
        Err(e) => {
            logger.log(&format!("enrich: listing adapters: {e}"));
            return;
        }
    };
    let Some(adapter) = adapters.first() else {
        logger.log("enrich: no Bluetooth adapter");
        return;
    };

    // Keep the scan active so `peripherals()` returns the current device list
    // (devices keep their random address for a while after the scan window).
    let _ = adapter.start_scan(ScanFilter::default()).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    for (mac, fingerprint) in &targets {
        let mac = mac.clone();
        let periph = match adapter
            .peripherals()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|p| p.address().to_string() == mac)
        {
            Some(p) => p,
            None => {
                logger.log(&format!("enrich: {mac} not found, skipping"));
                continue;
            }
        };

        logger.log(&format!(
            "enrich: connecting to {mac} ({fingerprint}) to read name"
        ));
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(8),
            read_device_name(&periph),
        )
        .await;
        match result {
            Ok(Ok(Some(name))) => {
                let name = name.trim().to_string();
                if !name.is_empty() {
                    logger.log(&format!("enrich: {mac} name=\"{name}\""));
                    crate::bn!("  Name via GATT: {name} ({mac})");
                    for d in devices.iter_mut() {
                        if d.mac == mac {
                            d.name = Some(name.clone());
                        }
                    }
                } else {
                    logger.log(&format!("enrich: {mac} empty name"));
                }
            }
            Ok(Ok(None)) => logger.log(&format!("enrich: {mac} no readable name")),
            Ok(Err(e)) => logger.log(&format!("enrich: {mac} read failed: {e}")),
            Err(_) => {
                logger.log(&format!("enrich: {mac} timed out"));
                let _ = periph.disconnect().await;
            }
        }
    }

    let _ = adapter.stop_scan().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phantom_kind_detects_popup_families() {
        let mut mfr: HashMap<u16, Vec<u8>> = HashMap::new();
        let services: Vec<String> = Vec::new();
        let sd: HashMap<String, Vec<u8>> = HashMap::new();

        // Apple Continuity "New Device" popup: 0x004C, primo byte 0x07.
        mfr.insert(0x004C, vec![0x07, 0x19, 0x07, 0x0E, 0x20]);
        assert_eq!(phantom_kind(&mfr, &services, &sd), Some("apple-popup"));

        // Swift Pair: Microsoft 0x0006 tipo 0x01 o prefisso 03 00 80.
        mfr.clear();
        mfr.insert(0x0006, vec![0x01]);
        assert_eq!(phantom_kind(&mfr, &services, &sd), Some("swift-pair"));
        mfr.insert(0x0006, vec![0x03, 0x00, 0x80, b'D']);
        assert_eq!(phantom_kind(&mfr, &services, &sd), Some("swift-pair"));

        // Samsung Easy Setup: 0x0075 payload che inizia 42 09.
        mfr.clear();
        mfr.insert(0x0075, vec![0x42, 0x09, 0x81, 0x02]);
        assert_eq!(
            phantom_kind(&mfr, &services, &sd),
            Some("samsung-easysetup")
        );

        // Fast Pair: service UUID 0xFE2C.
        mfr.clear();
        let svc = vec!["0000fe2c-0000-1000-8000-00805f9b34fb".to_string()];
        assert_eq!(phantom_kind(&mfr, &svc, &sd), Some("fast-pair"));

        // Tile tracker: service UUID 0xFEED.
        let svc_tile = vec!["0000feed-0000-1000-8000-00805f9b34fb".to_string()];
        assert_eq!(phantom_kind(&mfr, &svc_tile, &sd), Some("tile"));

        // Apple Find My (AirTag e accessori): 0x004C primo byte 0x12.
        mfr.clear();
        mfr.insert(0x004C, vec![0x12, 0x10, 0x00, 0x00]);
        assert_eq!(phantom_kind(&mfr, &services, &sd), Some("apple-findmy"));

        // Samsung SmartTag: service data 0xFD5A con primo byte 0x10.
        mfr.clear();
        let mut sd_tag: HashMap<String, Vec<u8>> = HashMap::new();
        sd_tag.insert(
            "0000fd5a-0000-1000-8000-00805f9b34fb".to_string(),
            vec![0x10, 0x00, 0x01],
        );
        assert_eq!(
            phantom_kind(&mfr, &services, &sd_tag),
            Some("samsung-smarttag")
        );

        // Samsung Find My Mobile: servizio 0xFD69.
        let svc_fmm = vec!["0000fd69-0000-1000-8000-00805f9b34fb".to_string()];
        assert_eq!(phantom_kind(&mfr, &svc_fmm, &sd), Some("samsung-fmm"));

        // Chipolo: servizio 0xFE33; Pebblebee: servizio 0xFA25.
        let svc_chipolo = vec!["0000fe33-0000-1000-8000-00805f9b34fb".to_string()];
        assert_eq!(phantom_kind(&mfr, &svc_chipolo, &sd), Some("chipolo"));
        let svc_pebble = vec!["0000fa25-0000-1000-8000-00805f9b34fb".to_string()];
        assert_eq!(phantom_kind(&mfr, &svc_pebble, &sd), Some("pebblebee"));

        // Google Find My Device Network: service data 0xFEAA frame 0x40/0x41.
        let mut sd_google: HashMap<String, Vec<u8>> = HashMap::new();
        sd_google.insert(
            "0000feaa-0000-1000-8000-00805f9b34fb".to_string(),
            vec![0x40, 0xAA, 0xBB],
        );
        assert_eq!(
            phantom_kind(&mfr, &services, &sd_google),
            Some("google-findmy")
        );
        sd_google.insert(
            "0000feaa-0000-1000-8000-00805f9b34fb".to_string(),
            vec![0x41, 0xAA],
        );
        assert_eq!(
            phantom_kind(&mfr, &services, &sd_google),
            Some("google-findmy")
        );

        // Eddystone (0xFEAA primo byte 0x00) NON è un tracker Google.
        sd_google.insert(
            "0000feaa-0000-1000-8000-00805f9b34fb".to_string(),
            vec![0x00, 0xAA, 0xBB],
        );
        assert_eq!(phantom_kind(&mfr, &services, &sd_google), None);

        // Annunci normali NON devono essere marcati (falsi positivi).
        mfr.clear();
        mfr.insert(0x004C, vec![0x10]); // Apple Nearby legittimo
        assert_eq!(phantom_kind(&mfr, &services, &sd), None);
        mfr.clear();
        mfr.insert(0x0075, vec![0x01, 0x02]); // SmartThings Find (telefono)
        assert_eq!(phantom_kind(&mfr, &services, &sd), None);
        let svc2 = vec!["0000fef3-0000-1000-8000-00805f9b34fb".to_string()];
        assert_eq!(phantom_kind(&mfr, &svc2, &sd), None);
    }

    #[test]
    fn apple_ibeacon_tx_reads_measured_power() {
        let mut mfr: HashMap<u16, Vec<u8>> = HashMap::new();
        // iBeacon: 0x02 0x15 + uuid(16) + major(2) + minor(2) + tx(1 byte).
        let mut payload = vec![0x02, 0x15];
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]);
        payload.push(0xC5); // -59 dBm
        mfr.insert(0x004C, payload);
        assert_eq!(apple_ibeacon_tx(&mfr), Some(-59));
        // Non-iBeacon (payload Apple generico): None.
        mfr.clear();
        mfr.insert(0x004C, vec![0x10, 0x01]);
        assert_eq!(apple_ibeacon_tx(&mfr), None);
        // Payload troppo corto: None.
        mfr.clear();
        mfr.insert(0x004C, vec![0x02, 0x15, 0x00]);
        assert_eq!(apple_ibeacon_tx(&mfr), None);
    }

    #[test]
    fn fastpair_model_id_reads_three_bytes_be() {
        let mut sd: HashMap<String, Vec<u8>> = HashMap::new();
        sd.insert(
            "0000fe2c-0000-1000-8000-00805f9b34fb".to_string(),
            // WH-1000XM5 Model ID 0xD446A7 = 13911719, + byte flags.
            vec![0xD4, 0x46, 0xA7, 0x00],
        );
        assert_eq!(fastpair_model_id(&sd), Some(13911719));
        // Payload troppo corto -> None (niente modello fittizio).
        sd.insert(
            "0000fe2c-0000-1000-8000-00805f9b34fb".to_string(),
            vec![0x00, 0x01],
        );
        assert_eq!(fastpair_model_id(&sd), None);
        let empty: HashMap<String, Vec<u8>> = HashMap::new();
        assert_eq!(fastpair_model_id(&empty), None);
    }
}
