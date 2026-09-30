//! Device classification + proximity zones (ideas ported from bluehood).
//!
//! Two small, dependency-free heuristics:
//! 1. `classify_device` maps a device (name / vendor / advertisement hint) to
//!    a coarse category: phone, audio, wearable, computer, vehicle, IoT.
//!    Priority: name patterns (strongest) -> vendor -> the existing
//!    advertisement `hint` produced by `bluetooth::classify`.
//! 2. `proximity_zone` buckets RSSI into Immediate/Near/Far/Remote, the same
//!    thresholds bluehood uses (> -50, -50..-60, -60..-70, < -70 dBm).

/// Coarse device category (bluehood's device-type classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCategory {
    Phone,
    Audio,
    Wearable,
    Computer,
    Vehicle,
    IoT,
    /// Annunci \"popup/phantom\" (Apple Continuity New Device, ecc.):
    /// marcatore difensivo, non un verdetto di colpevolezza.
    Phantom,
    Other,
}

impl DeviceCategory {
    /// Lowercase label used in log lines and CSV-adjacent output.
    pub fn label(&self) -> &'static str {
        match self {
            DeviceCategory::Phone => "phone",
            DeviceCategory::Audio => "audio",
            DeviceCategory::Wearable => "wearable",
            DeviceCategory::Computer => "computer",
            DeviceCategory::Vehicle => "vehicle",
            DeviceCategory::IoT => "iot",
            DeviceCategory::Phantom => "phantom",
            DeviceCategory::Other => "other",
        }
    }
}

/// Classify a device from its advertised name, OUI vendor and the
/// advertisement hint (from `bluetooth::classify`). All inputs optional.
pub fn classify_device(
    name: Option<&str>,
    vendor: Option<&str>,
    hint: Option<&str>,
) -> DeviceCategory {
    // 1) Name patterns: strongest signal (bluehood's priority order).
    if let Some(n) = name {
        let l = n.to_lowercase();
        // Phones first (some names contain "watch"/"buds" too, e.g. the
        // companion devices advertise with the phone's name).
        const PHONE_TOKENS: &[&str] = &[
            "iphone",
            "galaxy s",
            "galaxy a",
            "galaxy note",
            "galaxy z",
            "pixel",
            "redmi",
            "xiaomi",
            "huawei p",
            "huawei mate",
            "oneplus",
            "oppo",
            "vivo",
            "motorola",
            "moto g",
            "nokia",
            "honor",
            "nothing phone",
        ];
        if PHONE_TOKENS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::Phone;
        }
        const WEARABLE_TOKENS: &[&str] = &[
            "watch",
            "band",
            "fitbit",
            "fitness",
            "miband",
            "mi band",
            "amazfit",
            "gear fit",
            "airtag",
            "smarttag",
            "tile",
            "galaxy fit",
        ];
        if WEARABLE_TOKENS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::Wearable;
        }
        const AUDIO_TOKENS: &[&str] = &[
            "airpods",
            "buds",
            "headphone",
            "headset",
            "earbuds",
            "speaker",
            "soundbar",
            "jbl",
            "sony wh",
            "wf-",
            "beats",
            "music",
        ];
        if AUDIO_TOKENS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::Audio;
        }
        const COMPUTER_TOKENS: &[&str] = &[
            "macbook", "thinkpad", "notebook", "desktop", "pc-", "-pc", "surface", "keyboard",
            "mouse", "monitor", "printer", "webcam",
        ];
        if COMPUTER_TOKENS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::Computer;
        }
        const VEHICLE_TOKENS: &[&str] = &[
            "car",
            "vehicle",
            "tesla",
            "bmw",
            "audi",
            "volkswagen",
            "toyota",
            "fiat",
        ];
        if VEHICLE_TOKENS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::Vehicle;
        }
        const IOT_TOKENS: &[&str] = &[
            "tv",
            "roku",
            "chromecast",
            "echo",
            "nest",
            "tuya",
            "smart plug",
            "bulb",
            "thermostat",
            "camera",
            "doorbell",
            "vacuum",
            "fridge",
            "washer",
        ];
        if IOT_TOKENS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::IoT;
        }
    }

    // 2) Vendor (weaker: a vendor makes many categories).
    if let Some(v) = vendor {
        let l = v.to_lowercase();
        const PHONE_VENDORS: &[&str] = &["xiaomi", "oppo", "oneplus", "honor", "motorola"];
        if PHONE_VENDORS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::Phone;
        }
        const AUDIO_VENDORS: &[&str] = &["bose", "jbl", "beats", "sennheiser", "sony"];
        if AUDIO_VENDORS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::Audio;
        }
        const IOT_VENDORS: &[&str] = &["tuya", "nest", "roku", "ring", "philips"];
        if IOT_VENDORS.iter().any(|t| l.contains(t)) {
            return DeviceCategory::IoT;
        }
    }

    // 3) Advertisement hint (service-UUID fingerprint from bluetooth.rs).
    if let Some(h) = hint {
        let l = h.to_lowercase();
        // Annunci popup/phantom (Apple Continuity "New Device" ecc.):
        // marcatura difensiva "possibile spoof", mai un verdetto.
        if l.contains("popup") || l.contains("phantom") {
            return DeviceCategory::Phantom;
        }
        if l.contains("apple") && l.contains("find my") {
            // Apple Find My accessories (AirTag e simili).
            return DeviceCategory::Wearable;
        }
        // NB: l'hint "SmartThings Find (Galaxy phone or SmartTag)" NON basta
        // per classificare un orologio: è emesso anche dai telefoni Galaxy
        // (che pubblicizzano il servizio Find). Senza un nome che lo
        // confermi, ricade in Other.
        if l.contains("swift pair") {
            // NB: prima di "nearby" — l'hint Microsoft contiene infatti
            // "Nearby Share", che altrimenti lo farebbe classificare Phone.
            return DeviceCategory::Computer;
        }
        if l.contains("airdrop") || l.contains("nearby") {
            // Apple Nearby is emitted by phones and computers alike.
            return DeviceCategory::Phone;
        }
    }

    DeviceCategory::Other
}

/// Proximity zone from RSSI (bluehood's thresholds). `None` RSSI has no zone.
pub fn proximity_zone(rssi: Option<i16>) -> Option<&'static str> {
    let r = rssi?;
    Some(match r {
        r if r > -50 => "immediate",
        r if r >= -60 => "near",
        r if r >= -70 => "far",
        _ => "remote",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_by_name() {
        assert_eq!(
            classify_device(Some("iPhone di Salvatore"), None, None),
            DeviceCategory::Phone
        );
        assert_eq!(
            classify_device(Some("Galaxy A41"), None, None),
            DeviceCategory::Phone
        );
        assert_eq!(
            classify_device(Some("AirPods di Mario"), None, None),
            DeviceCategory::Audio
        );
        assert_eq!(
            classify_device(Some("Galaxy Watch6"), None, None),
            DeviceCategory::Wearable
        );
        assert_eq!(
            classify_device(Some("Casa Rossa TV"), None, None),
            DeviceCategory::IoT
        );
        assert_eq!(
            classify_device(Some("ThinkPad X1"), None, None),
            DeviceCategory::Computer
        );
        assert_eq!(
            classify_device(Some("Tesla Model 3"), None, None),
            DeviceCategory::Vehicle
        );
    }

    #[test]
    fn classify_phone_beats_watch_companion() {
        // A name carrying both phone and wearable tokens stays a phone.
        assert_eq!(
            classify_device(Some("iPhone Watch Remote"), None, None),
            DeviceCategory::Phone
        );
    }

    #[test]
    fn classify_by_vendor_then_hint() {
        assert_eq!(
            classify_device(None, Some("Bose Corporation"), None),
            DeviceCategory::Audio
        );
        assert_eq!(
            classify_device(None, None, Some("Apple Find My accessory")),
            DeviceCategory::Wearable
        );
        // Un Galaxy phone senza nome pubblicizzato (solo hint SmartThings
        // Find) NON è un orologio: era il falso positivo più comune.
        assert_eq!(
            classify_device(
                None,
                None,
                Some("Samsung device — SmartThings Find (Galaxy phone or SmartTag)")
            ),
            DeviceCategory::Other
        );
        assert_eq!(
            classify_device(Some("Fitbit Charge 6"), None, None),
            DeviceCategory::Wearable
        );
        assert_eq!(
            classify_device(Some("Mi Band 7"), None, None),
            DeviceCategory::Wearable
        );
        assert_eq!(classify_device(None, None, None), DeviceCategory::Other);
    }

    #[test]
    fn classify_phantom_popup_hint() {
        // Gli annunci popup/phantom (Apple Continuity "New Device") vengono
        // marcati Phantom — è un marcatore difensivo, non una condanna.
        assert_eq!(
            classify_device(
                None,
                None,
                Some("Apple Continuity — popup New Device (phantom)")
            ),
            DeviceCategory::Phantom
        );
        // Un nome reale ha la precedenza anche con hint popup (es. un Apple
        // TV in pairing che pubblicizza il proprio nome).
        assert_eq!(
            classify_device(
                Some("Living Room TV"),
                None,
                Some("Apple Continuity — popup New Device (phantom)")
            ),
            DeviceCategory::IoT
        );
        // Hint normali NON sono phantom.
        assert_eq!(
            classify_device(None, None, Some("Apple Find My accessory")),
            DeviceCategory::Wearable
        );
        assert_eq!(
            classify_device(
                None,
                None,
                Some("Microsoft device — Swift Pair / Nearby Share")
            ),
            DeviceCategory::Computer
        );
    }

    #[test]
    fn proximity_zones() {
        assert_eq!(proximity_zone(Some(-40)), Some("immediate"));
        assert_eq!(proximity_zone(Some(-55)), Some("near"));
        assert_eq!(proximity_zone(Some(-65)), Some("far"));
        assert_eq!(proximity_zone(Some(-90)), Some("remote"));
        assert_eq!(proximity_zone(None), None);
    }
}
