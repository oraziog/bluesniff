//! Stato di salute dell'adapter e del canale BLE.
//!
//! Serve a una cosa precisa: **distinguere il silenzio di un dispositivo dal
//! silenzio dell'adapter**. Senza questa distinzione qualunque analisi di
//! presenza è inutile su un setup reale, perché il canale LE di un dongle
//! USB può morire da un secondo all'altro (il caso classico è un Realtek su
//! VM con passthrough USB: l'inquiry classica continua a funzionare, il LE
//! restituisce zero pacchetti). In quel caso "il dispositivo è sparito" è
//! una frase falsa, e un allarme costruito su quella frase è rumore.
//!
//! Il modulo mantiene un heartbeat: chi osserva (il watcher BLE) lo aggiorna a
//! ogni pacchetto ricevuto. Se il battito non arriva da `stale_after_ms`, il
//! radio è considerato muto e l'analisi di presenza **tace**.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Ora (epoch ms) dell'ultimo pacchetto BLE effettivamente osservato.
static LAST_BLE_MS: AtomicI64 = AtomicI64::new(0);
/// Ora (epoch ms) dell'ultimo segnale di vita (qualunque fonte).
static LAST_LIFE_MS: AtomicI64 = AtomicI64::new(0);
/// Totale pacchetti BLE visto dall'avvio: distingue "mai visto niente"
/// (adapter assente) da "prima ne vedeva, ora no" (canale muto).
static BLE_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Numero di "buchi" rilevati: transizioni vivo -> muto.
static MUTE_EVENTS: AtomicU64 = AtomicU64::new(0);
/// Momento dell'ultimo buco, per mostrarlo in dashboard.
static LAST_MUTE_MS: AtomicI64 = AtomicI64::new(0);
/// Timestamp (epoch ms) dell'ultimo pacchetto come lo riporta il controller.
static LAST_PKT_MS: AtomicI64 = AtomicI64::new(0);
/// L'adapter e' stato aperto almeno una volta in questa sessione.
static RADIO_READY: AtomicBool = AtomicBool::new(false);

/// Sotto questo battito il radio è considerato muto. 20s è scelto con
/// margine: i pacchetti BLE di un device in zona arrivono con frequenza molto
/// maggiore, e il mio campione reale ha 68 MAC con almeno 8 annunci in poche
/// ore, quindi il radio non è mai realmente silenzioso in una zona attiva.
pub const DEFAULT_STALE_MS: i64 = 20_000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Chiamato per ogni pacchetto BLE osservato: è il battito.
pub fn note_ble_packet(ts_ms: i64) {
    let now = now_ms();
    let prev = LAST_BLE_MS.swap(now, Ordering::Relaxed);
    // Una transizione vivo -> muto vale solo se il silenzio precedente era
    // già scaduto: altrimenti ogni pacchetto conteggerebbe come un nuovo buco.
    if prev != 0 && now - prev > DEFAULT_STALE_MS {
        MUTE_EVENTS.fetch_add(1, Ordering::Relaxed);
        LAST_MUTE_MS.store(now, Ordering::Relaxed);
    }
    // L'istante del pacchetto (timestamp WinRT) viene tenuto separato dal
    // battito di sistema: se il controller consegna un timestamp indietro nel
    // tempo, il battito non deve risalire nel passato.
    if ts_ms > LAST_PKT_MS.load(Ordering::Relaxed) {
        LAST_PKT_MS.store(ts_ms, Ordering::Relaxed);
    }
    LAST_LIFE_MS.store(now, Ordering::Relaxed);
    BLE_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Chiamato quando l'adapter è stato aperto con successo.
///
/// Serve a distinguere "l'adapter non c'e'" da "l'adapter c'e' ma il canale LE
/// non produce niente": sono due guasti diversi e l'utente li risolve in due
/// modi diversi (cambiare dongle contro riavviare/resetare il radio).
pub fn note_radio_ready() {
    LAST_LIFE_MS.store(now_ms(), Ordering::Relaxed);
    RADIO_READY.store(true, Ordering::Relaxed);
}

pub fn radio_ready() -> bool {
    RADIO_READY.load(Ordering::Relaxed)
}

pub fn ble_total() -> u64 {
    BLE_TOTAL.load(Ordering::Relaxed)
}

pub fn mute_events() -> u64 {
    MUTE_EVENTS.load(Ordering::Relaxed)
}

pub fn last_mute_ms() -> i64 {
    LAST_MUTE_MS.load(Ordering::Relaxed)
}

/// Millisecondi dall'ultimo pacchetto BLE, `None` se non ne abbiamo mai visto.
pub fn since_last_ble_ms() -> Option<i64> {
    let last = LAST_BLE_MS.load(Ordering::Relaxed);
    if last == 0 {
        None
    } else {
        Some(now_ms() - last)
    }
}

/// Salute del radio, con la distinzione che conta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioHealth {
    /// Adapter presente, canale LE che produce pacchetti.
    Live,
    /// Adapter presente, ma il canale LE non produce pacchetti da troppo:
    /// è il guasto classico del Realtek su VM, l'inquiry classica continua.
    LeMute,
    /// Nessun pacchetto BLE mai visto: adapter assente, spento o in errore.
    Absent,
}

impl RadioHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            RadioHealth::Live => "live",
            RadioHealth::LeMute => "le_mute",
            RadioHealth::Absent => "absent",
        }
    }

    pub fn as_it(self) -> &'static str {
        match self {
            RadioHealth::Live => "attivo",
            RadioHealth::LeMute => "canale LE muto",
            RadioHealth::Absent => "adapter assente",
        }
    }

    /// L'osservazione è affidabile? Solo se il radio sta davvero producendo.
    pub fn reliable(self) -> bool {
        matches!(self, RadioHealth::Live)
    }
}

pub fn health(stale_ms: i64) -> RadioHealth {
    match since_last_ble_ms() {
        None => RadioHealth::Absent,
        Some(elapsed) if elapsed > stale_ms => RadioHealth::LeMute,
        Some(_) => RadioHealth::Live,
    }
}

/// Timestamp (epoch ms) dell'ultimo pacchetto osservato, come lo riporta il
/// controller: e' il dato che la dashboard mostra come "ultimo segnale".
pub fn last_packet_ms() -> i64 {
    LAST_PKT_MS.load(Ordering::Relaxed)
}

/// Stato completo per la dashboard e per l'API.
pub fn snapshot(stale_ms: i64) -> serde_json::Value {
    let h = health(stale_ms);
    serde_json::json!({
        "health": h.as_str(),
        "health_it": h.as_it(),
        "reliable": h.reliable(),
        "adapter_opened": radio_ready(),
        "ble_packets": ble_total(),
        "last_packet": if last_packet_ms() == 0 { serde_json::Value::Null } else { crate::logging::rfc3339_millis(last_packet_ms()).into() },
        "mute_events": mute_events(),
        "last_mute_ms": if last_mute_ms() == 0 { serde_json::Value::Null } else { crate::logging::rfc3339_millis(last_mute_ms()).into() },
        "since_last_ble_ms": since_last_ble_ms(),
        "stale_after_ms": stale_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Gli atomi sono globali: questi test non devono correre in parallelo fra
    // loro perché toccano lo stesso stato. Mutex dedicato.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() {
        LAST_BLE_MS.store(0, Ordering::Relaxed);
        LAST_LIFE_MS.store(0, Ordering::Relaxed);
        BLE_TOTAL.store(0, Ordering::Relaxed);
        MUTE_EVENTS.store(0, Ordering::Relaxed);
        LAST_MUTE_MS.store(0, Ordering::Relaxed);
        LAST_PKT_MS.store(0, Ordering::Relaxed);
        RADIO_READY.store(false, Ordering::Relaxed);
    }

    #[test]
    fn assente_senza_pacchetti() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert_eq!(health(DEFAULT_STALE_MS), RadioHealth::Absent);
        assert!(!health(DEFAULT_STALE_MS).reliable());
        assert_eq!(since_last_ble_ms(), None);
    }

    #[test]
    fn attivo_subito_dopo_un_pacchetto() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        note_ble_packet(0);
        assert_eq!(health(DEFAULT_STALE_MS), RadioHealth::Live);
        assert!(health(DEFAULT_STALE_MS).reliable());
        assert_eq!(ble_total(), 1);
    }

    #[test]
    fn muto_dopo_la_soglia() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        note_ble_packet(0);
        // Soglia 0: qualunque elapsed, anche di un millisecondo, e' "muto".
        // Usiamo -1 per non dipendere dall'orologio di sistema: con 0 il
        // confronto `elapsed > 0` potrebbe essere falso se le due chiamate
        // cadono nello stesso millisecondo, rendendo il test instabile.
        assert_eq!(health(-1), RadioHealth::LeMute);
        assert!(!health(-1).reliable());
        // Con una soglia enorme nessun silenzio e' scaduto: resta attivo.
        assert_eq!(health(i64::MAX), RadioHealth::Live);
        assert!(health(i64::MAX).reliable());
    }

    #[test]
    fn il_bussolo_non_conta_ogni_pacchetto_come_buco() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for _ in 0..10 {
            note_ble_packet(0);
        }
        // Dieci pacchetti ravvicinati: nessun buco oltre il primo (che non
        // avviene perché `prev` era 0 alla prima chiamata).
        assert_eq!(mute_events(), 0);
        assert_eq!(ble_total(), 10);
    }

    #[test]
    fn un_timestamp_indietro_non_fa_tornare_indietro_il_battito() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        note_ble_packet(1_000);
        // Il controller consegna un pacchetto con timestamp precedente.
        note_ble_packet(500);
        assert_eq!(last_packet_ms(), 1_000, "il battito non deve regredire");
        assert_eq!(ble_total(), 2, "il pacchetto e' comunque contato");
    }

    #[test]
    fn snapshot_espone_i_campi_che_la_dashboard_usa() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let v = snapshot(DEFAULT_STALE_MS);
        assert_eq!(v["health"], "absent");
        assert_eq!(v["reliable"], false);
        assert!(v.get("ble_packets").is_some());
        assert!(v.get("adapter_opened").is_some());
        assert!(v.get("mute_events").is_some());
    }
}
