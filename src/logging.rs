use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// True when stdout is a real terminal: only then the ANSI color codes are
/// kept. When the output is redirected to a file/pipe the codes would be
/// written raw, so `bn!` strips them.
pub fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Same check for stderr (used by `be!`, e.g. the colored `--inq-json` feed).
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Remove ANSI escape sequences (CSI colors like `\x1b[34m`) from a string.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Salta la sequenza fino al byte finale (lettera ASCII).
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `println!` che emette i colori ANSI solo se stdout è un terminale; quando
/// l'output è reindirizzato su file/pipe i codici vengono rimossi.
#[macro_export]
macro_rules! bn {
    () => {{
        println!();
    }};
    ($($arg:tt)*) => {{
        if $crate::logging::stdout_is_tty() {
            println!($($arg)*);
        } else {
            println!("{}", $crate::logging::strip_ansi(&format!($($arg)*)));
        }
    }};
}

/// Come `bn!` ma su stderr (feed colorato di `--inq-json`).
#[macro_export]
macro_rules! be {
    () => {{
        if $crate::logging::stderr_is_tty() {
            eprintln!();
        } else {
            eprintln!();
        }
    }};
    ($($arg:tt)*) => {{
        if $crate::logging::stderr_is_tty() {
            eprintln!($($arg)*);
        } else {
            eprintln!("{}", $crate::logging::strip_ansi(&format!($($arg)*)));
        }
    }};
}

/// Directory of the running executable (where `bluesniff.log`, `vendors.json`
/// and the CSV output live), falling back to the current directory.
pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Minimal append-only logger. Every line is prefixed with the UTC RFC3339
/// timestamp in the same format netmonloc uses (`[2026-08-20T06:01:53Z`), so
/// the two logs share a timeline key and their graphs can be overlaid.
///
/// `Logger` e' `Clone` e i cloni **condividono lo stesso handle di file**
/// (`Arc<Mutex<File>>`): e' il motivo per cui esiste. I task in background
/// devono poter scrivere nel log senza rubare il `Logger` dal main, e prima
/// questo si risolveva allungando il lifetime con `transmute`, che e' esattamente
/// il tipo di `unsafe` che un revisore segnala a prima vista. Un clone e'
/// gratuito, sicuro, e non apre handle aggiuntivi.
#[derive(Clone)]
pub struct Logger {
    file: std::sync::Arc<Mutex<std::fs::File>>,
    path: PathBuf,
}

impl Logger {
    /// Open `bluesniff.log` next to the running executable, falling back to the
    /// current directory when the executable path is unavailable.
    pub fn open_default() -> Result<Self, Box<dyn std::error::Error>> {
        Self::open(exe_dir().join("bluesniff.log"))
    }

    pub fn open(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let logger = Logger {
            file: std::sync::Arc::new(Mutex::new(file)),
            path,
        };
        logger.log(&format!(
            "===== bluesniff log started (unix epoch {epoch}) ====="
        ));
        Ok(logger)
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn log(&self, msg: &str) {
        let line = format!("[{} {msg}", utc_now_rfc3339());
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{line}");
        }
    }
}

/// RFC3339 UTC timestamp of right now, second precision and no fraction,
/// exactly like netmonloc's log prefix: `2026-08-20T06:01:53Z`.
pub fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs.div_euclid(86_400) as i64;
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Parse an RFC3339 UTC timestamp like `2026-08-20T06:01:53Z` back to unix
/// epoch seconds (inverse of `utc_now_rfc3339`). Pure arithmetic, no deps.
pub fn parse_rfc3339_epoch(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next()?.parse().ok()?;
    let ss: i64 = t.next()?.parse().ok()?;
    Some(days_from_civil(y, m, day) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// RFC3339 UTC timestamp con millisecondi: `2026-09-29T07:15:27.123Z`.
/// Serve al log raw per-pacchetto, dove la cadenza degli annunci si misura
/// in millisecondi (un dispositivo che emette ogni 20 ms va distinto).
pub fn rfc3339_millis(epoch_ms: i64) -> String {
    let secs = epoch_ms.div_euclid(1000);
    let ms = epoch_ms.rem_euclid(1000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Inverso di `rfc3339_millis`: accetta la forma con millisecondi
/// (`2026-09-29T07:15:27.123Z`), quella senza (`2026-09-29T07:15:27Z`) e
/// anche senza suffisso Z (input umano, es. da query string), che viene
/// interpretata come UTC. Ritorna epoch millisecondi.
pub fn parse_rfc3339_millis(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (date_time, ms) = match s.split_once('.') {
        Some((dt, frac)) => {
            // Tre cifre: oltre si tronca, meno si riempie di zeri.
            let mut frac = frac.to_string();
            frac.truncate(3);
            while frac.len() < 3 {
                frac.push('0');
            }
            (dt, frac.parse::<i64>().ok()?)
        }
        None => (s, 0),
    };
    let (date, time) = date_time.split_once('T')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next()?.parse().ok()?;
    // Secondi opzionali: "07:15" (input umano) vale ".000".
    let ss: i64 = t.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some((days_from_civil(y, m, day) * 86_400 + hh * 3600 + mm * 60 + ss) * 1000 + ms)
}

fn days_from_civil(y: i64, m: i64, day: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9).rem_euclid(12);
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Days since 1970-01-01 -> (year, month, day) in the proleptic Gregorian
/// calendar (Howard Hinnant's `civil_from_days`). Pure arithmetic, no deps.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_millis_round_trip() {
        // Round-trip su un istante qualsiasi (2026-09-29 07:15:27.123 UTC).
        let epoch_ms: i64 = 1_790_666_127_123;
        let s = rfc3339_millis(epoch_ms);
        assert_eq!(s, "2026-09-29T07:15:27.123Z");
        assert_eq!(parse_rfc3339_millis(&s), Some(epoch_ms));
    }

    #[test]
    fn parse_rfc3339_senza_milli_e_accettato() {
        // La forma senza frazione (quella di utc_now_rfc3339) vale .000.
        assert_eq!(
            parse_rfc3339_millis("2026-09-29T07:15:27Z"),
            Some(1_790_666_127_000)
        );
    }

    #[test]
    fn parse_rfc3339_frazioni_corte_e_lunghe() {
        // .5 -> 500 ms; 7 cifre -> troncate a 3.
        assert_eq!(
            parse_rfc3339_millis("2026-09-29T07:15:27.5Z"),
            Some(1_790_666_127_500)
        );
        assert_eq!(
            parse_rfc3339_millis("2026-09-29T07:15:27.1234567Z"),
            Some(1_790_666_127_123)
        );
    }

    #[test]
    fn parse_rfc3339_millis_rifiuta_input_invalidi() {
        assert_eq!(parse_rfc3339_millis(""), None);
        assert_eq!(parse_rfc3339_millis("nonsense"), None);
        // Mese/giorno fuori range: days_from_civil accetta qualunque numero,
        // quindi il guard è sulla presenza dei campi, non sul range (la
        // funzione è interna: input sempre di nostra produzione).
        assert_eq!(parse_rfc3339_millis("2026-99:99"), None);
    }

    #[test]
    fn parse_rfc3339_senza_z_e_accettato_come_utc() {
        // Input umano dalla query string (datetime-local senza Z).
        assert_eq!(
            parse_rfc3339_millis("2026-09-29T07:15:27"),
            Some(1_790_666_127_000)
        );
        assert_eq!(
            parse_rfc3339_millis("2026-09-29T07:15:27.5"),
            Some(1_790_666_127_500)
        );
        // Anche senza secondi (il <input type=datetime-local> può ometterli
        // quando step non è impostato a 1): "07:15" vale 07:15:00.000.
        assert_eq!(
            parse_rfc3339_millis("2026-09-29T07:15"),
            Some(1_790_666_100_000)
        );
    }
}
