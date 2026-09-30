use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// NetBIOS Name Service (NBNS) "Node Status" sweep: ask each live IP for its
/// machine name over UDP 137. This is the same trick `nbtscan` uses, and it
/// reaches Windows PCs and many Android/embedded devices that answer NetBIOS
/// even when they never announce mDNS.
///
/// Best-effort: dead hosts simply don't answer, and hosts with NetBIOS
/// disabled are skipped — the caller merges whatever comes back.
///
/// First-level encoding of the `*` wildcard name: 0x2A -> "CK" plus 'A' padding.
const ENCODED_STAR: &[u8; 32] = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Build a 50-byte NBNS Node Status query with the given transaction ID.
fn nb_query(transaction_id: u16) -> [u8; 50] {
    let mut pkt = [0u8; 50];
    pkt[0] = (transaction_id >> 8) as u8;
    pkt[1] = (transaction_id & 0xFF) as u8;
    // Flags = 0 (query); QDCOUNT = 1 (bytes 4..6), AN/NS/AR = 0.
    pkt[5] = 1;
    // QNAME: length 0x20 + 32-byte encoded '*' + 0x00 terminator.
    let mut i = 12;
    pkt[i] = 0x20;
    i += 1;
    pkt[i..i + 32].copy_from_slice(ENCODED_STAR);
    i += 32;
    pkt[i] = 0x00;
    i += 1;
    // QTYPE = NBSTAT (0x0021).
    pkt[i + 1] = 0x21;
    i += 2;
    // QCLASS = IN (0x0001).
    pkt[i + 1] = 0x01;
    pkt
}

/// Parse a Node Status response and return the machine name (the first
/// registered name with suffix 0x00, i.e. the workstation service name).
fn parse_nb_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;
    // Skip the question section (QNAME is a fixed 34-byte NBNS name).
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    for _ in 0..qd {
        pos += 34 + 4;
        if pos + 10 > data.len() {
            return None;
        }
    }

    // Answer RR: NAME (compression pointer 0xC0 0x0C) + TYPE/CLASS/TTL/RDLEN.
    if data.get(pos) == Some(&0xC0) && data.get(pos + 1) == Some(&0x0C) {
        pos += 2;
    } else {
        pos += 34;
    }
    if pos + 10 > data.len() {
        return None;
    }
    let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
    let rdata = pos + 10;
    if rdlen < 1 || rdata + rdlen > data.len() {
        return None;
    }

    let num_names = data[rdata] as usize;
    let mut p = rdata + 1;
    for _ in 0..num_names {
        if p + 18 > rdata + rdlen {
            return None;
        }
        if data[p + 15] == 0x00 {
            let raw = &data[p..p + 15];
            let name = String::from_utf8_lossy(raw)
                .trim_end_matches('\0')
                .trim()
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
        p += 18;
    }
    None
}

/// Send a Node Status query to every IP and collect the machine names that
/// answer within `window_ms`. Returns `IP -> names` (usually one name).
pub fn sweep(ips: &[IpAddr], window_ms: u64) -> HashMap<IpAddr, Vec<String>> {
    let mut out: HashMap<IpAddr, Vec<String>> = HashMap::new();
    if ips.is_empty() {
        return out;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));

    let mut tid = 1u16;
    for &ip in ips {
        let IpAddr::V4(v4) = ip else { continue };
        let _ = socket.send_to(&nb_query(tid), SocketAddr::new(IpAddr::V4(v4), 137));
        tid = tid.wrapping_add(1);
    }

    let deadline = Instant::now() + Duration::from_millis(window_ms);
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Some(name) = parse_nb_response(&buf[..len]) {
                    let entry = out.entry(src.ip()).or_default();
                    if !entry.contains(&name) {
                        entry.push(name);
                    }
                }
            }
            Err(_) => {
                let remain = deadline.saturating_duration_since(Instant::now());
                if remain.is_zero() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20).min(remain));
            }
        }
    }

    out
}
