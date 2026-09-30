use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::logging::Logger;

/// Snapshot of an mDNS discovery round: hostnames and recognised services.
#[derive(Debug, Clone, Default)]
pub struct MdnsSnapshot {
    /// IP -> recognised services (e.g. ["Apple TV / AirPlay"]).
    pub services: HashMap<IpAddr, Vec<String>>,
    /// IP -> candidate device names announced via mDNS (instance names like
    /// "Mario's iPhone" and hostnames like "mario-s-iphone").
    pub hostnames: HashMap<IpAddr, Vec<String>>,
}

/// Known mDNS service patterns: substring to search in the payload -> label.
/// Substring search, case-insensitive: not a full DNS parser, but enough to
/// recognise the common devices on a LAN.
pub const MDNS_SERVICE_PATTERNS: &[(&str, &str)] = &[
    ("_airplay._tcp", "Apple TV / AirPlay"),
    ("_airplay2._tcp", "Apple TV / AirPlay"),
    ("_airtunes._tcp", "Apple TV / AirPlay"),
    ("_appletv._tcp", "Apple TV"),
    ("_mediaremotetv._tcp", "Apple TV"),
    ("_raop._tcp", "AirPlay Audio"),
    ("_homekit._tcp", "HomeKit / Apple"),
    ("_hap._tcp", "HomeKit / Apple"),
    ("_apple-mobdev2._tcp", "iPhone / iPad"),
    ("_companion-link._tcp", "Apple Device"),
    ("_googlecast._tcp", "Chromecast / Google"),
    ("_googlezone._tcp", "Chromecast / Google"),
    ("_googlehome._tcp", "Google Home / Chromecast"),
    ("_nest._tcp", "Nest / Google"),
    ("_ipp._tcp", "Stampante (IPP)"),
    ("_ipps._tcp", "Stampante (IPP)"),
    ("_printer._tcp", "Stampante"),
    ("_printer._udp", "Stampante"),
    ("_pdl-datastream._tcp", "Stampante"),
    ("_scanner._tcp", "Scanner"),
    ("_sonos._tcp", "Sonos / Speaker Audio"),
    ("_spotify-connect._tcp", "Spotify / Speaker Audio"),
    ("_roku._tcp", "Roku / Smart TV"),
    ("_tivo-remote._tcp", "TiVo / Smart TV"),
    ("_amzn-wplay._tcp", "Fire TV / Amazon"),
    ("_amzn-echo._tcp", "Echo / Alexa"),
    ("_hue._tcp", "Lampadina Hue / IoT"),
    ("_philips_hue._tcp", "Lampadina Hue / IoT"),
    ("_miio._tcp", "Dispositivo Xiaomi / IoT"),
    ("_miio._udp", "Dispositivo Xiaomi / IoT"),
    ("_smb._tcp", "File Server"),
    ("_afpovertcp._tcp", "Mac File Server"),
    ("_nfs._tcp", "NAS"),
    ("_sftp-ssh._tcp", "Server SSH"),
    ("_http._tcp", "Server Web"),
    ("_https._tcp", "Server Web"),
    ("_mqtt._tcp", "IoT (MQTT)"),
    ("_workstation._tcp", "Workstation"),
    ("_device-info._tcp", "Dispositivo"),
];

/// Extract recognised service names from a raw mDNS payload (substring match;
/// works on both compressed and uncompressed messages).
pub fn parse_mdns_services(data: &[u8]) -> Vec<String> {
    let payload = String::from_utf8_lossy(data).to_lowercase();
    let mut found: Vec<String> = Vec::new();
    for (pattern, label) in MDNS_SERVICE_PATTERNS {
        if payload.contains(pattern) {
            let label = label.to_string();
            if !found.contains(&label) {
                found.push(label);
            }
        }
    }
    found
}

/// Service types probed with an active PTR query. Devices answer these
/// immediately (within ms) with their instance + SRV + A records, so a short
/// listen window is enough — passive-only listening would need ~2 minutes to
/// catch the periodic unsolicited announcements.
const MDNS_QUERIES: &[&str] = &[
    "_services._dns-sd._udp.local",
    "_companion-link._tcp.local",
    "_apple-mobdev2._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_homekit._tcp.local",
    "_googlecast._tcp.local",
    "_workstation._tcp.local",
    "_device-info._tcp.local",
    "_ipp._tcp.local",
    "_smb._tcp.local",
];

/// Encode a dotted DNS name as length-prefixed labels with a root terminator.
fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out
}

/// Build a minimal mDNS PTR query packet for the given service name.
fn mdns_ptr_query(name: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    // DNS header: ID=0, flags=0, QDCOUNT=1, rest 0.
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    // Question: QNAME + QTYPE=PTR(12) + QCLASS=IN(1).
    pkt.extend_from_slice(&encode_dns_name(name));
    pkt.extend_from_slice(&[0, 12, 0, 1]);
    pkt
}

/// Read a (possibly compressed) DNS name at `start`, following compression
/// pointers. Returns the fully decompressed dotted name and the offset just
/// past the name in the original (non-pointer) stream.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumped = false;
    let mut pos = start;

    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            if !jumped {
                end = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 1 >= msg.len() {
                return None;
            }
            let offset = ((len & 0x3F) << 8) | (msg[pos + 1] as usize);
            if !jumped {
                end = Some(pos + 2);
            }
            pos = offset;
            jumped = true;
        } else {
            if pos + 1 + len > msg.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&msg[pos + 1..pos + 1 + len]).into_owned());
            pos += 1 + len;
        }
    }

    Some((labels.join("."), end.unwrap_or(pos)))
}

/// Add a candidate device name (dedup, skip service types / ".local" / empty).
fn push_device_name(names: &mut Vec<String>, name: &str) {
    let name = name.trim();
    let name = name.strip_suffix(".local").unwrap_or(name);
    if name.is_empty() || name.starts_with('_') || name.eq_ignore_ascii_case("local") {
        return;
    }
    let name = name.to_string();
    if !names.iter().any(|n| n == &name) {
        names.push(name);
    }
}

/// Parse an mDNS/DNS response and extract candidate device names:
/// - PTR answers: instance name (first label of the RDATA name), e.g.
///   "Mario's iPhone._companion-link._tcp.local" -> "Mario's iPhone".
/// - SRV answers: target hostname, e.g. "mario-s-iphone.local".
/// - A/AAAA answers: owner hostname.
fn parse_mdns_message(msg: &[u8]) -> Vec<String> {
    if msg.len() < 12 {
        return Vec::new();
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let ns = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let ar = u16::from_be_bytes([msg[10], msg[11]]) as usize;

    let mut names = Vec::new();
    let mut pos = 12;

    // Skip the question section.
    for _ in 0..qd {
        let (_, npos) = match read_name(msg, pos) {
            Some(x) => x,
            None => return names,
        };
        pos = npos + 4; // QTYPE + QCLASS
        if pos > msg.len() {
            return names;
        }
    }

    // Walk answer + authority + additional records.
    for _ in 0..(an + ns + ar) {
        let (owner, npos) = match read_name(msg, pos) {
            Some(x) => x,
            None => return names,
        };
        pos = npos;
        if pos + 10 > msg.len() {
            return names;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > msg.len() {
            return names;
        }

        match rtype {
            // PTR: RDATA is a domain name (instance._service._tcp.local).
            12 => {
                if let Some((name, _)) = read_name(msg, rdata_start) {
                    if let Some(label) = name.split('.').next() {
                        push_device_name(&mut names, label);
                    }
                }
            }
            // SRV: priority(2) weight(2) port(2) target(name).
            33 => {
                if rdata_start + 6 <= rdata_end {
                    if let Some((target, _)) = read_name(msg, rdata_start + 6) {
                        push_device_name(&mut names, &target);
                    }
                }
            }
            // A / AAAA: owner name is the hostname.
            1 | 28 => push_device_name(&mut names, &owner),
            _ => {}
        }

        pos = rdata_end;
    }

    names
}

/// Discover mDNS devices for `seconds`: open the socket, send active PTR
/// queries for the common service types, then collect hostnames + services
/// from the answers (with real name decompression).
///
/// The socket is opened with SO_REUSEADDR so it can share port 5353 with the
/// system mDNS responder (Windows' Dnscache / Bonjour). Best-effort: on any
/// failure an empty snapshot is returned and the reason is written to the log.
pub async fn listen(logger: &Logger, seconds: u64) -> MdnsSnapshot {
    const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
    const MDNS_PORT: u16 = 5353;

    let (socket, joined, queries_sent) = match open_socket(MDNS_ADDR, MDNS_PORT) {
        Ok(x) => x,
        Err(e) => {
            logger.log(&format!(
                "mDNS: cannot open socket 0.0.0.0:5353 ({e}); hostnames unavailable"
            ));
            return MdnsSnapshot::default();
        }
    };
    logger.log(&format!(
        "mDNS: joined {joined} interface(s), sent {queries_sent} discovery query(s)"
    ));

    let mut found = MdnsSnapshot::default();
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    let mut buf = [0u8; 4096];
    let mut packets = 0usize;

    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(remaining) => break,
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((len, src)) => {
                        packets += 1;
                        let ip = src.ip();
                        let services = parse_mdns_services(&buf[..len]);
                        if !services.is_empty() {
                            found.services.entry(ip).or_insert_with(Vec::new).extend(services);
                        }
                        let names = parse_mdns_message(&buf[..len]);
                        if !names.is_empty() {
                            let entry = found.hostnames.entry(ip).or_insert_with(Vec::new);
                            for name in names {
                                if !entry.contains(&name) {
                                    entry.push(name);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    logger.log(&format!("mDNS: received {packets} packet(s)"));
    if packets == 0 {
        logger.log(
            "mDNS: hint — 0 packets usually means Windows Firewall blocks inbound UDP 5353 \
             (enable Network Discovery / Private profile) or no mDNS device answered",
        );
    }
    found
}

/// Create a non-blocking UDP socket bound to 0.0.0.0:5353 with SO_REUSEADDR,
/// joined to the mDNS multicast group on EVERY IPv4 interface, then send the
/// discovery queries out of each interface and convert to a tokio socket.
///
/// Joining + sending on every interface matters because the OS default
/// multicast interface is often a VPN/VM adapter, not the NIC the LAN devices
/// are actually on. Returns (socket, interfaces_joined, queries_sent).
fn open_socket(
    mdns_addr: Ipv4Addr,
    port: u16,
) -> std::io::Result<(tokio::net::UdpSocket, usize, usize)> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&socket2::SockAddr::from(SocketAddr::from((
        [0, 0, 0, 0],
        port,
    ))))?;
    socket.set_multicast_loop_v4(true)?;

    let ifaces = crate::lan::local_ipv4_addrs();

    let mut joined = 0usize;
    for iface in &ifaces {
        if socket.join_multicast_v4(&mdns_addr, iface).is_ok() {
            joined += 1;
        }
    }

    let target = socket2::SockAddr::from(SocketAddr::from((mdns_addr, port)));
    let mut queries_sent = 0usize;
    for iface in &ifaces {
        if socket.set_multicast_if_v4(iface).is_err() {
            continue;
        }
        for name in MDNS_QUERIES {
            if socket.send_to(&mdns_ptr_query(name), &target).is_ok() {
                queries_sent += 1;
            }
        }
    }

    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok((
        tokio::net::UdpSocket::from_std(std_socket)?,
        joined,
        queries_sent,
    ))
}
