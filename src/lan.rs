use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

pub struct LanDevice {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub hostnames: Vec<String>,
}

/// Detect the local IPv4 subnets from the machine's interfaces via
/// `GetIpAddrTable` (IP + netmask per interface). Link-local and loopback
/// addresses are skipped. Uses iphlpapi only — no Npcap, no privileges.
pub fn local_subnets() -> Vec<ipnet::IpNet> {
    #[cfg(windows)]
    {
        local_subnets_windows()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn local_subnets_windows() -> Vec<ipnet::IpNet> {
    use windows::Win32::NetworkManagement::IpHelper::{GetIpAddrTable, MIB_IPADDRTABLE};

    let mut out = Vec::new();

    // First call: query the required buffer size.
    let mut size: u32 = 0;
    // SAFETY: null table + size out-pointer is the documented size query.
    unsafe {
        GetIpAddrTable(None, &mut size, false);
    }
    if size == 0 {
        return out;
    }

    let mut buf: Vec<u8> = vec![0; size as usize];
    let table_ptr = buf.as_mut_ptr() as *mut MIB_IPADDRTABLE;
    // SAFETY: buffer is large enough per the size query above.
    let rc = unsafe { GetIpAddrTable(Some(table_ptr), &mut size, false) };
    if rc != 0 {
        return out;
    }

    // SAFETY: table_ptr points to a valid MIB_IPADDRTABLE with dwNumEntries rows.
    unsafe {
        let table = &*table_ptr;
        let entries = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for row in entries {
            let ip = Ipv4Addr::from(u32::from_be(row.dwAddr));
            let mask = u32::from_be(row.dwMask);
            if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || ip.is_multicast() {
                continue;
            }
            let prefix = mask.count_ones() as u8;
            if prefix == 0 {
                continue;
            }
            if let Ok(subnet) = ipnet::IpNet::new(IpAddr::V4(ip), prefix) {
                if !out.contains(&subnet) {
                    out.push(subnet);
                }
            }
        }
    }

    out
}

/// All local IPv4 interface addresses (loopback/link-local/multicast skipped).
/// Used by the mDNS listener to join the multicast group on every interface,
/// so answers are received regardless of which NIC the LAN sits on.
pub fn local_ipv4_addrs() -> Vec<Ipv4Addr> {
    #[cfg(windows)]
    {
        local_ipv4_addrs_windows()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn local_ipv4_addrs_windows() -> Vec<Ipv4Addr> {
    use windows::Win32::NetworkManagement::IpHelper::{GetIpAddrTable, MIB_IPADDRTABLE};

    let mut out = Vec::new();

    let mut size: u32 = 0;
    // SAFETY: null table + size out-pointer is the documented size query.
    unsafe {
        GetIpAddrTable(None, &mut size, false);
    }
    if size == 0 {
        return out;
    }

    let mut buf: Vec<u8> = vec![0; size as usize];
    let table_ptr = buf.as_mut_ptr() as *mut MIB_IPADDRTABLE;
    // SAFETY: buffer is large enough per the size query above.
    let rc = unsafe { GetIpAddrTable(Some(table_ptr), &mut size, false) };
    if rc != 0 {
        return out;
    }

    // SAFETY: table_ptr points to a valid MIB_IPADDRTABLE with dwNumEntries rows.
    unsafe {
        let table = &*table_ptr;
        let entries = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for row in entries {
            let ip = Ipv4Addr::from(u32::from_be(row.dwAddr));
            if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || ip.is_multicast() {
                continue;
            }
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }

    out
}

/// Active ARP sweep of every host in the given subnets via `SendARP`
/// (iphlpapi): sends one ARP request per IP in parallel and returns the IPs
/// that answered. Needs neither Npcap nor administrator rights, so the
/// standalone exe keeps working everywhere. Slower than a raw L2 sweep (~12s
/// on a /24) but fully portable.
///
/// The sweep also populates the OS ARP cache, so the following `capture()`
/// (GetIpNetTable2) sees the MACs of every live host, not only those that had
/// already talked to this machine.
pub fn arp_sweep(subnets: &[ipnet::IpNet]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let mut seen = HashSet::new();
    for subnet in subnets {
        for ip in subnet.hosts() {
            if seen.insert(ip) {
                ips.push(ip);
            }
        }
    }
    if ips.is_empty() {
        return Vec::new();
    }
    probe_parallel(&ips)
}

/// Parallel SendARP probe. SendARP blocks ~1s per dead host, so a whole /24
/// is split across a worker pool; alive hosts answer in a few ms.
#[cfg(windows)]
fn probe_parallel(ips: &[IpAddr]) -> Vec<IpAddr> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use windows::Win32::NetworkManagement::IpHelper::SendARP;

    let alive = Mutex::new(Vec::new());
    let cursor = AtomicUsize::new(0);
    let workers = 64usize.min(ips.len()).max(1);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let i = cursor.fetch_add(1, Ordering::Relaxed);
                if i >= ips.len() {
                    break;
                }
                let IpAddr::V4(ip) = ips[i] else { continue };

                let dest = u32::from_ne_bytes(ip.octets());
                let mut mac = [0u8; 8];
                let mut len: u32 = 8;
                // SAFETY: SendARP with a valid output buffer + length. `dest`
                // is the in_addr S_addr encoding of the IP.
                let rc = unsafe { SendARP(dest, 0, mac.as_mut_ptr() as *mut _, &mut len) };
                if rc == 0 && len == 6 {
                    alive.lock().unwrap().push(IpAddr::V4(ip));
                }
            });
        }
    });

    alive.into_inner().unwrap()
}

#[cfg(not(windows))]
fn probe_parallel(_ips: &[IpAddr]) -> Vec<IpAddr> {
    Vec::new()
}

/// Fresh liveness probe of a specific set of IPs via `SendARP`. Actively pings
/// every IP NOW, so it is the correct "online at this sample" check for
/// co-movement tracking. (Reading the raw ARP cache is not: a `Reachable`
/// entry ages into `Stale` after ~30s idle and would make a live host look
/// offline.)
pub fn probe_alive(ips: &[IpAddr]) -> HashSet<IpAddr> {
    probe_parallel(ips).into_iter().collect()
}

/// ICMP echo (ping) round-trip time for a set of IPs, in milliseconds.
/// `Some(ms)` = answered (and online), `None` = no reply (offline, ICMP
/// filtered, or unreachable). Uses `IcmpSendEcho` (iphlpapi): no Npcap, no
/// privileges. This is the LAN-side continuous signal that pairs with BLE
/// RSSI for co-movement (both degrade with physical distance).
#[cfg(windows)]
pub fn ping_rtt(ips: &[IpAddr]) -> HashMap<IpAddr, Option<u32>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    if ips.is_empty() {
        return HashMap::new();
    }

    let results = Mutex::new(HashMap::new());
    let cursor = AtomicUsize::new(0);
    let workers = 8usize.min(ips.len()).max(1);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                // One handle per worker (IcmpSendEcho is not documented as
                // thread-safe on a shared handle).
                // SAFETY: IcmpCreateFile/IcmpCloseHandle are the documented
                // create/close pair.
                let Ok(handle) = (unsafe { IcmpCreateFile() }) else {
                    return;
                };

                loop {
                    let i = cursor.fetch_add(1, Ordering::Relaxed);
                    if i >= ips.len() {
                        break;
                    }
                    let IpAddr::V4(ip) = ips[i] else { continue };

                    let dest = u32::from_ne_bytes(ip.octets());
                    let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + 64;
                    // Vec<u64> gives 8-byte alignment for the reply header.
                    let mut reply: Vec<u64> = vec![0u64; reply_size.div_ceil(8)];
                    // SAFETY: reply is large enough for header + data; null
                    // request data sends a plain echo request.
                    let rc = unsafe {
                        IcmpSendEcho(
                            handle,
                            dest,
                            std::ptr::null(),
                            0,
                            None,
                            reply.as_mut_ptr() as *mut _,
                            reply_size as u32,
                            500,
                        )
                    };
                    // SAFETY: on rc != 0 the buffer begins with a valid
                    // ICMP_ECHO_REPLY header.
                    let rtt = if rc == 0 {
                        None
                    } else {
                        // SAFETY: IcmpSendEcho2 ha scritto nell buffer
                        // esattamente un ICMP_ECHO_REPLY, e nel ramo rc != 0 la
                        // sua prima parola e' l'IP_STATUS con il risultato:
                        // quindi il puntatore a ICMP_ECHO_REPLY e' allineato e
                        // valido. La lettura non eccede la struttura scritta.
                        let echo = unsafe { &*(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
                        if echo.Status == 0 {
                            Some(echo.RoundTripTime)
                        } else {
                            None
                        }
                    };
                    results.lock().unwrap().insert(IpAddr::V4(ip), rtt);
                }

                // SAFETY: handle is valid.
                unsafe {
                    let _ = IcmpCloseHandle(handle);
                }
            });
        }
    });

    results.into_inner().unwrap()
}

#[cfg(not(windows))]
pub fn ping_rtt(_ips: &[IpAddr]) -> HashMap<IpAddr, Option<u32>> {
    HashMap::new()
}

/// Capture the local network neighbours from the Windows ARP table
/// (`GetIpNetTable2`): IP + MAC (+ best-effort OUI vendor). `hostnames` from
/// the mDNS listen are attached by IP.
///
/// NOTE: the raw ARP cache only contains hosts that talked to THIS machine
/// recently. Run `arp_sweep()` first to populate it with every live host.
#[cfg(windows)]
pub fn capture(hostnames: &HashMap<IpAddr, Vec<String>>) -> Vec<LanDevice> {
    use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2};
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut out = Vec::new();
    let mut table_ptr: *mut windows::Win32::NetworkManagement::IpHelper::MIB_IPNET_TABLE2 =
        std::ptr::null_mut();

    // SAFETY: GetIpNetTable2/FreeMibTable with a valid out-pointer; rows are
    // read behind the returned table pointer as documented by the Win32 API.
    unsafe {
        if GetIpNetTable2(AF_INET, &mut table_ptr).0 != 0 || table_ptr.is_null() {
            return out;
        }

        let table = &*table_ptr;
        let entries = std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize);
        for row in entries {
            if row.PhysicalAddressLength != 6 {
                continue;
            }
            let mac = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                row.PhysicalAddress[0],
                row.PhysicalAddress[1],
                row.PhysicalAddress[2],
                row.PhysicalAddress[3],
                row.PhysicalAddress[4],
                row.PhysicalAddress[5],
            );
            if mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF" {
                continue;
            }

            let s_addr = row.Address.Ipv4.sin_addr.S_un.S_addr;
            let ip = Ipv4Addr::from(u32::from_be(s_addr));
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                continue;
            }

            let hostnames = hostnames.get(&IpAddr::V4(ip)).cloned().unwrap_or_default();
            let vendor = oui_vendor(&mac).unwrap_or("").to_string();
            out.push(LanDevice {
                ip: ip.to_string(),
                mac,
                vendor,
                hostnames,
            });
        }
        FreeMibTable(table_ptr as *const _);
    }

    out.sort_by(|a, b| a.ip.cmp(&b.ip));
    out.dedup_by(|a, b| a.mac == b.mac);
    out
}

#[cfg(not(windows))]
pub fn capture(_hostnames: &HashMap<IpAddr, Vec<String>>) -> Vec<LanDevice> {
    Vec::new()
}

/// Best-effort OUI -> vendor for the common vendors we care about. Partial on
/// purpose: netmonloc has the full HTTP lookup (api.macvendors.com) to reuse.
fn oui_vendor(mac: &str) -> Option<&'static str> {
    let prefix = mac.get(0..8)?;
    Some(match prefix {
        // Apple
        "F0:9F:C2" | "F0:D1:A9" | "8C:85:90" | "A4:83:E7" | "3C:22:FB" | "D4:61:DA"
        | "F4:0F:24" | "AC:BC:32" | "B8:53:9C" | "4C:74:BF" | "D0:81:7A" | "F0:18:98" => "Apple",
        // Samsung
        "8C:77:12" | "E4:B0:21" | "CC:3A:61" | "D0:05:2A" | "5C:CB:99" | "B4:45:06"
        | "74:79:76" | "34:31:11" | "D8:5D:E2" | "AC:38:70" => "Samsung",
        // Microsoft
        "00:15:5D" | "C8:3F:26" | "F4:CE:46" | "9C:EB:E8" | "28:18:78" | "3C:FA:43"
        | "B4:AE:2B" | "0C:5B:8F" => "Microsoft",
        // Google
        "3C:5A:B4" | "E0:AC:CB" | "00:1A:11" | "F4:F5:D8" | "54:60:09" => "Google",
        // Intel
        "3C:A0:67" | "00:1E:64" | "A0:88:B4" | "84:3A:4B" | "00:24:D7" => "Intel",
        // Huawei
        "00:E0:FC" | "48:46:FB" | "A0:6A:44" | "2C:AB:00" | "DC:D9:16" => "Huawei",
        // Xiaomi
        "8C:DE:F9" | "78:11:DC" | "28:6C:07" | "F0:B4:29" | "64:09:80" => "Xiaomi",
        // Sony
        "30:F9:ED" | "00:1A:80" | "AC:9B:0A" | "78:98:E8" => "Sony",
        // Espressif
        "24:0A:C4" | "A4:CF:12" | "18:FE:34" | "EC:FA:BC" => "Espressif",
        // Nordic Semiconductor
        "E0:9D:31" | "CC:2F:71" | "D4:B0:28" => "Nordic Semiconductor",
        _ => return None,
    })
}
