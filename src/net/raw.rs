//! Raw L2/L3 packet crafting over AF_PACKET.
//!
//! Everything here requires CAP_NET_RAW (i.e. run as root).

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_ARP: u16 = 0x0806;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

#[derive(Clone)]
pub struct Iface {
    pub name: String,
    pub index: i32,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub gw_ip: Option<Ipv4Addr>,
    pub gw_mac: Option<[u8; 6]>,
}

impl Iface {
    /// Destination MAC for off-link traffic: the gateway, else broadcast.
    pub fn next_hop_mac(&self) -> [u8; 6] {
        self.gw_mac.unwrap_or(BROADCAST_MAC)
    }
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn iface_ip(name: &str) -> Option<Ipv4Addr> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return None;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let c = CString::new(name).ok()?;
        let bytes = c.as_bytes_with_nul();
        if bytes.len() > libc::IFNAMSIZ {
            libc::close(fd);
            return None;
        }
        for (i, b) in bytes.iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        let rc = libc::ioctl(fd, libc::SIOCGIFADDR as _, &mut ifr);
        libc::close(fd);
        if rc < 0 {
            return None;
        }
        let sin = &*(&ifr.ifr_ifru.ifru_addr as *const libc::sockaddr
            as *const libc::sockaddr_in);
        Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
    }
}

fn iface_index(name: &str) -> Option<i32> {
    let c = CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx as i32)
    }
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Default route: (interface, gateway IPv4) from /proc/net/route.
fn default_route() -> Option<(String, Ipv4Addr)> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        // Destination 00000000 == default route, flags bit RTF_GATEWAY (0x2).
        let dest = u32::from_str_radix(f[1], 16).ok()?;
        let flags = u32::from_str_radix(f[3], 16).ok()?;
        if dest == 0 && flags & 0x2 != 0 {
            let gw = u32::from_str_radix(f[2], 16).ok()?;
            return Some((f[0].to_string(), Ipv4Addr::from(gw.to_be())));
        }
    }
    None
}

fn arp_lookup(ip: Ipv4Addr) -> Option<[u8; 6]> {
    let table = std::fs::read_to_string("/proc/net/arp").ok()?;
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        if f[0].parse::<Ipv4Addr>().ok() == Some(ip) {
            if let Some(mac) = parse_mac(f[3]) {
                if mac != [0u8; 6] {
                    return Some(mac);
                }
            }
        }
    }
    None
}

/// Pick the default-route interface when possible, else the first usable one.
pub fn discover() -> io::Result<Iface> {
    let route = default_route();
    let gw_ip = route.as_ref().map(|(_, gw)| *gw);
    let preferred = route.as_ref().map(|(n, _)| n.clone());

    let mut names: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let state = read_trim(&format!("/sys/class/net/{name}/operstate")).unwrap_or_default();
            if state != "up" && state != "unknown" {
                continue;
            }
            names.push(name);
        }
    }
    // Default-route interface first, then the rest alphabetically.
    names.sort_by_key(|n| (Some(n) != preferred.as_ref(), n.clone()));

    for name in names {
        let Some(ip) = iface_ip(&name) else { continue };
        if ip.is_loopback() {
            continue;
        }
        let Some(mac) = read_trim(&format!("/sys/class/net/{name}/address"))
            .and_then(|s| parse_mac(&s))
        else {
            continue;
        };
        let Some(index) = iface_index(&name) else { continue };
        let gw_mac = gw_ip.and_then(arp_lookup);
        return Ok(Iface {
            name,
            index,
            mac,
            ip,
            gw_ip,
            gw_mac,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no usable IPv4 network interface found",
    ))
}

pub struct RawSock {
    fd: RawFd,
}

impl RawSock {
    pub fn open(iface: &Iface) -> io::Result<Self> {
        unsafe {
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            sll.sll_ifindex = iface.index;
            let rc = libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            );
            if rc < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            let bufsz: libc::c_int = 8 * 1024 * 1024;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &bufsz as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            );
            Ok(Self { fd })
        }
    }

    /// Send many frames with a single `sendmmsg` syscall.
    pub fn send_batch(&self, frames: &[Vec<u8>]) -> io::Result<usize> {
        if frames.is_empty() {
            return Ok(0);
        }
        let mut iov: Vec<libc::iovec> = frames
            .iter()
            .map(|f| libc::iovec {
                iov_base: f.as_ptr() as *mut libc::c_void,
                iov_len: f.len(),
            })
            .collect();
        let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(iov.len());
        for slot in iov.iter_mut() {
            let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
            m.msg_hdr.msg_iov = slot as *mut libc::iovec;
            m.msg_hdr.msg_iovlen = 1;
            msgs.push(m);
        }
        let n = unsafe {
            libc::sendmmsg(
                self.fd,
                msgs.as_mut_ptr(),
                msgs.len() as libc::c_uint,
                libc::MSG_DONTWAIT as _,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Drop for RawSock {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ---------------------------------------------------------------- checksums

fn ones_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: u16) -> u32 {
    let mut s = 0u32;
    for o in src.octets().chunks(2) {
        s += u16::from_be_bytes([o[0], o[1]]) as u32;
    }
    for o in dst.octets().chunks(2) {
        s += u16::from_be_bytes([o[0], o[1]]) as u32;
    }
    s += proto as u32;
    s += len as u32;
    s
}

// ---------------------------------------------------------------- builders

pub fn eth_header(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(14);
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v
}

pub fn arp_request(src_mac: [u8; 6], src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut v = eth_header(BROADCAST_MAC, src_mac, ETH_P_ARP);
    v.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
    v.extend_from_slice(&ETH_P_IP.to_be_bytes()); // ptype
    v.push(6); // hlen
    v.push(4); // plen
    v.extend_from_slice(&1u16.to_be_bytes()); // op = request
    v.extend_from_slice(&src_mac);
    v.extend_from_slice(&src_ip.octets());
    v.extend_from_slice(&[0u8; 6]);
    v.extend_from_slice(&target_ip.octets());
    v
}

pub fn ipv4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    payload_len: usize,
    id: u16,
    frag_off: u16,
    ttl: u8,
) -> Vec<u8> {
    let total = 20 + payload_len;
    let mut v = Vec::with_capacity(20);
    v.push(0x45);
    v.push(0);
    v.extend_from_slice(&(total as u16).to_be_bytes());
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&frag_off.to_be_bytes());
    v.push(ttl);
    v.push(proto);
    v.extend_from_slice(&[0, 0]); // checksum placeholder
    v.extend_from_slice(&src.octets());
    v.extend_from_slice(&dst.octets());
    let c = fold(ones_sum(&v));
    v[10..12].copy_from_slice(&c.to_be_bytes());
    v
}

pub fn tcp_segment(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(20 + payload.len());
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&ack.to_be_bytes());
    v.push(5 << 4); // data offset 5 words
    v.push(flags);
    v.extend_from_slice(&window.to_be_bytes());
    v.extend_from_slice(&[0, 0]); // checksum placeholder
    v.extend_from_slice(&[0, 0]); // urgent ptr
    v.extend_from_slice(payload);
    let mut sum = pseudo_sum(src, dst, IPPROTO_TCP, v.len() as u16);
    sum += ones_sum(&v);
    let c = fold(sum);
    v[16..18].copy_from_slice(&c.to_be_bytes());
    v
}

pub fn udp_datagram(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&(len as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    let mut sum = pseudo_sum(src, dst, IPPROTO_UDP, len as u16);
    sum += ones_sum(&v);
    let mut c = fold(sum);
    if c == 0 {
        c = 0xffff;
    }
    v[6..8].copy_from_slice(&c.to_be_bytes());
    v
}

pub fn icmp_echo(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.push(8); // echo request
    v.push(0);
    v.extend_from_slice(&[0, 0]); // checksum placeholder
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(payload);
    let c = fold(ones_sum(&v));
    v[2..4].copy_from_slice(&c.to_be_bytes());
    v
}

/// Full ethernet+IP+TCP frame.
#[allow(clippy::too_many_arguments)]
pub fn tcp_frame(
    iface: &Iface,
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let seg = tcp_segment(src_ip, dst_ip, sport, dport, seq, ack, flags, 65535, payload);
    let mut f = eth_header(dst_mac, iface.mac, ETH_P_IP);
    f.extend_from_slice(&ipv4_header(
        src_ip,
        dst_ip,
        IPPROTO_TCP,
        seg.len(),
        rand_u16(),
        0x4000,
        64,
    ));
    f.extend_from_slice(&seg);
    f
}

pub fn udp_frame(
    iface: &Iface,
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let dg = udp_datagram(src_ip, dst_ip, sport, dport, payload);
    let mut f = eth_header(dst_mac, iface.mac, ETH_P_IP);
    f.extend_from_slice(&ipv4_header(
        src_ip,
        dst_ip,
        IPPROTO_UDP,
        dg.len(),
        rand_u16(),
        0x4000,
        64,
    ));
    f.extend_from_slice(&dg);
    f
}

pub fn icmp_frame(
    iface: &Iface,
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let echo = icmp_echo(id, seq, payload);
    let mut f = eth_header(dst_mac, iface.mac, ETH_P_IP);
    f.extend_from_slice(&ipv4_header(
        src_ip,
        dst_ip,
        IPPROTO_ICMP,
        echo.len(),
        rand_u16(),
        0x4000,
        64,
    ));
    f.extend_from_slice(&echo);
    f
}

/// Two tiny fragments of one UDP datagram (offset 0 and offset 1 word).
pub fn frag_frames(
    iface: &Iface,
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
) -> [Vec<u8>; 2] {
    let id = rand_u16();
    let payload = [0u8; 16];
    let dg = udp_datagram(src_ip, dst_ip, sport, dport, &payload);
    let (first, rest) = dg.split_at(8);

    let mut a = eth_header(dst_mac, iface.mac, ETH_P_IP);
    a.extend_from_slice(&ipv4_header(
        src_ip,
        dst_ip,
        IPPROTO_UDP,
        first.len(),
        id,
        0x2000, // MF set, offset 0
        64,
    ));
    a.extend_from_slice(first);

    let mut b = eth_header(dst_mac, iface.mac, ETH_P_IP);
    b.extend_from_slice(&ipv4_header(
        src_ip,
        dst_ip,
        IPPROTO_UDP,
        rest.len(),
        id,
        1, // offset 1 (8 bytes)
        64,
    ));
    b.extend_from_slice(rest);

    [a, b]
}

#[inline]
pub fn rand_u16() -> u16 {
    rand::random::<u16>()
}

#[inline]
pub fn rand_u32() -> u32 {
    rand::random::<u32>()
}

/// Random source port kept below the kernel ephemeral range (32768-60999)
/// so spoofed SYN-ACK/RST replies do not collide with real sockets.
#[inline]
pub fn rand_port() -> u16 {
    1024 + (rand::random::<u16>() % 31744)
}
