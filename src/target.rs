//! Target parsing, DNS resolution and service fingerprinting.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream as AsyncTcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Service {
    Http,
    Https,
    Dns,
    Ssh,
    Smtp,
    Ftp,
    Generic,
    Unknown,
}

impl Service {
    pub fn label(self) -> &'static str {
        match self {
            Service::Http => "HTTP",
            Service::Https => "HTTPS/TLS",
            Service::Dns => "DNS",
            Service::Ssh => "SSH",
            Service::Smtp => "SMTP",
            Service::Ftp => "FTP",
            Service::Generic => "TCP service",
            Service::Unknown => "unknown / filtered",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Target {
    pub input: String,
    pub host: String,
    pub port: Option<u16>,
    pub ips: Vec<Ipv4Addr>,
    pub service: Service,
    pub tls: bool,
}


/// Strip scheme / path / brackets from user input.
pub fn normalize(input: &str) -> (String, Option<u16>, bool) {
    let mut s = input.trim().to_string();
    let mut tls = false;
    if let Some(rest) = s.strip_prefix("https://") {
        s = rest.to_string();
        tls = true;
    } else if let Some(rest) = s.strip_prefix("http://") {
        s = rest.to_string();
    }
    if let Some(i) = s.find('/') {
        s.truncate(i);
    }
    let mut port = None;
    // host:port (avoid IPv6 colons by only splitting the last one)
    if let Some(i) = s.rfind(':') {
        if let Ok(p) = s[i + 1..].parse::<u16>() {
            if p > 0 {
                port = Some(p);
                s.truncate(i);
            }
        }
    }
    (s, port, tls)
}

impl Target {
    pub fn parse(input: &str, port_field: &str) -> Result<Self, String> {
        let (host, mut port, mut tls) = normalize(input);
        if host.is_empty() {
            return Err("target is empty".into());
        }
        if !port_field.trim().is_empty() {
            port = Some(
                port_field
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port: {port_field}"))?,
            );
        }
        if port == Some(0) {
            return Err("port must be 1-65535".into());
        }
        if port == Some(443) || port == Some(8443) {
            tls = true;
        }
        Ok(Self {
            input: input.trim().to_string(),
            host,
            port,
            ips: Vec::new(),
            service: Service::Unknown,
            tls,
        })
    }


    pub fn resolve(&mut self) -> Result<(), String> {
        if let Ok(ip) = self.host.parse::<Ipv4Addr>() {
            self.ips = vec![ip];
            return Ok(());
        }
        let addrs = (self.host.as_str(), 0u16)
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed for {}: {e}", self.host))?;
        let mut v4: Vec<Ipv4Addr> = Vec::new();
        for a in addrs {
            if let IpAddr::V4(ip) = a.ip() {
                if !v4.contains(&ip) {
                    v4.push(ip);
                }
            }
        }
        if v4.is_empty() {
            return Err(format!("{} has no IPv4 address", self.host));
        }
        self.ips = v4;
        Ok(())
    }

    pub fn primary(&self) -> Option<Ipv4Addr> {
        self.ips.first().copied()
    }
}

fn probe_tcp(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<Vec<u8>> {
    let addr = SocketAddr::from((ip, port));
    let mut s = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = s.set_read_timeout(Some(timeout));
    let mut buf = [0u8; 256];
    match s.read(&mut buf) {
        Ok(n) if n > 0 => Some(buf[..n].to_vec()),
        _ => Some(Vec::new()),
    }
}

fn probe_udp_dns(ip: Ipv4Addr, timeout: Duration) -> bool {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(timeout));
    // Minimal DNS query for "a." type A.
    let q: [u8; 19] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'a', 0x00,
        0x00, 0x01, 0x00, 0x01,
    ];
    if sock.send_to(&q, SocketAddr::from((ip, 53))).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    sock.recv_from(&mut buf).is_ok()
}

fn classify(port: u16, banner: &[u8]) -> Service {
    let b = String::from_utf8_lossy(banner).to_ascii_lowercase();
    if b.starts_with("ssh-") {
        return Service::Ssh;
    }
    if b.starts_with("220") && b.contains("smtp") {
        return Service::Smtp;
    }
    if b.starts_with("220") && b.contains("ftp") {
        return Service::Ftp;
    }
    if b.contains("http/") || b.contains("server:") {
        return Service::Http;
    }
    match port {
        80 | 8080 | 8000 | 8888 | 3000 | 5000 | 9000 => Service::Http,
        443 | 8443 | 9443 | 4443 => Service::Https,
        53 => Service::Dns,
        22 => Service::Ssh,
        25 | 587 | 465 => Service::Smtp,
        21 => Service::Ftp,
        _ => Service::Generic,
    }
}

/// Probe the target to work out what it is, so vectors can be auto-selected.
pub fn fingerprint(t: &mut Target) -> Result<(), String> {
    let ip = t.primary().ok_or("target not resolved")?;
    let timeout = Duration::from_millis(900);

    if let Some(port) = t.port {
        let banner = probe_tcp(ip, port, timeout);
        t.service = match banner {
            Some(b) => {
                let s = classify(port, &b);
                if s == Service::Http && port == 443 {
                    Service::Https
                } else {
                    s
                }
            }
            None => {
                if port == 53 {
                    Service::Dns
                } else {
                    Service::Unknown
                }
            }
        };
        if t.service == Service::Https {
            t.tls = true;
        }
        return Ok(());
    }

    // No port given: sweep common ports to identify the service.
    const SWEEP: [u16; 12] = [80, 443, 8080, 8443, 53, 22, 25, 21, 3000, 8000, 8888, 3306];
    for p in SWEEP {
        if let Some(b) = probe_tcp(ip, p, Duration::from_millis(500)) {
            t.service = classify(p, &b);
            t.port = Some(p);
            if t.service == Service::Https {
                t.tls = true;
            }
            return Ok(());
        }
    }
    if probe_udp_dns(ip, Duration::from_millis(600)) {
        t.service = Service::Dns;
        t.port = Some(53);
        return Ok(());
    }
    t.service = Service::Unknown;
    Ok(())
}

/// Classify a port without a banner grab.
pub fn classify_port(port: u16) -> Service {
    match port {
        443 | 8443 | 9443 | 4443 => Service::Https,
        80 | 8080 | 8000 | 8888 | 3000 | 5000 | 9000 => Service::Http,
        53 => Service::Dns,
        22 => Service::Ssh,
        25 | 587 | 465 => Service::Smtp,
        21 => Service::Ftp,
        _ => Service::Generic,
    }
}

/// Pick the most interesting open port and its service.
pub fn best_service(ports: &[u16]) -> (Service, Option<u16>) {
    let rank = |p: u16| match classify_port(p) {
        Service::Https => 0,
        Service::Http => 1,
        Service::Dns => 2,
        Service::Ssh => 3,
        Service::Smtp => 4,
        Service::Ftp => 5,
        Service::Generic => 6,
        Service::Unknown => 7,
    };
    match ports.iter().min_by_key(|p| rank(**p)) {
        Some(&p) => (classify_port(p), Some(p)),
        None => (Service::Unknown, None),
    }
}

async fn port_open(ip: Ipv4Addr, port: u16) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(400),
            AsyncTcpStream::connect((ip, port))
        )
        .await,
        Ok(Ok(_))
    )
}

const QUICK_PORTS: [u16; 26] = [
    80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 3306, 5432, 6379, 27017, 8000, 8888, 3000, 5000,
    9000, 9200, 11211, 5900, 3389, 445, 139, 23,
];

/// Scan every TCP port on `ip`, streaming hits through `found_tx`.
///
/// A quick pass over common ports runs first so the UI has something to show
/// immediately, then the full 1-65535 range is swept.
pub async fn scan_all_ports(
    ip: Ipv4Addr,
    found_tx: mpsc::UnboundedSender<u16>,
    progress: Arc<AtomicU32>,
) -> Vec<u16> {
    let mut found: Vec<u16> = Vec::new();

    let mut set = JoinSet::new();
    for p in QUICK_PORTS {
        set.spawn(async move { (p, port_open(ip, p).await) });
    }
    while let Some(r) = set.join_next().await {
        if let Ok((p, true)) = r {
            found.push(p);
            let _ = found_tx.send(p);
        }
    }

    let mut port: u32 = 1;
    let mut set = JoinSet::new();
    loop {
        while set.len() < 1200 && port <= 65535 {
            let p = port as u16;
            port += 1;
            if found.contains(&p) {
                progress.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            set.spawn(async move { (p, port_open(ip, p).await) });
        }
        if set.is_empty() {
            break;
        }
        if let Some(Ok((p, true))) = set.join_next().await {
            found.push(p);
            let _ = found_tx.send(p);
        }
        progress.fetch_add(1, Ordering::Relaxed);
    }
    found.sort_unstable();
    found
}
