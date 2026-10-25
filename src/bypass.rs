//! Anti-DDoS / bot-filter reconnaissance and bypass helpers.
//!
//! Three things live here:
//!
//! * CDN detection, by published Cloudflare ranges and by response headers.
//! * Origin discovery, by resolving likely subdomains and confirming that a
//!   candidate actually serves the site for the target `Host` header.
//! * Challenge handling: Cloudflare is detected and reported, Anubis proof of
//!   work is actually solved and the resulting cookie reused.
//!
//! A JavaScript challenge (Cloudflare "Just a moment", Turnstile) cannot be
//! solved without a JS engine, so those are reported rather than defeated.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::js;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const CF_V4: [&str; 14] = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
];

const SUBDOMAINS: [&str; 34] = [
    "direct", "origin", "origin-www", "www", "www2", "web", "ftp", "mail", "smtp", "pop", "imap",
    "webmail", "cpanel", "whm", "dev", "staging", "stage", "test", "beta", "old", "legacy", "api",
    "admin", "portal", "vpn", "git", "ssh", "backup", "cdn", "static", "assets", "media", "img",
    "files",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Challenge {
    None,
    Cloudflare,
    Anubis,
    Other,
}

impl Challenge {
    pub fn label(self) -> &'static str {
        match self {
            Challenge::None => "none",
            Challenge::Cloudflare => "cloudflare JS challenge",
            Challenge::Anubis => "anubis proof-of-work",
            Challenge::Other => "unknown challenge",
        }
    }
}

pub struct Sub {
    pub name: String,
    pub ips: Vec<Ipv4Addr>,
}

pub struct Recon {
    pub cdn: Option<&'static str>,
    pub challenge: Challenge,
    pub origins: Vec<Ipv4Addr>,
    pub cookie: Option<String>,
    pub notes: Vec<String>,
    pub subs: Vec<Sub>,
    pub js_ran: usize,
    pub js_cookie: Option<String>,
    pub js_redirect: Option<String>,
    pub js_errors: Vec<String>,
}

fn in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let Some((base, bits)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(base), Ok(bits)) = (base.parse::<Ipv4Addr>(), bits.parse::<u32>()) else {
        return false;
    };
    if bits == 0 {
        return true;
    }
    if bits > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - bits);
    (u32::from(ip) & mask) == (u32::from(base) & mask)
}

pub fn cdn_by_ip(ips: &[Ipv4Addr]) -> Option<&'static str> {
    for ip in ips {
        for c in CF_V4 {
            if in_cidr(*ip, c) {
                return Some("Cloudflare");
            }
        }
    }
    None
}

fn cdn_by_headers(headers: &str) -> Option<&'static str> {
    let h = headers.to_ascii_lowercase();
    if h.contains("cf-ray") || h.contains("server: cloudflare") {
        return Some("Cloudflare");
    }
    if h.contains("server: fastly") || h.contains("x-served-by: cache-") {
        return Some("Fastly");
    }
    if h.contains("server: cloudfront") || h.contains("x-amz-cf-id") {
        return Some("CloudFront");
    }
    if h.contains("server: akamaighost") || h.contains("x-akamai-") {
        return Some("Akamai");
    }
    if h.contains("server: varnish") || h.contains("x-varnish") {
        return Some("Varnish");
    }
    None
}

// ---------------------------------------------------------------- transport

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

async fn connect(ip: Ipv4Addr, port: u16, tls: bool, sni: &str) -> Option<Box<dyn Stream>> {
    let tcp = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    if !tls {
        return Some(Box::new(tcp));
    }
    let cfg = crate::tls::config()?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).ok()?;
    let s = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_rustls::TlsConnector::from(cfg).connect(name, tcp),
    )
    .await
    .ok()?
    .ok()?;
    Some(Box::new(s))
}

struct Response {
    status: u16,
    headers: String,
    body: String,
}

async fn request(
    ip: Ipv4Addr,
    port: u16,
    tls: bool,
    host: &str,
    path: &str,
    cookie: Option<&str>,
    method: &str,
) -> Option<Response> {
    let mut s = connect(ip, port, tls, host).await?;
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\nAccept: text/html,*/*\r\nConnection: close\r\n",
        ua()
    );
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    if method == "POST" {
        req.push_str("Content-Length: 0\r\n");
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.ok()?;

    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(6), async {
        let mut chunk = [0u8; 4096];
        loop {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > 512 * 1024 {
                        break;
                    }
                }
            }
        }
    })
    .await;

    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text, String::new()),
    };
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Some(Response {
        status,
        headers: head,
        body,
    })
}

fn ua() -> &'static str {
    const UAS: [&str; 5] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    ];
    UAS[(Instant::now().elapsed().subsec_nanos() as usize) % UAS.len()]
}

// ---------------------------------------------------------------- anubis

fn json_field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\"");
    let i = s.find(&pat)? + pat.len();
    let rest = s[i..].trim_start().strip_prefix(':')?.trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(&stripped[..end])
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

fn solve_pow(challenge: &str, difficulty: usize) -> Option<u64> {
    let target = difficulty.min(16);
    for nonce in 0u64..5_000_000 {
        let mut h = Sha256::new();
        h.update(challenge.as_bytes());
        h.update(nonce.to_string().as_bytes());
        let digest = h.finalize();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        if hex.bytes().take_while(|b| *b == b'0').count() >= target {
            return Some(nonce);
        }
    }
    None
}

/// Solve the Anubis proof of work and return the session cookie.
async fn solve_anubis(
    ip: Ipv4Addr,
    port: u16,
    tls: bool,
    host: &str,
) -> Option<String> {
    let base = "/.within.website/x/cmd/anubis/api";
    let r = request(ip, port, tls, host, &format!("{base}/make-challenge"), None, "POST").await?;
    let challenge = json_field(&r.body, "challenge")?.to_string();
    let difficulty: usize = json_field(&r.body, "difficulty")
        .and_then(|d| d.parse().ok())
        .unwrap_or(4);
    let t0 = Instant::now();
    let nonce = solve_pow(&challenge, difficulty)?;
    let mut h = Sha256::new();
    h.update(challenge.as_bytes());
    h.update(nonce.to_string().as_bytes());
    let response: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let elapsed = t0.elapsed().as_millis();

    let path = format!(
        "{base}/pass-challenge?response={response}&nonce={nonce}&redir=%2F&elapsedTime={elapsed}"
    );
    let r = request(ip, port, tls, host, &path, None, "GET").await?;
    let lower = r.headers.to_ascii_lowercase();
    if !lower.contains("set-cookie") {
        return None;
    }
    let mut cookies = Vec::new();
    for line in r.headers.lines() {
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("set-cookie:") {
            let _ = v;
            let raw = &line[line.find(':').unwrap() + 1..];
            if let Some(pair) = raw.trim().split(';').next() {
                cookies.push(pair.trim().to_string());
            }
        }
    }
    if cookies.is_empty() {
        None
    } else {
        Some(cookies.join("; "))
    }
}

// ---------------------------------------------------------------- recon

async fn resolve(name: String) -> Vec<Ipv4Addr> {
    tokio::task::spawn_blocking(move || {
        (name.as_str(), 0u16)
            .to_socket_addrs()
            .map(|it| {
                it.filter_map(|a| match a.ip() {
                    IpAddr::V4(v) => Some(v),
                    _ => None,
                })
                .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

async fn verify_origin(ip: Ipv4Addr, port: u16, tls: bool, host: &str) -> bool {    let Some(r) = request(ip, port, tls, host, "/", None, "GET").await else {
        return false;
    };
    if !(200..400).contains(&r.status) {
        return false;
    }
    // If the candidate still answers as a CDN edge, it is not the origin.
    cdn_by_headers(&r.headers).is_none()
}

pub async fn run(ips: &[Ipv4Addr], port: u16, tls: bool, host: &str) -> Recon {
    let mut recon = Recon {
        cdn: cdn_by_ip(ips),
        challenge: Challenge::None,
        origins: Vec::new(),
        cookie: None,
        notes: Vec::new(),
        subs: Vec::new(),
        js_ran: 0,
        js_cookie: None,
        js_redirect: None,
        js_errors: Vec::new(),
    };
    let Some(&ip) = ips.first() else {
        return recon;
    };

    let r = request(ip, port, tls, host, "/", None, "GET").await;
    if let Some(r) = r {
        if recon.cdn.is_none() {
            recon.cdn = cdn_by_headers(&r.headers);
        }
        let body = r.body.to_ascii_lowercase();
        recon.challenge = if r.headers.to_ascii_lowercase().contains("cf-mitigated")
            || body.contains("just a moment")
            || body.contains("cf-challenge")
        {
            Challenge::Cloudflare
        } else if body.contains("anubis") || body.contains("make-challenge") {
            Challenge::Anubis
        } else if matches!(r.status, 403 | 503) && body.contains("captcha") {
            Challenge::Other
        } else {
            Challenge::None
        };

        // Run the challenge script in the JS engine when there is one.
        if recon.challenge == Challenge::Cloudflare {
            let html = r.body.clone();
            let url = format!("https://{host}/");
            let h = host.to_string();
            let handle = tokio::runtime::Handle::current();
            let (tx, rx) = std::sync::mpsc::channel();
            let spawned = std::thread::Builder::new()
                .stack_size(32 * 1024 * 1024)
                .spawn(move || {
                    let r = (|| {
                        let mut s = js::Session::new(&url, &h)?;
                        for code in js::inline_scripts(&html) {
                            s.eval(&code);
                        }
                        let mut pending = s.take_dyn();
                        pending.extend(js::script_urls(&html));
                        let mut rounds = 0;
                        while !pending.is_empty() && rounds < 3 {
                            rounds += 1;
                            for u in pending.drain(..) {
                                let path = if u.starts_with("http") {
                                    if !u.contains(&h) {
                                        continue;
                                    }
                                    format!("/{}", u.splitn(4, '/').nth(3).unwrap_or(""))
                                } else if u.starts_with('/') {
                                    u
                                } else {
                                    format!("/{u}")
                                };
                                if let Some(sr) =
                                    handle.block_on(request(ip, port, tls, &h, &path, None, "GET"))
                                {
                                    if sr.status == 200 && !sr.body.is_empty() {
                                        s.eval(&sr.body);
                                    }
                                }
                            }
                            pending = s.take_dyn();
                        }
                        Some((s.ran, s.errors.clone(), s.cookie(), s.redirect()))
                    })();
                    let _ = tx.send(r);
                });
            let outcome = if spawned.is_ok() {
                rx.recv().ok().flatten()
            } else {
                None
            };

            if let Some((ran, errors, cookie, redirect)) = outcome {
                recon.js_ran = ran;
                recon.js_errors = errors;
                if let Some(c) = cookie {
                    recon.js_cookie = Some(c.clone());
                    recon.cookie = Some(c);
                    recon.notes.push("challenge cookie produced by JS".into());
                }
                if let Some(rd) = redirect {
                    recon.js_redirect = Some(rd);
                }
                if recon.js_ran == 0 {
                    recon.notes.push("challenge script did not run".into());
                }
            }
        }
    }

    if recon.challenge == Challenge::Anubis {
        match solve_anubis(ip, port, tls, host).await {
            Some(c) => {
                recon.cookie = Some(c);
                recon.notes.push("anubis challenge solved".into());
            }
            None => recon.notes.push("anubis solve failed".into()),
        }
    }

    // Subdomains from certificate transparency. On failure we simply carry on
    // with the user's own domain rather than inventing candidates.
    let names = crt_sh(host).await;
    if names.is_empty() {
        recon.notes.push("crt.sh unavailable, primary domain only".into());
    } else {
        recon.notes.push(format!("crt.sh: {} names", names.len()));
        let mut names = names;
        names.truncate(200);
        recon.subs = verify_subs(names).await;
        recon
            .notes
            .push(format!("{} subdomains still resolve", recon.subs.len()));
    }

    if recon.cdn.is_some() {
        let mut set = tokio::task::JoinSet::new();
        for sub in SUBDOMAINS {
            let name = format!("{sub}.{host}");
            set.spawn(async move {
                let addrs = resolve(name).await;
                (sub, addrs)
            });
        }
        let mut seen: Vec<Ipv4Addr> = Vec::new();
        while let Some(Ok((sub, addrs))) = set.join_next().await {
            for a in addrs {
                if seen.contains(&a) || cdn_by_ip(&[a]).is_some() {
                    continue;
                }
                seen.push(a);
                if verify_origin(a, port, tls, host).await {
                    recon.origins.push(a);
                    recon.notes.push(format!("origin candidate via {sub}.{host}"));
                }
            }
        }
        if recon.origins.is_empty() {
            recon
                .notes
                .push("no origin found; flooding the edge only".into());
        }
    }
    recon
}

/// Convenience for the UI: a one-line summary.
pub fn summary(r: &Recon) -> String {
    let mut s = String::new();
    if let Some(c) = r.cdn {
        s.push_str(&format!("behind {c}"));
    }
    if !r.origins.is_empty() {
        if !s.is_empty() {
            s.push_str(" | ");
        }
        s.push_str(&format!(
            "origin {}",
            r.origins
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if r.challenge != Challenge::None {
        if !s.is_empty() {
            s.push_str(" | ");
        }
        s.push_str(r.challenge.label());
    }
    if s.is_empty() {
        s.push_str("no CDN or challenge detected");
    }
    s
}


// ---------------------------------------------------------------- crt.sh

/// Pull subdomains for `host` out of certificate transparency logs.
///
/// crt.sh is frequently slow or 502s, so this is best-effort and bounded.
pub async fn crt_sh(host: &str) -> Vec<String> {
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        if let Some(v) = crt_sh_once(host).await {
            return v;
        }
    }
    Vec::new()
}

async fn crt_sh_once(host: &str) -> Option<Vec<String>> {
    let crt_host = std::env::var("RUSTDOS_CRT_HOST").unwrap_or_else(|_| "crt.sh".into());
    let port: u16 = std::env::var("RUSTDOS_CRT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    let tls = port == 443;
    let ips = resolve(crt_host.clone()).await;
    let &ip = ips.first()?;
    let path = format!("/?q=%25.{host}&output=json");
    let r = request(ip, port, tls, &crt_host, &path, None, "GET").await?;
    if r.status != 200 {
        return None;
    }
    let v = serde_json::from_str::<serde_json::Value>(&r.body).ok()?;
    let mut out: Vec<String> = Vec::new();
    let suffix = format!(".{host}");
    for entry in v.as_array().into_iter().flatten() {
        let Some(nv) = entry.get("name_value").and_then(|n| n.as_str()) else {
            continue;
        };
        for raw in nv.split(['\n', '\r']) {
            let name = raw.trim().trim_start_matches("*.").to_ascii_lowercase();
            if name.is_empty() || name == host || name.len() > 253 {
                continue;
            }
            if !name.ends_with(&suffix) && name != host {
                continue;
            }
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out.sort();
    Some(out)
}

/// Keep only subdomains that still resolve, with their addresses.
pub async fn verify_subs(names: Vec<String>) -> Vec<Sub> {
    let mut set = tokio::task::JoinSet::new();
    for n in names {
        set.spawn(async move {
            let ips = resolve(n.clone()).await;
            (n, ips)
        });
    }
    let mut out = Vec::new();
    while let Some(Ok((name, ips))) = set.join_next().await {
        if !ips.is_empty() {
            out.push(Sub { name, ips });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}
