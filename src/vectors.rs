//! Attack vector catalogue and metadata.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Vector {
    EthFlood,
    ArpFlood,
    IcmpFlood,
    IpFrag,
    UdpRaw,
    SynFlood,
    AckFlood,
    RstFlood,
    TcpConnect,
    UdpFlood,
    HttpGet,
    HttpPost,
    Slowloris,
    TlsFlood,
    DnsFlood,
}

pub struct Spec {
    pub vector: Vector,
    pub name: &'static str,
    pub layer: &'static str,
    pub raw: bool,
    pub needs_port: bool,
    pub desc: &'static str,
}

pub const ALL: [Spec; 15] = [
    Spec { vector: Vector::EthFlood, name: "eth-flood", layer: "L1", raw: true, needs_port: false, desc: "raw ethernet frame flood" },
    Spec { vector: Vector::ArpFlood, name: "arp-flood", layer: "L2", raw: true, needs_port: false, desc: "ARP request storm to gateway" },
    Spec { vector: Vector::IcmpFlood, name: "icmp-flood", layer: "L3", raw: true, needs_port: false, desc: "ICMP echo request flood" },
    Spec { vector: Vector::IpFrag, name: "ip-frag", layer: "L3", raw: true, needs_port: true, desc: "tiny IP fragment flood" },
    Spec { vector: Vector::UdpRaw, name: "udp-raw", layer: "L3", raw: true, needs_port: true, desc: "spoofed-source UDP datagrams" },
    Spec { vector: Vector::SynFlood, name: "syn-flood", layer: "L4", raw: true, needs_port: true, desc: "TCP SYN flood, random source ports" },
    Spec { vector: Vector::AckFlood, name: "ack-flood", layer: "L4", raw: true, needs_port: true, desc: "TCP ACK flood" },
    Spec { vector: Vector::RstFlood, name: "rst-flood", layer: "L4", raw: true, needs_port: true, desc: "TCP RST flood" },
    Spec { vector: Vector::TcpConnect, name: "tcp-connect", layer: "L4", raw: false, needs_port: true, desc: "full TCP handshake flood" },
    Spec { vector: Vector::UdpFlood, name: "udp-flood", layer: "L4", raw: false, needs_port: true, desc: "kernel UDP sendto flood" },
    Spec { vector: Vector::HttpGet, name: "http-get", layer: "L7", raw: false, needs_port: true, desc: "HTTP GET request flood" },
    Spec { vector: Vector::HttpPost, name: "http-post", layer: "L7", raw: false, needs_port: true, desc: "HTTP POST body flood" },
    Spec { vector: Vector::Slowloris, name: "slowloris", layer: "L7", raw: false, needs_port: true, desc: "slow header exhaustion" },
    Spec { vector: Vector::TlsFlood, name: "tls-flood", layer: "L7", raw: false, needs_port: true, desc: "TLS ClientHello handshake flood" },
    Spec { vector: Vector::DnsFlood, name: "dns-flood", layer: "L7", raw: false, needs_port: true, desc: "random-subdomain DNS query flood" },
];

impl Vector {
    pub fn spec(self) -> &'static Spec {
        ALL.iter().find(|s| s.vector == self).expect("spec exists")
    }
    pub fn name(self) -> &'static str {
        self.spec().name
    }
    pub fn needs_raw(self) -> bool {
        self.spec().raw
    }
    pub fn index(self) -> usize {
        ALL.iter().position(|s| s.vector == self).unwrap()
    }
}

/// Default port per vector when the user did not supply one.
pub fn default_port(v: Vector) -> u16 {
    match v {
        Vector::HttpGet | Vector::HttpPost | Vector::Slowloris => 80,
        Vector::TlsFlood => 443,
        Vector::DnsFlood => 53,
        Vector::SynFlood | Vector::AckFlood | Vector::RstFlood | Vector::TcpConnect => 80,
        _ => 80,
    }
}

/// Choose a focused vector set for a detected service.
///
/// Raw floods dominate the wire, so the default plan keeps only two of them
/// and pairs them with the service-specific L7 vectors. Press `a` in the TUI
/// to arm every vector instead.
pub fn plan_for(service: crate::target::Service, port: Option<u16>, raw_ok: bool) -> Vec<Vector> {
    use crate::target::Service as S;
    let mut v: Vec<Vector> = Vec::new();

    if raw_ok {
        v.push(Vector::SynFlood);
        v.push(Vector::UdpRaw);
    }

    let p = port.unwrap_or(0);
    match service {
        S::Http => {
            v.push(Vector::HttpGet);
            v.push(Vector::Slowloris);
        }
        S::Https => {
            v.push(Vector::TlsFlood);
            v.push(Vector::HttpGet);
        }
        S::Dns => {
            v.push(Vector::DnsFlood);
            v.push(Vector::UdpFlood);
        }
        S::Ssh | S::Smtp | S::Ftp | S::Generic => {
            v.push(Vector::TcpConnect);
        }
        S::Unknown => {
            if p == 443 || p == 8443 {
                v.push(Vector::TlsFlood);
            } else if p == 53 {
                v.push(Vector::DnsFlood);
            } else if p == 80 || p == 8080 || p == 8000 || p == 8888 {
                v.push(Vector::HttpGet);
            } else {
                v.push(Vector::TcpConnect);
            }
        }
    }
    v.sort_by_key(|x| x.index());
    v.dedup();
    v
}
