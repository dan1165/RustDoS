import Foundation

enum Service: String, Sendable {
    case http, https, dns, ssh, smtp, ftp, generic, unknown

    var label: String {
        switch self {
        case .http: "HTTP"
        case .https: "HTTPS / TLS"
        case .dns: "DNS"
        case .ssh: "SSH"
        case .smtp: "SMTP"
        case .ftp: "FTP"
        case .generic: "TCP service"
        case .unknown: "unknown / filtered"
        }
    }

    var symbol: String {
        switch self {
        case .http, .https: "globe"
        case .dns: "network"
        case .ssh: "terminal"
        case .smtp: "envelope"
        case .ftp: "folder"
        case .generic: "bolt.horizontal"
        case .unknown: "questionmark.circle"
        }
    }
}

enum Layer: String, CaseIterable, Sendable {
    case l3 = "L3", l4 = "L4", l7 = "L7"
}

/// Attack vectors that survive on iOS. L1/L2 (AF_PACKET) are gone: iOS has no
/// ethernet frames, so eth-flood and arp-flood cannot exist here.
enum Vector: String, CaseIterable, Identifiable, Sendable {
    case icmpFlood, ipFrag, udpRaw
    case synFlood, ackFlood, rstFlood, tcpConnect, udpFlood
    case httpGet, httpPost, slowloris, tlsFlood, dnsFlood

    var id: String { rawValue }

    var name: String {
        switch self {
        case .icmpFlood: "icmp-flood"
        case .ipFrag: "ip-frag"
        case .udpRaw: "udp-raw"
        case .synFlood: "syn-flood"
        case .ackFlood: "ack-flood"
        case .rstFlood: "rst-flood"
        case .tcpConnect: "tcp-connect"
        case .udpFlood: "udp-flood"
        case .httpGet: "http-get"
        case .httpPost: "http-post"
        case .slowloris: "slowloris"
        case .tlsFlood: "tls-flood"
        case .dnsFlood: "dns-flood"
        }
    }

    var layer: Layer {
        switch self {
        case .icmpFlood, .ipFrag, .udpRaw: .l3
        case .synFlood, .ackFlood, .rstFlood, .tcpConnect, .udpFlood: .l4
        case .httpGet, .httpPost, .slowloris, .tlsFlood, .dnsFlood: .l7
        }
    }

    var desc: String {
        switch self {
        case .icmpFlood: "ICMP echo request flood"
        case .ipFrag: "tiny IP fragment flood"
        case .udpRaw: "spoofed-source UDP datagrams"
        case .synFlood: "TCP SYN flood, random source ports"
        case .ackFlood: "TCP ACK flood"
        case .rstFlood: "TCP RST flood"
        case .tcpConnect: "full TCP handshake flood"
        case .udpFlood: "kernel UDP sendto flood"
        case .httpGet: "HTTP GET request flood"
        case .httpPost: "HTTP POST body flood"
        case .slowloris: "slow header exhaustion"
        case .tlsFlood: "TLS ClientHello handshake flood"
        case .dnsFlood: "random-subdomain DNS query flood"
        }
    }

    var needsRaw: Bool {
        switch self {
        case .icmpFlood, .ipFrag, .udpRaw, .synFlood, .ackFlood, .rstFlood: true
        default: false
        }
    }

    var defaultPort: UInt16 {
        switch self {
        case .tlsFlood: 443
        case .dnsFlood: 53
        default: 80
        }
    }

    var workers: Int {
        switch self {
        case .icmpFlood, .ipFrag, .udpRaw, .synFlood, .ackFlood, .rstFlood: 1
        case .udpFlood: 4
        case .tcpConnect: 64
        case .httpGet, .httpPost: 32
        case .tlsFlood: 16
        case .dnsFlood: 8
        case .slowloris: 32
        }
    }

    /// Packets per second for raw vectors. Uncapped raw floods starve the L7
    /// workers; SYN is lowest because every SYN-ACK costs the kernel a RST.
    var rate: Int {
        switch self {
        case .synFlood: 2_000
        case .ackFlood, .rstFlood: 6_000
        case .udpRaw: 15_000
        default: 8_000
        }
    }

    var proto: Int32 {
        switch self {
        case .icmpFlood: IPPROTO_ICMP
        case .udpRaw, .ipFrag, .udpFlood, .dnsFlood: IPPROTO_UDP
        default: IPPROTO_TCP
        }
    }
}

enum Plan {
    /// Focused vector set for a detected service, mirroring the desktop tool.
    static func forService(_ service: Service, port: UInt16?, rawOK: Bool) -> [Vector] {
        var v: [Vector] = rawOK ? [.synFlood, .udpRaw] : []
        switch service {
        case .http: v += [.httpGet, .slowloris]
        case .https: v += [.tlsFlood, .httpGet]
        case .dns: v += [.dnsFlood, .udpFlood]
        case .ssh, .smtp, .ftp, .generic: v += [.tcpConnect]
        case .unknown:
            switch port {
            case 443, 8443: v += [.tlsFlood]
            case 53: v += [.dnsFlood]
            case 80, 8080, 8000, 8888: v += [.httpGet]
            default: v += [.tcpConnect]
            }
        }
        return Array(Set(v)).sorted { $0.order < $1.order }
    }
}

extension Vector {
    var order: Int { Vector.allCases.firstIndex(of: self) ?? 0 }
}

struct Target: Sendable {
    var host: String
    var port: UInt16?
    var ips: [String]
    var service: Service
    var tls: Bool

    var primary: String? { ips.first }
}

/// Strip scheme, path and `:port` from what the user typed.
func normalize(_ input: String) -> (host: String, port: UInt16?, tls: Bool) {
    var s = input.trimmingCharacters(in: .whitespaces)
    var tls = false
    if let r = s.range(of: "https://") { s = String(s[r.upperBound...]); tls = true }
    else if let r = s.range(of: "http://") { s = String(s[r.upperBound...]) }
    if let i = s.firstIndex(of: "/") { s = String(s[..<i]) }
    var port: UInt16?
    if let i = s.lastIndex(of: ":"), let p = UInt16(s[s.index(after: i)...]), p > 0 {
        port = p
        s = String(s[..<i])
    }
    return (s, port, tls)
}

func classify(port: UInt16, banner: String) -> Service {
    let b = banner.lowercased()
    if b.hasPrefix("ssh-") { return .ssh }
    if b.hasPrefix("220") && b.contains("smtp") { return .smtp }
    if b.hasPrefix("220") && b.contains("ftp") { return .ftp }
    if b.contains("http/") || b.contains("server:") { return .http }
    return classify(port: port)
}

func classify(port: UInt16) -> Service {
    switch port {
    case 443, 8443, 9443, 4443: .https
    case 80, 8080, 8000, 8888, 3000, 5000, 9000: .http
    case 53: .dns
    case 22: .ssh
    case 25, 587, 465: .smtp
    case 21: .ftp
    default: .generic
    }
}

func bestService(_ ports: [UInt16]) -> (Service, UInt16?) {
    let rank: (UInt16) -> Int = { p in
        switch classify(port: p) {
        case .https: 0
        case .http: 1
        case .dns: 2
        case .ssh: 3
        case .smtp: 4
        case .ftp: 5
        case .generic: 6
        case .unknown: 7
        }
    }
    guard let p = ports.min(by: { rank($0) < rank($1) }) else { return (.unknown, nil) }
    return (classify(port: p), p)
}

func humanBytes(_ n: Double) -> String {
    let u = ["B", "KiB", "MiB", "GiB"]
    var v = n
    var i = 0
    while v >= 1024 && i < u.count - 1 { v /= 1024; i += 1 }
    return i == 0 ? String(format: "%.0f B", v) : String(format: "%.1f %@", v, u[i])
}

func humanRate(_ n: Double) -> String {
    if n >= 1_000_000 { return String(format: "%.2fM", n / 1_000_000) }
    if n >= 1_000 { return String(format: "%.1fk", n / 1_000) }
    return String(format: "%.0f", n)
}
