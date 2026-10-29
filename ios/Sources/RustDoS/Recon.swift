import Darwin
import Foundation

/// Resolution, port scanning, service fingerprinting and the bypass recon
/// (CDN detection, crt.sh subdomains, origin candidates).
enum Recon {
    static let quickPorts: [UInt16] = [80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 3306, 5432, 6379, 27017, 8000, 8888, 3000, 5000, 9000, 9200, 11211, 5900, 3389, 445, 139, 23]

    static let cfRanges = [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
    ]

    static let originNames = [
        "direct", "origin", "origin-www", "www", "www2", "web", "ftp", "mail", "smtp", "pop", "imap",
        "webmail", "cpanel", "whm", "dev", "staging", "stage", "test", "beta", "old", "legacy", "api",
        "admin", "portal", "vpn", "git", "ssh", "backup", "cdn", "static", "assets", "media", "img", "files",
    ]

    static func resolve(_ host: String) -> [String] {
        var probe = in_addr()
        if inet_pton(AF_INET, host, &probe) == 1 { return [host] }
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let head = res else { return [] }
        defer { freeaddrinfo(res) }
        var ips: [String] = []
        for ai in sequence(first: head, next: { $0.pointee.ai_next }) {
            guard let sa = ai.pointee.ai_addr else { continue }
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sa, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(cString: buf)
                if !ips.contains(ip) { ips.append(ip) }
            }
        }
        return ips
    }

    static func inCIDR(_ ip: String, _ cidr: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let bits = UInt32(parts[1]), bits <= 32 else { return false }
        var base = in_addr()
        var addr = in_addr()
        guard inet_pton(AF_INET, String(parts[0]), &base) == 1, inet_pton(AF_INET, ip, &addr) == 1 else { return false }
        let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
        return (addr.s_addr & mask) == (base.s_addr & mask)
    }

    static func cdn(byIPs ips: [String]) -> String? {
        ips.contains { ip in cfRanges.contains { inCIDR(ip, $0) } } ? "Cloudflare" : nil
    }

    static func cdn(byHeaders headers: [AnyHashable: Any]) -> String? {
        let h = headers.map { "\($0.key): \($0.value)" }.joined(separator: "\n").lowercased()
        if h.contains("cf-ray") || h.contains("server: cloudflare") { return "Cloudflare" }
        if h.contains("server: fastly") || h.contains("x-served-by: cache-") { return "Fastly" }
        if h.contains("server: cloudfront") || h.contains("x-amz-cf-id") { return "CloudFront" }
        if h.contains("akamai") || h.contains("x-akamai") { return "Akamai" }
        if h.contains("server: varnish") || h.contains("x-varnish") { return "Varnish" }
        return nil
    }

    static func httpHeaders(host: String, tls: Bool) async -> [AnyHashable: Any] {
        guard let url = URL(string: "\(tls ? "https" : "http")://\(host)/") else { return [:] }
        var req = URLRequest(url: url, timeoutInterval: 6)
        req.httpMethod = "HEAD"
        req.setValue(Engine.uaPool[0], forHTTPHeaderField: "User-Agent")
        guard let (_, resp) = try? await URLSession.shared.data(for: req),
              let http = resp as? HTTPURLResponse else { return [:] }
        return http.allHeaderFields
    }

    /// Banner grab, then classify. Returns the service and the banner.
    static func fingerprint(ip: String, port: UInt16) -> (Service, String) {
        guard let fd = Net.connect(ip, port, timeoutMs: 900) else {
            return (port == 53 ? .dns : .unknown, "")
        }
        defer { close(fd) }
        Net.setRecvTimeout(fd, ms: 900)
        var buf = [UInt8](repeating: 0, count: 256)
        let n = recv(fd, &buf, buf.count, 0)
        let banner = n > 0 ? String(decoding: buf[..<n], as: UTF8.self) : ""
        var service = classify(port: port, banner: banner)
        if service == .http && port == 443 { service = .https }
        return (service, banner)
    }

    /// Probe one port. Returns the banner when the port is open.
    static func probe(ip: String, port: UInt16, timeoutMs: Int32) -> String? {
        guard let fd = Net.connect(ip, port, timeoutMs: timeoutMs) else { return nil }
        defer { close(fd) }
        Net.setRecvTimeout(fd, ms: timeoutMs)
        var buf = [UInt8](repeating: 0, count: 256)
        let n = recv(fd, &buf, buf.count, 0)
        return n > 0 ? String(decoding: buf[..<n], as: UTF8.self) : ""
    }

    final class Token: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        var cancelled: Bool {
            lock.lock(); defer { lock.unlock() }
            return value
        }
        func cancel() {
            lock.lock(); defer { lock.unlock() }
            value = true
        }
    }

    /// Sweep every port with `concurrency` workers, streaming hits as they land.
    static func scanAll(ip: String, concurrency: Int = 512, token: Token,
                        onFound: @escaping @Sendable (UInt16) -> Void,
                        progress: @escaping @Sendable (Int) -> Void) async -> [UInt16] {
        let lock = NSLock()
        var found: [UInt16] = []
        var next: UInt32 = 1
        var done = 0

        func take() -> UInt16? {
            lock.lock(); defer { lock.unlock() }
            while next <= 65535 {
                let p = UInt16(next)
                next += 1
                if !found.contains(p) { return p }
            }
            return nil
        }

        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            let group = DispatchGroup()
            for _ in 0..<concurrency {
                group.enter()
                DispatchQueue.global(qos: .utility).async {
                    defer { group.leave() }
                    while !token.cancelled, let p = take() {
                        if let fd = Net.connect(ip, p, timeoutMs: 400) {
                            close(fd)
                            lock.lock()
                            found.append(p)
                            lock.unlock()
                            onFound(p)
                        }
                        lock.lock()
                        done += 1
                        let d = done
                        lock.unlock()
                        progress(d)
                    }
                }
            }
            group.notify(queue: .global()) { cont.resume() }
        }
        return found.sorted()
    }

    static func crtSh(_ host: String) async -> [String] {
        guard let url = URL(string: "https://crt.sh/?q=\(host.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? host)&output=json") else { return [] }
        var req = URLRequest(url: url, timeoutInterval: 12)
        req.setValue(Engine.uaPool[0], forHTTPHeaderField: "User-Agent")
        guard let (data, _) = try? await URLSession.shared.data(for: req),
              let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
        var names: [String] = []
        for row in rows {
            guard let value = row["name_value"] as? String else { continue }
            for name in value.split(separator: "\n") {
                let n = name.trimmingCharacters(in: .whitespaces).lowercased()
                guard !n.hasPrefix("*"), n.hasSuffix(host), n != host, !names.contains(n) else { continue }
                names.append(n)
            }
        }
        return Array(names.prefix(40))
    }

    /// Keep only subdomains that still resolve, and drop the ones behind the CDN.
    static func verify(_ names: [String]) -> [(String, [String])] {
        names.compactMap { name in
            let ips = resolve(name)
            return ips.isEmpty ? nil : (name, ips)
        }
    }

    static func originCandidates(_ host: String) -> [(String, String)] {
        originNames.compactMap { sub in
            let name = "\(sub).\(host)"
            guard let ip = resolve(name).first, cdn(byIPs: [ip]) == nil else { return nil }
            return (name, ip)
        }
    }

    /// Confirm a candidate actually serves the site for the real Host header.
    static func servesHost(ip: String, port: UInt16, host: String) -> Bool {
        guard let fd = Net.connect(ip, port, timeoutMs: 1_500) else { return false }
        defer { close(fd) }
        Net.setRecvTimeout(fd, ms: 1_500)
        let req = "GET / HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: \(Engine.uaPool[0])\r\nConnection: close\r\n\r\n"
        guard Net.write(fd, Array(req.utf8)) else { return false }
        var buf = [UInt8](repeating: 0, count: 16)
        let n = recv(fd, &buf, buf.count, 0)
        guard n > 6 else { return false }
        let line = String(decoding: buf[..<n], as: UTF8.self)
        return line.hasPrefix("HTTP/1.") && !line.contains(" 5")
    }
}
