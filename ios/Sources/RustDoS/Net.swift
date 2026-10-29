import Darwin
import Foundation

/// Thin POSIX layer: sockets, packet builders and checksums.
enum Net {
    static func makeSockaddr(_ ip: String, _ port: UInt16) -> sockaddr_in {
        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = port.bigEndian
        _ = withUnsafeMutablePointer(to: &sa.sin_addr) { inet_pton(AF_INET, ip, $0) }
        return sa
    }

    static func withSockaddr<T>(_ sa: inout sockaddr_in, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
        withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                body($0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    /// Non-blocking connect with a poll timeout. Returns a blocking fd or nil.
    static func connect(_ ip: String, _ port: UInt16, timeoutMs: Int32 = 3_000) -> Int32? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        var sa = makeSockaddr(ip, port)
        let r = withSockaddr(&sa) { Darwin.connect(fd, $0, $1) }
        if r != 0 {
            guard errno == EINPROGRESS else { close(fd); return nil }
            var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            guard poll(&p, 1, timeoutMs) > 0 else { close(fd); return nil }
            var err: Int32 = 0
            var len = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0, err == 0 else {
                close(fd)
                return nil
            }
        }
        _ = fcntl(fd, F_SETFL, flags)
        return fd
    }

    static func setRecvTimeout(_ fd: Int32, ms: Int32) {
        var tv = timeval(tv_sec: Int(ms / 1000), tv_usec: Int32((ms % 1000) * 1000))
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    static func write(_ fd: Int32, _ data: [UInt8]) -> Bool {
        data.withUnsafeBytes { buf in
            var off = 0
            while off < buf.count {
                let n = send(fd, buf.baseAddress! + off, buf.count - off, 0)
                if n <= 0 { return false }
                off += n
            }
            return true
        }
    }

    static func udpSocket() -> Int32? {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        return fd >= 0 ? fd : nil
    }

    static func sendTo(_ fd: Int32, _ data: [UInt8], _ ip: String, _ port: UInt16) -> Int {
        var sa = makeSockaddr(ip, port)
        return data.withUnsafeBytes { buf in
            Int(withSockaddr(&sa) { sendto(fd, buf.baseAddress, buf.count, 0, $0, $1) })
        }
    }

    static func rawSocket(_ proto: Int32) -> Int32? {
        let fd = socket(AF_INET, SOCK_RAW, proto)
        guard fd >= 0 else { return nil }
        var one: Int32 = 1
        _ = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, socklen_t(MemoryLayout<Int32>.size))
        return fd
    }

    /// Our own IPv4 address, taken from the first interface that has one.
    static func localIP() -> String {
        var addrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrs) == 0, let head = addrs else { return "0.0.0.0" }
        defer { freeifaddrs(addrs) }
        var fallback = "0.0.0.0"
        for ifa in sequence(first: head, next: { $0.pointee.ifa_next }) {
            guard let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let ip = String(cString: host)
            if ip.hasPrefix("127.") { continue }
            if String(cString: ifa.pointee.ifa_name) == "en0" { return ip }
            if fallback == "0.0.0.0" { fallback = ip }
        }
        return fallback
    }
}

enum Packet {
    static func checksum(_ data: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < data.count {
            sum += UInt32(data[i]) << 8 | UInt32(data[i + 1])
            i += 2
        }
        if i < data.count { sum += UInt32(data[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum & 0xffff)
    }

    static func randPort() -> UInt16 { UInt16.random(in: 1024..<32768) }
    static func randU32() -> UInt32 { UInt32.random(in: 0...UInt32.max) }

    static func bytes(_ ip: String) -> [UInt8] {
        var a = in_addr()
        guard inet_pton(AF_INET, ip, &a) == 1 else { return [0, 0, 0, 0] }
        return withUnsafeBytes(of: a.s_addr) { Array($0) }
    }

    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
    static func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }

    /// IPv4 header. Darwin wants ip_len/ip_off in host byte order with
    /// IP_HDRINCL, so those two fields are written little-endian.
    static func ipHeader(src: [UInt8], dst: [UInt8], proto: Int32, payload: Int, id: UInt16, fragOff: UInt16, moreFrags: Bool) -> [UInt8] {
        let total = UInt16(20 + payload)
        var h: [UInt8] = [0x45, 0x00]
        h += withUnsafeBytes(of: total.littleEndian) { Array($0) }
        h += be16(id)
        let off = withUnsafeBytes(of: (fragOff | (moreFrags ? 0x2000 : 0)).littleEndian) { Array($0) }
        h += off
        h += [64, UInt8(proto), 0, 0]
        h += src + dst
        let sum = checksum(h)
        h[10] = UInt8(sum >> 8)
        h[11] = UInt8(sum & 0xff)
        return h
    }

    static func pseudo(src: [UInt8], dst: [UInt8], proto: UInt8, len: UInt16) -> [UInt8] {
        src + dst + [0, proto] + be16(len)
    }

    static func tcp(src: [UInt8], dst: [UInt8], sport: UInt16, dport: UInt16, seq: UInt32, ack: UInt32, flags: UInt8) -> [UInt8] {
        var h = be16(sport) + be16(dport) + be32(seq) + be32(ack) + [0x50, flags] + be16(65535) + [0, 0, 0, 0]
        let sum = checksum(pseudo(src: src, dst: dst, proto: UInt8(IPPROTO_TCP), len: UInt16(h.count)) + h)
        h[16] = UInt8(sum >> 8)
        h[17] = UInt8(sum & 0xff)
        return h
    }

    static func udp(src: [UInt8], dst: [UInt8], sport: UInt16, dport: UInt16, payload: [UInt8]) -> [UInt8] {
        var h = be16(sport) + be16(dport) + be16(UInt16(8 + payload.count)) + [0, 0]
        let sum = checksum(pseudo(src: src, dst: dst, proto: UInt8(IPPROTO_UDP), len: UInt16(h.count + payload.count)) + h + payload)
        h[6] = UInt8(sum >> 8)
        h[7] = UInt8(sum & 0xff)
        return h + payload
    }

    static func icmp(id: UInt16, seq: UInt16, payload: [UInt8]) -> [UInt8] {
        var h: [UInt8] = [8, 0, 0, 0] + be16(id) + be16(seq) + payload
        let sum = checksum(h)
        h[2] = UInt8(sum >> 8)
        h[3] = UInt8(sum & 0xff)
        return h
    }
}
