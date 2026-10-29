import Foundation
import Observation

enum Health: String {
    case unknown = "no sample"
    case up = "up"
    case degraded = "degraded"
    case down = "down"

    var tint: String {
        switch self {
        case .unknown: "slate"
        case .up: "green"
        case .degraded: "amber"
        case .down: "red"
        }
    }
}

@MainActor
@Observable
final class AppModel {
    enum Phase { case setup, scanning, selecting, running, stopped }

    var phase: Phase = .setup
    var targetInput = ""
    var portInput = ""
    var minutes = 0
    var error: String?

    var target: Target?
    var openPorts: [UInt16] = []
    var scanned = 0
    var scanTotal = 65_535
    var scanning = false
    var service: Service = .unknown
    var cdn: String?
    var subdomains: [(name: String, ips: [String])] = []
    var selectedSubs: Set<String> = []
    var origins: [String] = []
    var rawOK = true

    var selected: Set<Vector> = []
    var state: RunState?
    var snapshot = Snapshot()
    var elapsed: TimeInterval = 0
    var pps = 0.0
    var bps = 0.0
    var health: Health = .unknown
    var latency = 0
    var successRate: Double?

    private var scanToken: Recon.Token?
    private var ticker: Task<Void, Never>?
    private var prober: Task<Void, Never>?
    private var deadline: Date?

    var port: UInt16? {
        if let p = UInt16(portInput.trimmingCharacters(in: .whitespaces)), p > 0 { return p }
        return target?.port
    }

    var running: Bool { phase == .running }

    // MARK: - scan

    func scan() async {
        error = nil
        let (host, typedPort, tls) = normalize(targetInput)
        guard !host.isEmpty else {
            error = "Enter a host, IP or URL first."
            return
        }
        if !portInput.isEmpty, UInt16(portInput) == nil {
            error = "Port must be 1-65535."
            return
        }
        let ips = Recon.resolve(host)
        guard !ips.isEmpty else {
            error = "\(host) does not resolve to IPv4."
            return
        }

        let port = typedPort ?? (UInt16(portInput) ?? nil)
        target = Target(host: host, port: port, ips: ips, service: .unknown, tls: tls || port == 443 || port == 8443)
        phase = .scanning
        openPorts = []
        scanned = 0
        scanning = true
        scanTotal = port == nil ? 65_535 : 1
        subdomains = []
        selectedSubs = []
        origins = []
        cdn = nil

        if let port {
            let banner = Recon.probe(ip: ips[0], port: port, timeoutMs: 900)
            service = banner.map { classify(port: port, banner: $0) } ?? (port == 53 ? .dns : .unknown)
            openPorts = banner == nil ? [] : [port]
            scanned = 1
        } else {
            let token = Recon.Token()
            scanToken = token
            let ip = ips[0]
            _ = await Recon.scanAll(
                ip: ip,
                token: token,
                onFound: { [weak self] p in Task { @MainActor in self?.openPorts.append(p) } },
                progress: { [weak self] n in Task { @MainActor in self?.scanned = n } }
            )
            let (svc, best) = bestService(openPorts)
            service = svc
            if let best { target?.port = best }
        }

        scanning = false
        scanToken = nil
        target?.service = service
        if service == .https { target?.tls = true }
        if target?.port == nil, let first = openPorts.first { target?.port = first }

        selected = Set(Plan.forService(service, port: target?.port, rawOK: rawOK))
        phase = .selecting

        Task { await recon() }
    }

    func cancelScan() {
        scanToken?.cancel()
        scanning = false
        phase = .setup
    }

    private func recon() async {
        guard let target else { return }
        let ips = target.ips
        if let byIP = Recon.cdn(byIPs: ips) {
            cdn = byIP
        } else {
            let headers = await Recon.httpHeaders(host: target.host, tls: target.tls)
            cdn = Recon.cdn(byHeaders: headers)
        }
        let names = await Recon.crtSh(target.host)
        let verified = Recon.verify(names)
        subdomains = verified
        if let port = target.port {
            origins = Recon.originCandidates(target.host)
                .filter { Recon.servesHost(ip: $0.1, port: port, host: target.host) }
                .map(\.0)
        }
    }

    // MARK: - attack

    func start() {
        guard var target, !selected.isEmpty else { return }
        let port = port ?? selected.sorted { $0.order < $1.order }.first?.defaultPort ?? 80
        target.port = port
        target.service = service
        self.target = target

        let state = Engine.start(target: target, vectors: Array(selected), port: port)
        self.state = state
        snapshot = Snapshot()
        elapsed = 0
        pps = 0
        bps = 0
        health = .unknown
        successRate = nil
        latency = 0
        deadline = minutes > 0 ? Date().addingTimeInterval(Double(minutes) * 60) : nil
        phase = .running
        tick()
        probe(target: target, port: port, state: state)
    }

    func stop() {
        state?.stop()
        ticker?.cancel()
        prober?.cancel()
        state = nil
        phase = .stopped
    }

    func restart() {
        phase = .selecting
        snapshot = Snapshot()
        elapsed = 0
        pps = 0
        bps = 0
        health = .unknown
    }

    func reset() {
        stop()
        phase = .setup
        target = nil
        openPorts = []
        selected = []
        subdomains = []
        origins = []
        cdn = nil
        error = nil
    }

    func toggle(_ v: Vector) {
        if selected.contains(v) { selected.remove(v) } else { selected.insert(v) }
    }

    // MARK: - timers

    private func tick() {
        ticker = Task { [weak self] in
            var last = Snapshot()
            var lastTime = Date()
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(250))
                guard let self, let state = self.state else { return }
                let now = state.snapshot()
                let dt = Date().timeIntervalSince(lastTime)
                self.snapshot = now
                self.elapsed = Date().timeIntervalSince(lastTime) + self.elapsed
                if dt > 0 {
                    self.pps = Double(now.totalPackets - last.totalPackets) / dt
                    self.bps = Double(now.totalBytes - last.totalBytes) / dt
                }
                last = now
                lastTime = Date()
                if let deadline = self.deadline, Date() >= deadline {
                    self.stop()
                    return
                }
            }
        }
    }

    private func probe(target: Target, port: UInt16, state: RunState) {
        prober = Task { [weak self] in
            var fails = 0
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(500))
                guard let self, let ip = target.primary else { return }
                let t0 = Date()
                let fd = Net.connect(ip, port, timeoutMs: 1_200)
                if let fd {
                    close(fd)
                    fails = 0
                    let ms = Int(Date().timeIntervalSince(t0) * 1000)
                    self.latency = self.latency == 0 ? ms : (self.latency * 7 + ms) / 8
                    self.health = self.latency > 800 ? .degraded : .up
                    let prev = self.successRate ?? 1
                    self.successRate = prev * 0.8 + 0.2
                } else {
                    fails += 1
                    self.health = fails >= 3 ? .down : .degraded
                    self.successRate = (self.successRate ?? 1) * 0.8
                }
            }
        }
    }
}
