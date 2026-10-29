import Foundation
import Observation
import UIKit

enum LogLevel: String {
    case info = "INFO"
    case warn = "WARN"
    case error = "ERROR"
}

struct LogEntry: Identifiable {
    let id = UUID()
    let at: Date
    let level: LogLevel
    let category: String
    let message: String

    var line: String {
        let t = Self.stamp.string(from: at)
        return "\(t) \(level.rawValue.padding(toLength: 5, withPad: " ", startingAt: 0)) [\(category)] \(message)"
    }

    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()
}

/// Ring buffer plus an on-disk copy, so a run can be shared after the fact.
@MainActor
@Observable
final class LogStore {
    static let shared = LogStore()

    private(set) var entries: [LogEntry] = []
    private var handle: FileHandle?
    private let cap = 5_000

    var fileURL: URL {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("rustdos.log")
    }

    var text: String {
        entries.map(\.line).joined(separator: "\n")
    }

    private init() {
        FileManager.default.createFile(atPath: fileURL.path, contents: nil)
        handle = try? FileHandle(forWritingTo: fileURL)
        write(.info, "app", "RustDoS \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?") on \(UIDevice.current.model), iOS \(UIDevice.current.systemVersion)")
        NSSetUncaughtExceptionHandler { exception in
            let line = "FATAL \(exception.name.rawValue): \(exception.reason ?? "") \(exception.callStackSymbols.joined(separator: " | "))\n"
            let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("rustdos.log")
            if let h = try? FileHandle(forWritingTo: url) {
                try? h.seekToEnd()
                try? h.write(contentsOf: Data(line.utf8))
                try? h.close()
            }
        }
    }

    func write(_ level: LogLevel, _ category: String, _ message: String) {
        let entry = LogEntry(at: Date(), level: level, category: category, message: message)
        entries.append(entry)
        if entries.count > cap { entries.removeFirst(entries.count - cap) }
        try? handle?.write(contentsOf: Data((entry.line + "\n").utf8))
    }

    func clear() {
        entries.removeAll()
        try? handle?.truncate(atOffset: 0)
    }
}

/// Fire-and-forget logging for worker threads.
enum Log {
    static func info(_ category: String, _ message: String) {
        Task { @MainActor in LogStore.shared.write(.info, category, message) }
    }

    static func warn(_ category: String, _ message: String) {
        Task { @MainActor in LogStore.shared.write(.warn, category, message) }
    }

    static func error(_ category: String, _ message: String) {
        Task { @MainActor in LogStore.shared.write(.error, category, message) }
    }
}

func errnoText(_ code: Int32) -> String {
    "\(code) \(String(cString: strerror(code)))"
}
