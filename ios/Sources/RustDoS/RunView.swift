import SwiftUI

struct RunView: View {
    @Bindable var model: AppModel

    private var maxPackets: UInt64 {
        max(model.snapshot.packets.max() ?? 1, 1)
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    header
                    tiles
                    healthCard
                    vectorList
                }
                .padding(20)
            }

            controls
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(model.target?.host ?? "").font(.title3.weight(.bold)).lineLimit(1)
                Spacer()
                Pill(text: model.running ? "ARMED" : "STOPPED", tint: model.running ? Theme.accent : .white.opacity(0.4), filled: model.running)
            }
            HStack(spacing: 6) {
                Pill(text: "port \(model.port.map(String.init) ?? "-")")
                Pill(text: "\(model.selected.count) vectors")
                Pill(text: time)
            }
        }
    }

    private var time: String {
        let s = Int(model.elapsed)
        return String(format: "%02d:%02d", s / 60, s % 60)
    }

    private var tiles: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
            StatTile(label: "packets / s", value: humanRate(model.pps), tint: Theme.accent)
            StatTile(label: "throughput", value: "\(humanBytes(model.bps))/s")
            StatTile(label: "sent", value: humanRate(Double(model.snapshot.totalPackets)))
            StatTile(label: "errors", value: humanRate(Double(model.snapshot.errors)), tint: model.snapshot.errors > 0 ? Theme.danger : .white)
        }
    }

    private var healthCard: some View {
        Card {
            HStack(spacing: 12) {
                Circle()
                    .fill(Theme.tint(model.health.tint))
                    .frame(width: 10, height: 10)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Target \(model.health.rawValue)")
                        .font(.subheadline.weight(.semibold))
                    Text(model.latency == 0 ? "waiting for first probe" : "\(model.latency) ms round trip")
                        .font(.caption2)
                        .foregroundStyle(.white.opacity(0.4))
                }
                Spacer()
                if let rate = model.successRate {
                    Text("\(Int(rate * 100))%")
                        .font(.title3.weight(.bold).monospacedDigit())
                        .foregroundStyle(Theme.tint(model.health.tint))
                }
            }
        }
    }

    private var vectorList: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionTitle(text: "Per vector")
            Card {
                VStack(spacing: 10) {
                    ForEach(Vector.allCases.filter { model.selected.contains($0) }) { v in
                        let count = model.snapshot.packets[v.order]
                        VStack(spacing: 4) {
                            HStack {
                                Text(v.name).font(.caption.weight(.medium))
                                Spacer()
                                Text(humanRate(Double(count)))
                                    .font(.caption.monospacedDigit())
                                    .foregroundStyle(.white.opacity(0.5))
                            }
                            GeometryReader { geo in
                                Capsule()
                                    .fill(Theme.accent.opacity(0.7))
                                    .frame(width: max(2, geo.size.width * CGFloat(Double(count) / Double(maxPackets))))
                            }
                            .frame(height: 4)
                        }
                    }
                }
            }
        }
    }

    private var controls: some View {
        VStack(spacing: 10) {
            if model.running {
                PrimaryButton(title: "Stop attack", symbol: "stop.fill", tint: Theme.danger) {
                    model.stop()
                }
            } else {
                PrimaryButton(title: "Run again", symbol: "arrow.clockwise") {
                    model.start()
                }
                Button("New target") { model.reset() }
                    .font(.footnote)
                    .foregroundStyle(.white.opacity(0.4))
            }
        }
        .padding(20)
        .background(.ultraThinMaterial)
    }
}
