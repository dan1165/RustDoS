import SwiftUI

struct SelectView: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    targetCard

                    if !model.subdomains.isEmpty {
                        subdomainCard
                    }

                    if !model.origins.isEmpty {
                        originCard
                    }

                    ForEach(Layer.allCases, id: \.self) { layer in
                        let vectors = Vector.allCases.filter { $0.layer == layer }
                        VStack(alignment: .leading, spacing: 8) {
                            SectionTitle(text: "\(layer.rawValue) vectors")
                            Card {
                                VStack(spacing: 0) {
                                    ForEach(vectors) { v in
                                        VectorRow(vector: v, on: model.selected.contains(v)) {
                                            model.toggle(v)
                                        }
                                        if v != vectors.last { Divider().overlay(Theme.stroke) }
                                    }
                                }
                            }
                        }
                    }
                }
                .padding(20)
            }

            VStack(spacing: 10) {
                PrimaryButton(
                    title: model.selected.isEmpty ? "Pick a vector" : "Start \(model.selected.count) vectors",
                    symbol: "bolt.fill",
                    disabled: model.selected.isEmpty
                ) {
                    model.start()
                }
                Button("Edit target") { model.reset() }
                    .font(.footnote)
                    .foregroundStyle(.white.opacity(0.4))
            }
            .padding(20)
            .background(.ultraThinMaterial)
        }
    }

    private var targetCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(model.target?.host ?? "").font(.headline).lineLimit(1)
                    Spacer()
                    Pill(text: model.service.label, tint: Theme.accent)
                    LogButton()
                }
                HStack(spacing: 6) {
                    Pill(text: "port \(model.port.map(String.init) ?? "auto")")
                    if let cdn = model.cdn {
                        Pill(text: "\(cdn) edge", tint: Theme.danger)
                    }
                    if !model.rawOK {
                        Pill(text: "raw blocked", tint: Theme.danger)
                    }
                }
                Text(model.target?.ips.joined(separator: "  ") ?? "")
                    .font(.caption.monospaced())
                    .foregroundStyle(.white.opacity(0.4))
            }
        }
    }

    private var subdomainCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionTitle(text: "Subdomains", trailing: "\(model.selectedSubs.count) selected")
            Card {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 120), spacing: 8)], alignment: .leading, spacing: 8) {
                    ForEach(model.subdomains, id: \.name) { sub in
                        let on = model.selectedSubs.contains(sub.name)
                        Button {
                            if on { model.selectedSubs.remove(sub.name) } else { model.selectedSubs.insert(sub.name) }
                        } label: {
                            Text(sub.name)
                                .font(.caption2)
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 7)
                                .background(on ? Theme.accent.opacity(0.22) : Color.white.opacity(0.05), in: Capsule())
                                .foregroundStyle(on ? Theme.accent : .white.opacity(0.6))
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }

    private var originCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionTitle(text: "Origin candidates", trailing: "bypass")
            Card {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(model.origins, id: \.self) { origin in
                        Label(origin, systemImage: "arrow.triangle.branch")
                            .font(.caption)
                            .foregroundStyle(Theme.accent)
                    }
                }
            }
        }
    }
}

struct VectorRow: View {
    let vector: Vector
    let on: Bool
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
            HStack(spacing: 12) {
                Image(systemName: on ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(on ? Theme.accent : .white.opacity(0.25))
                VStack(alignment: .leading, spacing: 2) {
                    Text(vector.name).font(.subheadline.weight(.medium))
                    Text(vector.desc).font(.caption2).foregroundStyle(.white.opacity(0.4))
                }
                Spacer()
                if vector.needsRaw {
                    Pill(text: "raw", tint: .white.opacity(0.3))
                }
            }
            .padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
