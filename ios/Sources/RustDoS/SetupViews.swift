import SwiftUI

struct RootView: View {
    @State private var model = AppModel()

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            Group {
                switch model.phase {
                case .setup: SetupView(model: model)
                case .scanning: ScanningView(model: model)
                case .selecting: SelectView(model: model)
                case .running, .stopped: RunView(model: model)
                }
            }
            .transition(.opacity)
        }
        .preferredColorScheme(.dark)
        .tint(Theme.accent)
        .animation(.easeInOut(duration: 0.2), value: model.phase)
    }
}

struct SetupView: View {
    @Bindable var model: AppModel
    @FocusState private var focused: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Header()

                Card {
                    VStack(alignment: .leading, spacing: 14) {
                        FieldLabel(text: "Target")
                        TextField("example.com, 1.1.1.1 or a URL", text: $model.targetInput)
                            .textFieldStyle(.plain)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                            .focused($focused)
                            .font(.body.weight(.medium))
                            .padding(.vertical, 10)
                            .padding(.horizontal, 12)
                            .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 12, style: .continuous))

                        HStack(spacing: 12) {
                            VStack(alignment: .leading, spacing: 6) {
                                FieldLabel(text: "Port")
                                TextField("scan all", text: $model.portInput)
                                    .textFieldStyle(.plain)
                                    .keyboardType(.numberPad)
                                    .font(.body.monospacedDigit())
                                    .padding(.vertical, 10)
                                    .padding(.horizontal, 12)
                                    .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                            }
                            VStack(alignment: .leading, spacing: 6) {
                                FieldLabel(text: "Duration")
                                Stepper(value: $model.minutes, in: 0...120) {
                                    Text(model.minutes == 0 ? "Unlimited" : "\(model.minutes) min")
                                        .font(.body.monospacedDigit())
                                }
                                .padding(.vertical, 6)
                                .padding(.horizontal, 12)
                                .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                            }
                        }
                    }
                }

                if let error = model.error {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(Theme.danger)
                }

                PrimaryButton(title: "Scan target", symbol: "magnifyingglass", disabled: model.targetInput.isEmpty) {
                    focused = false
                    Task { await model.scan() }
                }

                Text("No port scans all 65 535 ports and picks the busiest service. Raw vectors (SYN, ACK, RST, ICMP, spoofed UDP) need no root on iOS.")
                    .font(.footnote)
                    .foregroundStyle(.white.opacity(0.35))
            }
            .padding(20)
        }
        .scrollDismissesKeyboard(.interactively)
    }
}

struct ScanningView: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Header()

            Card {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text(model.target?.host ?? "").font(.headline).lineLimit(1)
                        Spacer()
                        Pill(text: "\(model.scanned) / \(model.scanTotal)")
                    }
                    ProgressView(value: Double(model.scanned), total: Double(max(model.scanTotal, 1)))
                        .tint(Theme.accent)
                    Text("\(model.openPorts.count) open ports found")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.45))
                }
            }

            ScrollView {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 62), spacing: 8)], spacing: 8) {
                    ForEach(model.openPorts, id: \.self) { port in
                        Text("\(port)")
                            .font(.footnote.monospacedDigit().weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .background(Theme.card, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }
                }
            }

            PrimaryButton(title: "Cancel scan", symbol: "xmark", tint: .white.opacity(0.15)) {
                model.cancelScan()
            }
        }
        .padding(20)
    }
}
