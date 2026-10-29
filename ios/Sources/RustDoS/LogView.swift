import SwiftUI

struct LogButton: View {
    @State private var show = false

    var body: some View {
        Button {
            show = true
        } label: {
            Image(systemName: "text.alignleft")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.white.opacity(0.6))
                .frame(width: 34, height: 34)
                .background(Color.white.opacity(0.08), in: Circle())
        }
        .buttonStyle(.plain)
        .sheet(isPresented: $show) { LogView() }
    }
}

struct LogView: View {
    @State private var store = LogStore.shared
    @State private var copied = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(store.entries) { entry in
                            Text(entry.line)
                                .font(.caption2.monospaced())
                                .foregroundStyle(tint(entry.level))
                                .textSelection(.enabled)
                                .id(entry.id)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                }
                .onChange(of: store.entries.count) {
                    if let last = store.entries.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
            .background(Color(red: 0.04, green: 0.05, blue: 0.07))
            .navigationTitle("Log")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Clear") { store.clear() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(copied ? "Copied" : "Copy") {
                        UIPasteboard.general.string = store.text
                        copied = true
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: store.fileURL) { Image(systemName: "square.and.arrow.up") }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func tint(_ level: LogLevel) -> Color {
        switch level {
        case .info: .white.opacity(0.7)
        case .warn: Color(red: 1.0, green: 0.76, blue: 0.35)
        case .error: Theme.danger
        }
    }
}
