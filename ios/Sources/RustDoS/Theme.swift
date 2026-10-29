import SwiftUI

enum Theme {
    static let accent = Color(red: 0.36, green: 0.95, blue: 0.66)
    static let danger = Color(red: 1.0, green: 0.42, blue: 0.42)
    static let card = Color.white.opacity(0.055)
    static let stroke = Color.white.opacity(0.09)

    static let background = LinearGradient(
        colors: [Color(red: 0.055, green: 0.07, blue: 0.10), Color(red: 0.02, green: 0.03, blue: 0.05)],
        startPoint: .top, endPoint: .bottom
    )

    static func tint(_ name: String) -> Color {
        switch name {
        case "green": accent
        case "amber": Color(red: 1.0, green: 0.76, blue: 0.35)
        case "red": danger
        default: Color.white.opacity(0.45)
        }
    }
}

struct Card<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.stroke))
    }
}

struct Pill: View {
    let text: String
    var tint: Color = .white.opacity(0.45)
    var filled = false

    var body: some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(filled ? Color.black : tint)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(filled ? tint : tint.opacity(0.12), in: Capsule())
    }
}

struct FieldLabel: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(.caption2.weight(.bold))
            .tracking(1.1)
            .foregroundStyle(.white.opacity(0.4))
    }
}

struct PrimaryButton: View {
    let title: String
    var symbol: String
    var tint: Color = Theme.accent
    var disabled = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: symbol)
                Text(title).fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(disabled ? Color.white.opacity(0.08) : tint, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .foregroundStyle(disabled ? Color.white.opacity(0.35) : Color.black)
        }
        .disabled(disabled)
        .buttonStyle(.plain)
    }
}

struct StatTile: View {
    let label: String
    let value: String
    var tint: Color = .white

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label.uppercased())
                .font(.caption2.weight(.bold))
                .tracking(1)
                .foregroundStyle(.white.opacity(0.4))
            Text(value)
                .font(.title2.weight(.bold))
                .monospacedDigit()
                .foregroundStyle(tint)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Theme.stroke))
    }
}

struct Header: View {
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "bolt.fill")
                .font(.title3.weight(.bold))
                .foregroundStyle(Color.black)
                .frame(width: 42, height: 42)
                .background(Theme.accent, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            VStack(alignment: .leading, spacing: 1) {
                Text("RustDoS").font(.title2.weight(.bold))
                Text("L3–L7 stress tester").font(.caption).foregroundStyle(.white.opacity(0.45))
            }
            Spacer()
        }
    }
}

struct SectionTitle: View {
    let text: String
    var trailing: String?

    var body: some View {
        HStack {
            Text(text.uppercased())
                .font(.caption2.weight(.bold))
                .tracking(1.2)
                .foregroundStyle(.white.opacity(0.4))
            Spacer()
            if let trailing {
                Text(trailing).font(.caption2).foregroundStyle(.white.opacity(0.35))
            }
        }
    }
}
