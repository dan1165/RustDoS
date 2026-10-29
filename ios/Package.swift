// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "RustDoS",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "RustDoS",
            targets: ["RustDoS"]
        ),
    ],
    targets: [
        .target(
            name: "RustDoS",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
