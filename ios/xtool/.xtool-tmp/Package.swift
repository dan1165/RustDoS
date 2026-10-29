// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "RustDoS-Builder",
    platforms: [
        .iOS("17.0"),
    ],
    dependencies: [
        .package(name: "RootPackage", path: "../.."),
    ],
    targets: [
        .executableTarget(
    name: "RustDoS-App",
    dependencies: [
        .product(name: "RustDoS", package: "RootPackage"),
    ],
    linkerSettings: [
    .unsafeFlags([
        "-Xlinker", "-rpath", "-Xlinker", "@executable_path/Frameworks",
    ]),
]
)
    ]
)
