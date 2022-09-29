// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "HashGenerator",
    products: [
        .library(
            name: "HashGenerator",
            targets: ["HashGenerator"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-docc-plugin",
            from: "1.0.0"
        ),
    ],
    targets: [
        .target(
            name: "HashGenerator",
            dependencies: []
        ),
        .testTarget(
            name: "HashGeneratorTests",
            dependencies: ["HashGenerator"]
        ),
    ]
)
