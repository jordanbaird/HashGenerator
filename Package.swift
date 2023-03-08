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
