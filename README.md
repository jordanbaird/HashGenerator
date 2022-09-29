# HashGenerator

A simple class for generating hashes using commonly available hash algorithms.

## Install

Add the following dependency to your `Package.swift` file:

```swift
.package(url: "https://github.com/jordanbaird/HashGenerator", from: "0.0.1")
```

## Usage

[Read full documentation here](https://jordanbaird.github.io/HashGenerator/documentation/hashgenerator/hashgenerator)

```swift
let generator = HashGenerator(using: .sha256)
let digest = generator.hash("Hello")
print(digest)
// Prints '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969'
```
