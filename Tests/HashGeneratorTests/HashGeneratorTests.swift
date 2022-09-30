//===----------------------------------------------------------------------===//
//
// HashGeneratorTests.swift
//
// Created: 2022. Author: Jordan Baird.
//
//===----------------------------------------------------------------------===//

import XCTest
import CommonCrypto
@testable import HashGenerator

final class HashGeneratorTests: XCTestCase {
  func testSHA256() {
    let generator = HashGenerator(.sha256)
    XCTAssertEqual(
      generator.hash("Hello").string(),
      "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969")
  }
  
  func testSHA384() {
    let generator = HashGenerator(.sha384)
    XCTAssertEqual(
      generator.hash("Hello").string(),
      "3519fe5ad2c596efe3e276a6f351b8fc0b03db861782490d45f7598ebd0ab5fd5520ed102f38c4a5ec834e98668035fc")
  }
  
  func testSHA512() {
    let generator = HashGenerator(.sha512)
    XCTAssertEqual(
      generator.hash("Hello").string(),
      "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315")
  }
  
  func testSHA1() {
    let generator = HashGenerator(.sha1)
    XCTAssertEqual(
      generator.hash("Hello").string(),
      "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0")
  }
  
  func testMD5() {
    let generator = HashGenerator(.md5)
    XCTAssertEqual(
      generator.hash("Hello").string(),
      "8b1a9953c4611296a827abf8c47804d7")
  }
  
  func testSalt() {
    let valueToBeHashed = "Hello, world!"
    let generator = HashGenerator(using: .sha256)
    
    let salt1 = HashGenerator.generateSalt(length: 20, kind: .data)
    let digest1 = generator.append(salt: salt1).hash(valueToBeHashed)
    
    let salt2 = HashGenerator.generateSalt(length: 20, kind: .data)
    let digest2 = generator.append(salt: salt2).hash(valueToBeHashed)
    
    XCTAssertNotEqual(digest1, digest2)
  }
  
  func testGenerateRandomBytesCommonCrypto() {
    measure {
      var bytes = [UInt8](repeating: 0, count: 200)
      CCRandomGenerateBytes(&bytes, 200)
    }
  }
  
  func testGenerateRandomBytesSec() {
    measure {
      var bytes = [UInt8](repeating: 0, count: 200)
      _ = SecRandomCopyBytes(kSecRandomDefault, 200, &bytes)
    }
  }
  
  func testGenerateRandomBytesSystem() {
    measure {
      var bytes = [UInt8]()
      while bytes.count < 200 {
        bytes.append(.random(in: 0...255))
      }
    }
  }
}
