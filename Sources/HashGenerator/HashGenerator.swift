//===----------------------------------------------------------------------===//
//
// HashGenerator.swift
//
// Created: 2022. Author: Jordan Baird.
//
//===----------------------------------------------------------------------===//

import Foundation
import CommonCrypto

/// Generate hash digests from several widely used hash algorithms.
///
/// Create a `HashGenerator` by choosing an algorithm. Then, hash some data
/// using one of several `hash(_:)` methods. An instance of ``Digest`` will
/// be produced, from which you retrieve the hash in the form of a string,
/// data, or bytes.
///
/// ```swift
/// let generator = HashGenerator(using: .sha256)
/// let digest = generator.hash("Hello, world!")
///
/// let string = digest.format(.string)
/// let data = digest.format(.data)
/// let bytes = digest.format(.bytes)
/// ```
///
/// The algorithm the generator uses can be changed at any given time.
///
/// ```swift
/// let generator = HashGenerator(using: .sha256)
///
/// print(generator.hash("Hello, world!"))
/// // Prints:
/// // 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
///
/// generator.setAlgorithm(.md5)
/// 
/// print(generator.hash("Hello, world!"))
/// // Prints:
/// // 6cd3556deb0da54bca060b4c39479839
/// ```
///
/// ### Generating Salt
///
/// `HashGenerator` has the ability the generate random salt values of a chosen
/// length. A salt value can be returned as a string, an array of bytes (`[UInt8]`),
/// or a `Data` instance.
///
/// ```swift
/// let saltString = HashGenerator.generateSalt(length: 20, kind: .string)
/// print(saltString)
/// // Prints:
/// // 0a86cd4090f314e67107
///
/// let saltBytes = HashGenerator.generateSalt(length: 20, kind: .bytes)
/// print(saltBytes)
/// // Prints:
/// // [148, 187, 57, 197, 207, 5, 59, 159, 86, 94, 68, 31, 224, 34, 149, 113, 196, 225, 84, 6]
///
/// let saltData = HashGenerator.generateSalt(length: 20, kind: .data)
/// print(saltData)
/// // Prints:
/// // '20 bytes' (the default Data description)
///
/// // Use Data's `map(_:)` function to convert the data into an array of bytes:
/// print(saltData.map { $0 })
/// // Prints:
/// // [197, 246, 75, 47, 47, 250, 174, 98, 155, 45, 19, 120, 76, 111, 139, 165, 160, 113, 139, 122]
/// ```
///
/// ### Appending and Prepending Salt
///
/// `HashGenerator` has 4 methods that allow you to append or prepend salt to the
/// next value that is hashed. Once that value is hashed, the generator will revert
/// back to its previous state. The methods all return the generator, allowing for
/// a declarative-style syntax. You can also chain one method to another to both
/// append and prepend unique salt values simultaneously.
///
/// ```swift
/// let generator = HashGenerator(using: .sha256)
///
/// generator.appendSalt(length: 20).hash("Hello, world!")
/// generator.appendSalt(data: someData).hash("Hello, world!")
///
/// generator.prependSalt(length: 20).hash("Hello, world!")
/// generator.prependSalt(data: someData).hash("Hello, world!")
///
/// generator
///     .appendSalt(length: 20)
///     .prependSalt(length: 20)
///     .hash("Hello, world!")
/// ```
///
/// ``appendSalt(length:)`` and ``prependSalt(length:)`` both use the static
/// ``generateSalt(length:kind:)`` method that was mentioned above. ``appendSalt(data:)``
/// and ``prependSalt(data:)`` both accept custom data. No matter which version of
/// these methods you use, you can access the salt from properties within the returned
/// `Digest` instance.
///
/// ```swift
/// let generator = HashGenerator(using: .sha256)
///
/// let digest = generator
///     .appendSalt(length: 20)
///     .prependSalt(length: 20)
///     .hash("Hello, world!")
///
/// print((digest.appendedSalt as! Data).map { $0 })
/// // Prints:
/// // [65, 153, 211, 18, 45, 176, 184, 166, 196, 167, 192, 77, 43, 31, 1, 82, 165, 213, 50, 164]
/// 
/// print((digest.prependedSalt as! Data).map { $0 })
/// // Prints:
/// // [212, 206, 125, 27, 191, 138, 21, 31, 218, 152, 95, 28, 72, 56, 98, 13, 250, 169, 234, 147]
/// ```
public final class HashGenerator {
  private static let seed = HashGenerator(.sha256).hash(UUID()).string()
  
  @usableFromInline
  @inline(__always)
  static var pad: String {
    // It's safe to "unsafely" unwrap here, as we're guaranteed a value.
    .init(seed.randomElement().unsafelyUnwrapped)
  }
  
  @usableFromInline
  var appended: Data?
  
  @usableFromInline
  var prepended: Data?
  
  @usableFromInline
  var algorithm: HashAlgorithm
  
  /// Creates an instance for hashing values with a given algorithm.
  /// - Parameter algorithm: The `HashAlgorithm` to use when computing hash digests.
  @inlinable
  @inline(__always)
  public init(using algorithm: HashAlgorithm) {
    self.algorithm = algorithm
  }
  
  /// Creates an instance for hashing values with a given algorithm.
  /// - Parameter algorithm: The `HashAlgorithm` to use when computing hash digests.
  @inlinable
  @inline(__always)
  public init(_ algorithm: HashAlgorithm) {
    self.algorithm = algorithm
  }
}

extension HashGenerator {
  /// Hashes the given data and returns a `Digest` instance.
  /// - Parameter data: The data to be hashed.
  /// - Returns: A `Digest` instance containing the data computed by the hash function.
  @inlinable
  @inline(__always)
  @_optimize(speed)
  public func hash(_ data: Data) -> Digest {
    // -- NOTE -- //
    // This method is as long as it is in an effort to make it as optimized
    // as possible. A previous version had a more generalized approach, which
    // resulted in cases where code was executed where it didn't need to (for
    // example, even if only an appended value existed, it would still attempt
    // to add the prepended value).
    
    // We go in the order of (presumably) the most likely to occur to least
    // likely to occur.
    
    if appended == nil, prepended == nil {
      // Here we are neither appending or prepending.
      return algorithm.hash(data)
    } else if let appended, let prepended {
      // Here we are both appending and prepending.
      var data = data
      data = prepended + data
      data += appended
      
      // Make sure to remove the stored appended and prepended values.
      self.appended = nil
      self.prepended = nil
      
      // Create the digest.
      var digest = algorithm.hash(data)
      
      // Add the appended and prepended values to the digest so that
      // they can be retrieved by the user.
      digest._appendedSalt = appended
      digest._prependedSalt = prepended
      
      // Return the digest.
      return digest
    } else if let appended, prepended == nil {
      // Here we are appending, but not prepending.
      var data = data
      data += appended
      
      // Make sure to remove the stored appended value.
      self.appended = nil
      
      // Create the digest.
      var digest = algorithm.hash(data)
      
      // Add the appended value to the digest so that it can be
      // retrieved by the user.
      digest._appendedSalt = appended
      
      // Return the digest.
      return digest
    } else if let prepended, appended == nil {
      // Here we are prepending, but not appending.
      var data = data
      data = prepended + data
      
      // Make sure to remove the stored prepended value.
      self.prepended = nil
      
      // Create the digest.
      var digest = algorithm.hash(data)
      
      // Add the prepended value to the digest so that it can be
      // retrieved by the user.
      digest._prependedSalt = prepended
      
      // Return the digest.
      return digest
    } else {
      // All possible cases should have been covered, so throw
      // a fatal error if we somehow make it to this point.
      fatalError("Unable to hash data.")
    }
  }
  
  /// Hashes a given string and returns a `Digest` instance.
  /// - Parameter string: A string to be hashed.
  /// - Returns: A `Digest` instance containing the data computed by the hash function.
  @inlinable
  @inline(__always)
  @_optimize(speed)
  public func hash(_ string: String) -> Digest {
    hash(string.data(using: .utf8)!)
  }
  
  /// Hashes a given value and returns a `Digest` instance.
  ///
  /// Do not rely on this method for industry standard hashing. As the `value` parameter
  /// accepts a generic type, `HashGenerator` must decide how to go about hashing that
  /// value. Most hash algorithms only accept raw data as their input, so the way that
  /// this method converts its value to that data may differ from other tools.
  ///
  /// - Parameter value: A value to be hashed.
  /// - Returns: A `Digest` instance containing the data computed by the hash function.
  @inlinable
  @inline(__always)
  @_optimize(speed)
  public func hash<T>(_ value: T) -> Digest {
    var value = value
    return hash(Data(bytes: &value, count: MemoryLayout<T>.size))
  }
  
  /// Hashes the given `Hashable` value and returns a `Digest` instance.
  /// - Parameter data: The data to be hashed.
  /// - Returns: A `Digest` instance containing the data computed by the hash function.
  @inlinable
  @inline(__always)
  @_optimize(speed)
  @_disfavoredOverload
  public func hash<H: Hashable>(_ hashable: H) -> Digest {
    if algorithm == .swift {
      if let data = hashable as? Data {
        return hash(data)
      } else if let string = hashable as? String {
        return hash(string)
      }
      return algorithm._hash(hashable.hashValue)
    }
    return hash(String(describing: hashable.hashValue))
  }
}

extension HashGenerator {
  /// Changes the algorithm that the generator uses.
  /// - Parameter algorithm: The `HashAlgorithm` to use when computing hash digests.
  @inlinable
  @discardableResult
  public func setAlgorithm(_ algorithm: HashAlgorithm) -> Self {
    self.algorithm = algorithm
    return self
  }
}

extension HashGenerator {
  @usableFromInline
  @inline(__always)
  @_optimize(speed)
  static func generateIndividualBytes(_ count: Int) -> [UInt8] {
    var bytes = [UInt8]()
    while bytes.endIndex < count {
      bytes.append(.random(in: 0...255))
    }
    return bytes
  }
  
  #if os(macOS)
  @usableFromInline
  @inline(__always)
  @_optimize(speed)
  static func generateRandomBytesSec(_ count: Int) -> [UInt8]? {
    var bytes = [UInt8](repeating: 0, count: count)
    if SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess {
      return bytes
    } else {
      return nil
    }
  }
  
  @usableFromInline
  @inline(__always)
  @_optimize(speed)
  static func generateRandomBytesCC(_ count: Int) -> [UInt8]? {
    var bytes = [UInt8](repeating: 0, count: count)
    if CCRandomGenerateBytes(&bytes, count) == kCCSuccess {
      return bytes
    } else {
      return nil
    }
  }
  
  @usableFromInline
  @inline(__always)
  @_optimize(speed)
  static func generateRandomBytesMacOS(_ count: Int) -> [UInt8] {
    // Try this method first. It's fast and uses a cryptographically
    // secure pseudorandom number generator to generate its bytes.
    generateRandomBytesSec(count) ??
    // If the above method fails (very unlikely), try this method
    // instead. Also cryptographically secure, but a little slower.
    generateRandomBytesCC(count) ??
    // If we still somehow have a failure, generate bytes one at a
    // time. This uses the system's default random number generator,
    // which uses a cryptographically secure source of randomness
    // wherever possible. In theory, however, this might not be quite
    // as secure as the other two methods, so only use it as a last
    // resort.
    generateIndividualBytes(count)
  }
  #endif
  
  @usableFromInline
  @inline(__always)
  @_optimize(speed)
  static func generateRandomBytes(_ count: Int) -> [UInt8] {
    #if os(macOS)
    generateRandomBytesMacOS(count)
    #else
    generateIndividualBytes(count)
    #endif
  }
}

extension HashGenerator {
  /// Constants that indicate the kind of salt value to be generated.
  public struct SaltKind<T> {
    private init() { }
    
    /// Specifies a salt value that takes the form of a `Data` object.
    public static var data: SaltKind<Data> { .init() }
    
    /// Specifies a salt value that takes the form of a string.
    public static var string: SaltKind<String> { .init() }
    
    /// Specifies a salt value that takes the form of an array of bytes.
    public static var bytes: SaltKind<[UInt8]> { .init() }
  }
  
  /// Generates a salt value that can be appended or prepended to a ``HashGenerator``'s
  /// input. This has the effect of drastically altering the generated digest, and is
  /// often used as an extra security measure. This method uses a cryptographically
  /// secure pseudorandom number generator wherever possible.
  ///
  /// ```swift
  /// let generator = HashGenerator(using: .sha256)
  ///
  /// let salt1 = HashGenerator.generateSalt(length: 20, kind: .data)
  /// let digest1 = generator.appendSalt(data: salt1).hash("Hello, world!")
  ///
  /// let salt2 = HashGenerator.generateSalt(length: 20, kind: .data)
  /// let digest2 = generator.appendSalt(data: salt2).hash("Hello, world!")
  ///
  /// print(digest1)
  /// // Prints '14b9c131b7218fafe5ec044f98a43c260fccbe9ab6721fe4a1336dd8e777c807'
  ///
  /// print(digest2)
  /// // Prints '0def742f9414712f25e0274973d8b0582cd23d6edc778327b3aa5af54e868b31'
  ///
  /// assert(digest1 != digest2)
  /// ```
  ///
  /// For more information, see [Salt](https://w.wiki/4o6Y)
  ///
  /// - Parameters:
  ///   - length: If `kind` is ``SaltKind/data`` or ``SaltKind/bytes``, this value
  ///     determines the number of bytes to generate. If `kind` is ``SaltKind/string``,
  ///     this value determines the length of the generated string.
  ///   - kind: An instance of ``SaltKind`` that specifies the form that the generated
  ///     salt should take. If not specified, this value defaults to ``SaltKind/data``.
  /// - Returns: A generated salt value, converted according to the specified ``SaltKind``.
  public static func generateSalt<T>(length: Int, kind: SaltKind<T> = .data) -> T {
    if T.self is Data.Type {
      return Data(generateRandomBytes(length)) as! T
    } else if T.self is String.Type {
      return generateSalt(length: length, kind: .data)
        .map { .init(format: "%02x", $0) }
        .joined()
        // Count will likely be off, so pad or truncate to
        // the appropriate length.
        .padding(toLength: length, withPad: pad, startingAt: 0) as! T
    } else if T.self is [UInt8].Type {
      return generateRandomBytes(length) as! T
    } else {
      // This will never be called.
      fatalError()
    }
  }
}

extension HashGenerator {
  /// Causes the generator to append a salt value to its input before its next hash.
  ///
  /// After the next hash is complete, the generator will revert to hashing without
  /// appending salt. This method can be used together with `prependingSalt(_:)` and
  /// both will be applied.
  @inlinable
  @discardableResult
  @available(*, deprecated, renamed: "appendSalt(data:)")
  public func appendingSalt(_ salt: Data) -> Self {
    appendSalt(data: salt)
  }
  
  /// Causes the generator to prepend a salt value to its input before its next hash.
  ///
  /// After the next hash is complete, the generator will revert to hashing without
  /// prepending salt. This method can be used together with `appendingSalt(_:)` and
  /// both will be applied.
  @inlinable
  @discardableResult
  @available(*, deprecated, renamed: "prependSalt(data:)")
  public func prependingSalt(_ salt: Data) -> Self {
    prependSalt(data: salt)
  }
  
  /// Causes the generator to append a salt value to its input before its next hash.
  ///
  /// After the next hash is complete, the generator will revert to hashing without
  /// appending salt. This method can be used together with `prependingSalt(_:)` and
  /// both will be applied.
  @inlinable
  @discardableResult
  @available(*, deprecated, renamed: "appendSalt(length:)")
  public func appendingSalt(length: Int) -> Self {
    appendSalt(length: length)
  }
  
  /// Causes the generator to prepend a salt value to its input before its next hash.
  ///
  /// After the next hash is complete, the generator will revert to hashing without
  /// prepending salt. This method can be used together with `appendingSalt(_:)` and
  /// both will be applied.
  @inlinable
  @discardableResult
  @available(*, deprecated, renamed: "prependSalt(length:)")
  public func prependingSalt(length: Int) -> Self {
    prependSalt(length: length)
  }
}

extension HashGenerator {
  /// Causes the generator to append a salt value to its input before its next hash.
  ///
  /// After the next hash is complete, the generator will revert to hashing without
  /// appending salt. This method can be used together with either ``prependSalt(data:)``
  /// or ``prependSalt(length:)``.
  @inlinable
  @discardableResult
  public func appendSalt(data: Data) -> Self {
    appended = data
    return self
  }
  
  /// Causes the generator to prepend a salt value to its input before its next hash.
  ///
  /// After the next hash is complete, the generator will revert to hashing without
  /// prepending salt. This method can be used together with either ``appendSalt(data:)``
  /// or ``appendSalt(length:)``.
  @inlinable
  @discardableResult
  public func prependSalt(data: Data) -> Self {
    prepended = data
    return self
  }
  
  /// Causes the generator to append a salt value to its input before its next hash.
  ///
  /// After the next hash is complete, the generator will revert to hashing without
  /// appending salt. This method can be used together with either ``prependSalt(data:)``
  /// or ``prependSalt(length:)``.
  @inlinable
  @discardableResult
  public func appendSalt(length: Int) -> Self {
    appendSalt(data: Self.generateSalt(length: length))
  }
  
  /// Causes the generator to prepend a salt value to its input before its next hash.
  ///
  /// After the next hash is complete, the generator will revert to hashing without
  /// prepending salt. This method can be used together with either ``appendSalt(data:)``
  /// or ``appendSalt(length:)``.
  @inlinable
  @discardableResult
  public func prependSalt(length: Int) -> Self {
    prependSalt(data: Self.generateSalt(length: length))
  }
}

extension HashGenerator {
  /// The result type produced by `HashGenerator`.
  public struct Digest {
    /// The raw data type of a digest.
    public typealias RawValue = Data
    
    /// The raw bytes of the digest.
    public let rawValue: RawValue
    
    /// The algorithm that was used to compute the digest.
    public let algorithm: HashAlgorithm
    
    @usableFromInline
    var _appendedSalt: AnyHashable?
    
    @usableFromInline
    var _prependedSalt: AnyHashable?
    
    /// The salt that was appended to the value in the computation of the digest, if
    /// there was one.
    ///
    /// This value can be a `Data` instance, a `String` instance, or an `Array<UInt8>`
    /// instance. Therefore, it is presented as `AnyHashable`. You can cast it to its
    /// correct type using one of the casting (`as`, `as?`, or `as!`) operators.
    public var appendedSalt: AnyHashable? { _appendedSalt }
    
    /// The salt that was prepended to the value in the computation of the digest, if
    /// there was one.
    ///
    /// This value can be a `Data` instance, a `String` instance, or an `Array<UInt8>`
    /// instance. Therefore, it is presented as `AnyHashable`. You can cast it to its
    /// correct type using one of the casting (`as`, `as?`, or `as!`) operators.
    public var prependedSalt: AnyHashable? { _prependedSalt }
    
    // This initializer should never be used. It's simply to hide the
    // 'init(rawValue:)' initializer when someone tries to initialize
    // a Digest from outside this file.
    @available(*, unavailable)
    private init() {
      fatalError()
    }
    
    @usableFromInline
    @inline(__always)
    init(rawValue: RawValue, algorithm: HashAlgorithm) {
      self.rawValue = rawValue
      self.algorithm = algorithm
    }
    
    @usableFromInline
    @inline(__always)
    init(rawValue: CFData, algorithm: HashAlgorithm) {
      self.init(
        rawValue: rawValue as Data,
        algorithm: algorithm)
    }
    
    /// Returns a string representation of the digest.
    ///
    /// This method is synonymous with the digest's `description` property,
    public func string() -> String {
      description
    }
    
    /// Accesses and returns the data in the digest using the given format.
    /// - Parameter format: The format of the data to be returned.
    /// - Returns: The data, returned in the specified format.
    @inlinable
    public func format<T>(_ format: DigestFormat<T>) -> T {
      // We go in the order of least time to compute, to most time to compute.
      
      // We can force cast the values below, as we will have already
      // determined that the value's type is the same as what we're
      // casting to.
      
      if T.self is Data.Type {
        // The value of 'format' is '.data'.
        return rawValue as! T
      } else if T.self is [UInt8].Type {
        // The value of 'format' is '.bytes'.
        return rawValue.map { $0 } as! T
      } else if T.self is String.Type {
        // The value of 'format' is '.string'.
        return description as! T
      } else {
        // Failure is not possible here. It MUST be one of the above options.
        // Regardless, to avoid having to return some other value, we throw a
        // fatal error if we somehow get this far. We won't, but if we do...
        fatalError("Bad format.")
      }
    }
    
    /// Various formats for accessing the data in a digest.
    public struct DigestFormat<T> {
      private init() { }
      
      /// Specifies the return of the raw data of a digest.
      public static var data: DigestFormat<Data> { .init() }
      
      /// Specifies the return of the data of a digest as an array of bytes.
      public static var bytes: DigestFormat<[UInt8]> { .init() }
      
      /// Specifies the return of a string representation of the data in a digest.
      public static var string: DigestFormat<String> { .init() }
    }
  }
}
 
extension HashGenerator {
  /// Various algorithms available for hashing.
  public struct HashAlgorithm {
    let rawValue: String
    
    private init(rawValue: String = #function) {
      self.rawValue = rawValue
    }
    
    /// A widely used, cryptographically secure hash algorithm that produces a digest
    /// of 256 bits. Good for any use case.
    public static var sha256: Self { .init() }
    
    /// A widely used, cryptographically secure hash algorithm that produces a digest
    /// of 384 bits. Good for any use case.
    public static var sha384: Self { .init() }
    
    /// A widely used, cryptographically secure hash algorithm that produces a digest
    /// of 512 bits. Good for any use case.
    public static var sha512: Self { .init() }
    
    /// A cryptographic hash algorithm that produces a digest of 160 bits. Not recommended
    /// for security purposes, but has other applicable uses, such as managing data in
    /// hash tables and dictionaries, or uniquely identifying objects.
    public static var sha1: Self { .init() }
    
    /// A cryptographically broken legacy hash algorithm. While it should _never_ be
    /// used for security purposes, it still has many applicable uses, such as managing
    /// data in hash tables and dictionaries, or uniquely identifying objects. This hash
    /// function produces a digest of 128 bits.
    public static var md5: Self { .init() }
    
    /// The standard Swift hash function. This is equivalent to getting the `hashValue`
    /// property of an object. If the object does not conform to `Hashable` it will be
    /// converted into a `Data` representation of itself, which will then be hashed.
    ///
    /// - Note: Swift does not guarantee that its hashing algorithm will produce
    /// the same result for every launch of the program. Each launch, a different
    /// seed is chosen to compute the hashes for the entire runtime of the process.
    /// During any given execution, the algorithm will remain the same, and produce
    /// consistent hashes, but this algorithm should not be used to reference
    /// externally stored values. See Swift documentation for more details.
    public static var swift: Self { .init() }
    
    // This represents the absence of a value. Even though we have to give
    // it _some_ value for its definition, it will never be used externally.
    @usableFromInline
    static var invalid: Self { .init() }
  }
}

extension HashGenerator.HashAlgorithm: DeprecationBypassable {
  // Avoids deprecation warning for using MD5.
  fileprivate var bypassed: DeprecationBypassable { self }
  
  @usableFromInline
  @inline(__always)
  @_optimize(speed)
  func hash(_ data: Data) -> HashGenerator.Digest {
    var length: Int32 = 0
    switch self {
    case .sha256:
      length = CC_SHA256_DIGEST_LENGTH
    case .sha384:
      length = CC_SHA384_DIGEST_LENGTH
    case .sha512:
      length = CC_SHA512_DIGEST_LENGTH
    case .sha1:
      length = CC_SHA1_DIGEST_LENGTH
    case .md5:
      length = CC_MD5_DIGEST_LENGTH
    case .swift:
      return _hash(data.hashValue)
    default:
      incorrectHashFunction(for: self)
    }
    return bypassed._hash(data: data, length: length)
  }
  
  // Not really deprecated, but as CommonCrypto seems to have
  // stopped supporting MD5, we need to mark it like it is to
  // avoid a compiler warning.
  @usableFromInline
  @inline(__always)
  @_optimize(speed)
  @available(macOS, deprecated: 10.15)
  func _hash(data: Data, length: Int32) -> HashGenerator.Digest {
    let data = NSMutableData(data: data)
    
    // It's okay to unsafely unwrap this since we're just creating a byte buffer.
    let digest = NSMutableData(length: Int(length)).unsafelyUnwrapped
    let digestBytes = digest.mutableBytes.bindMemory(to: UInt8.self, capacity: digest.length)
    
    switch self {
    case .sha256:
      CC_SHA256(data.bytes, CC_LONG(data.count), digestBytes)
    case .sha384:
      CC_SHA384(data.bytes, CC_LONG(data.count), digestBytes)
    case .sha512:
      CC_SHA512(data.bytes, CC_LONG(data.count), digestBytes)
    case .sha1:
      CC_SHA1(data.bytes, CC_LONG(data.count), digestBytes)
    case .md5:
      CC_MD5(data.bytes, CC_LONG(data.count), digestBytes)
    default:
      // This is fatal, but it will never be called.
      incorrectHashFunction(for: self)
    }
    return HashGenerator.Digest(rawValue: digest, algorithm: self)
  }
  
  // Uses the default Swift hash algorithm. The value passed in will already
  // have been hashed. This just converts the integer into a digest.
  @usableFromInline
  @inline(__always)
  @_optimize(speed)
  func _hash(_ hashValue: Int) -> HashGenerator.Digest {
    guard let data = String(describing: hashValue).data(using: .utf8) else {
      fatalError("Unable to convert integer value into an appropriate data format.")
    }
    return HashGenerator.Digest(rawValue: data, algorithm: .swift)
  }
  
  @inline(__always)
  fileprivate func incorrectHashFunction(for alg: HashGenerator.HashAlgorithm) -> Never {
    fatalError("Attempted to use incorrect hash function for '\(alg)' ALGORITHM.")
  }
}

extension HashGenerator.HashAlgorithm: Hashable { }

extension HashGenerator.HashAlgorithm: Equatable { }

extension HashGenerator.HashAlgorithm: CustomStringConvertible {
  public var description: String {
    switch self {
    case .sha256:
      return "SHA256"
    case .sha384:
      return "SHA384"
    case .sha512:
      return "SHA512"
    case .sha1:
      return "SHA1"
    case .md5:
      return "MD5"
    case .swift:
      return "SWIFT"
    case .invalid:
      return "INVALID"
    default:
      incorrectHashFunction(for: self)
    }
  }
}

extension HashGenerator.HashAlgorithm: CustomDebugStringConvertible {
  public var debugDescription: String {
    "\(Self.self)(\(self))"
  }
}

extension HashGenerator.Digest: CustomStringConvertible {
  public var description: String {
    rawValue.map { .init(format: "%02x", $0) }.joined()
  }
}

extension HashGenerator.Digest: Hashable {
  public func hash(into hasher: inout Hasher) {
    hasher.combine(rawValue)
  }
}

extension HashGenerator.Digest: Equatable {
  public static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.rawValue == rhs.rawValue
  }
}

extension HashGenerator.Digest {
  /// Returns the concatenated result of two digests.
  ///
  /// - Note: If `lhs` and `rhs` have different values for their `algorithm`
  /// property, the returned digest's `algorithm` property will be set to
  /// `.invalid`. This does not affect the validity of the digest, rather it
  /// merely states that the digest was not computed using one of the available
  /// hash algorithms.
  public static func + (lhs: Self, rhs: Self) -> Self {
    .init(
      rawValue: lhs.rawValue + rhs.rawValue,
      algorithm: lhs.algorithm == rhs.algorithm ? lhs.algorithm : .invalid)
  }
  
  /// Sets the value of `lhs` to the concatenated result of itself and another
  /// digest.
  ///
  /// - Note: If `lhs` and `rhs` have different values for their `algorithm`
  /// property, the returned digest's `algorithm` property will be set to
  /// `.invalid`. This does not affect the validity of the digest, rather it
  /// merely states that the digest was not computed using one of the available
  /// hash algorithms.
  public static func += (lhs: inout Self, rhs: Self) {
    lhs = lhs + rhs
  }
}

extension HashGenerator: CustomStringConvertible {
  public var description: String {
    "\(Self.self)(algorithm: \(algorithm))"
  }
}

extension HashGenerator: CustomDebugStringConvertible {
  public var debugDescription: String {
    "\(Self.self)"
    + "("
    + "algorithm: \(algorithm), "
    + "appended: \(appended != nil ? "\(appended!)" : "nil"), "
    + "prepended: \(prepended != nil ? "\(prepended!)" : "nil")"
    + ")"
  }
}

fileprivate protocol DeprecationBypassable {
  func _hash(data: Data, length: Int32) -> HashGenerator.Digest
}
