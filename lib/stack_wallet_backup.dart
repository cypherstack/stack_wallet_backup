/// This library is useful for safely encrypting and decrypting data with a passphrase.
/// 
/// Since user-supplied passphrases are assumed to be of low entropy (and probably reused elsewhere), we run the passphrase through a password-based key derivation function (PBKDF) using a random nonce as salt.
/// The resulting derived key is used with another random nonce to encrypt the data with an authenticated encryption with additional data (AEAD) construction, which also provides authentication.
/// After this process, we assemble a plaintext protocol version number, the PBKDF nonce, and all AEAD data.
/// A checksum is computed over this assembled data and appended to it; this is useful for fast detection of data that may have been incompletely or incorrectly transferred across devices.
/// 
/// To decrypt, we parse the data into its expected components: protocol version number, PBKDF nonce, AEAD data, checksum.
/// The protocol version number and checksum are first verified, in order to abort early in case of an unsupported version or corrupted data.
/// The supplied passphrase is then used with the PBKDF nonce to derive the key.
/// This key is used with the AEAD data to authenticate the ciphertext; we abort if this fails, as the data has been tampered with and is invalid.
/// If authentication succeeds, we decrypt and return the plaintext.
/// 
/// You can specify a version for encryption, but the library will safely default to the most recent.
/// Decryption automatically detects and supports all known versions.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:tuple/tuple.dart';

import 'stack_wallet_backup_platform_interface.dart';

class StackWalletBackup {
  Future<String?> getPlatformVersion() {
    return StackWalletBackupPlatform.instance.getPlatformVersion();
  }
}

/// Get version information
/// NOTE: A new version _must_ have a higher number than all previous versions, as this determines the default
List<VersionParameters> getAllVersions() {
  List<VersionParameters> versions = [];
  const String protocol = 'Stack Wallet backup v';
  int version;
  String aad;

  // Version 1 uses PBKDF2, XChaCha20-Poly1305, and Blake2b
  version = 1;
  aad = protocol + version.toString();
  versions.add(VersionParameters(
    version,
    (passphrase, nonce) => _pbkdf2(passphrase, nonce, Hmac.sha512(), 120000, 32),
    (key, nonce, plaintext) => _xChaCha20Poly1305Encrypt(key, nonce, plaintext, aad),
    (key, blob) => _xChaCha20Poly1305Decrypt(key, blob, aad),
    (data) => _blake2b(data, aad),
    16,
    24,
    16,
    64
  ));

  return versions;
}

/// Get parameters for a version; if not specified, get the most recent
VersionParameters getVersion(int? version) {
  // Get all versions
  List<VersionParameters> versions = getAllVersions();

  // If no version is specified, use the highest
  version ??= versions.map((version) => version.version).reduce(max);

  // Return the (first) version with this number if it exists
  VersionParameters foundVersion = versions.firstWhere((item) => item.version == version, orElse: () => throw BadProtocolVersion());
  return foundVersion;
}

/// An exception indicating a bad PBKDF nonce
class BadPbkdfNonce implements Exception {
  String errMsg() => 'Bad PBKDF nonce length';
}

/// An exception indicating a bad AEAD key
class BadAeadKey implements Exception {
  String errMsg() => 'Bad AEAD key length';
}

/// An exception indicating a bad AEAD nonce
class BadAeadNonce implements Exception {
  String errMsg() => 'Bad AEAD nonce length';
}

/// An exception indicating a bad AEAD MAC
class BadAeadMac implements Exception {
  String errMsg() => 'Bad AEAD MAC length';
}

/// An exception indicating incomplete data
class BadDataLength implements Exception {
  String errMsg() => 'Bad data length';
}

/// An exception indicating an unsupported protocol version
class BadProtocolVersion implements Exception {
  String errMsg() => 'Bad protocol version';
}

/// An exception indicating failed decryption
class FailedDecryption implements Exception {
  String errMsg() => 'Failed decryption';
}

/// An exception indicating a bad checksum
class BadChecksum implements Exception {
  String errMsg() => 'Bad checksum';
}

/// An exception indicating a bad AAD length
class BadAadLength implements Exception {
  String errMsg() => 'Bad AAD length';
}

/// Class to hold data relevant for decryption
class PackageData {
  VersionParameters parameters;
  List<int> pbkdfNonce;
  List<int> aeadNonce;
  List<int> aeadTag;
  List<int> ciphertext;

  PackageData(this.parameters, this.pbkdfNonce, this.aeadNonce, this.aeadTag, this.ciphertext);

  /// Encode data to bytes
  Uint8List encode(List<int> checksum) {
    if (checksum.length != parameters.checksumSize) {
      throw BadChecksum();
    }

    final bytes = BytesBuilder();
    bytes.addByte(parameters.version);
    bytes.add(pbkdfNonce);
    bytes.add(aeadNonce);
    bytes.add(aeadTag);
    bytes.add(checksum);
    bytes.add(ciphertext);
    return bytes.toBytes();
  }
}

/// Class to hold data for protocol versions
class VersionParameters {
  int version;
  Future<List<int>> Function(String, List<int>) pbkdf; // (passphrase, nonce)
  Future<SecretBox> Function(List<int>, List<int>, List<int>) aeadEncrypt; // (key, nonce, plaintext)
  Future<List<int>> Function(List<int>, SecretBox) aeadDecrypt; // (key, blob)
  Future<List<int>> Function(PackageData) checksum; // (data)
  int pbkdfNonceSize; // PBKDF nonce size in bytes
  int aeadNonceSize; // AEAD nonce size in bytes
  int aeadTagSize; // AEAD tag size in bytes
  int checksumSize; // checksum size in bytes

  VersionParameters(
    this.version,
    this.pbkdf,
    this.aeadEncrypt,
    this.aeadDecrypt,
    this.checksum,
    this.pbkdfNonceSize,
    this.aeadNonceSize,
    this.aeadTagSize,
    this.checksumSize,
  );
}

/// Parse data from bytes
Future<PackageData> _parseBytes(Uint8List bytes) async {
  // We need to parse at least the version
  if (bytes.isEmpty) {
    throw BadDataLength();
  }

  // Keep a counter for indexing purposes, because Dart iterators are silly
  int i = 0;

  // Parse the version and ensure it's valid; this can fail
  final parameters = getVersion(bytes[0]);
  i += 1;

  // Use the version to determine the minimum length of the bytes
  if (bytes.length < 1 + parameters.pbkdfNonceSize + parameters.aeadNonceSize + parameters.aeadTagSize + parameters.checksumSize) {
    throw BadDataLength();
  }

  // Since we know that we have enough bytes, parse all the required data
  final pbkdfNonce = bytes.sublist(i, i + parameters.pbkdfNonceSize);
  i += parameters.pbkdfNonceSize;
  final aeadNonce = bytes.sublist(i, i + parameters.aeadNonceSize);
  i += parameters.aeadNonceSize;
  final aeadTag = bytes.sublist(i, i + parameters.aeadTagSize);
  i += parameters.aeadTagSize;
  final checksum = bytes.sublist(i, i + parameters.checksumSize);
  i += parameters.checksumSize;
  final ciphertext = bytes.sublist(i);

  // Verify the checksum
  final data = PackageData(parameters, pbkdfNonce, aeadNonce, aeadTag, ciphertext);
  final expectedChecksum = await parameters.checksum(data);
  if (!(const ListEquality()).equals(checksum, expectedChecksum)) {
    throw BadChecksum();
  }

  return data;
}

//
// PBKDF functions
//

/// PBKDF2
Future<List<int>> _pbkdf2(String passphrase, List<int> nonce, MacAlgorithm macAlgorithm, int iterations, int derivedKeyLength) async {
  final pbkdf = Pbkdf2(
    macAlgorithm: macAlgorithm,
    iterations: iterations,
    bits: derivedKeyLength * 8 // bits
  );
  final derivedKey = await pbkdf.deriveKey(
    secretKey: SecretKey(utf8.encode(passphrase)),
    nonce: nonce
  );

  return derivedKey.extractBytes();
}

//
// AEAD functions
//

/// XChaCha20-Poly1305 encryption
Future<SecretBox> _xChaCha20Poly1305Encrypt(List<int> key, List<int> nonce, List<int> plaintext, String aad) async {
  final aead = Xchacha20.poly1305Aead();
  final ciphertext = await aead.encrypt(
    plaintext,
    secretKey: SecretKey(key),
    nonce: nonce,
    aad: utf8.encode(aad)
  );

  return ciphertext;
}

/// XChaCha20-Poly1305 decryption
Future<List<int>> _xChaCha20Poly1305Decrypt(List<int> key, SecretBox blob, String aad) async {
  final aead = Xchacha20.poly1305Aead();
  try {
    final plaintext = await aead.decrypt(
      blob,
      secretKey: SecretKey(key),
      aad: utf8.encode(aad)
    );

    return plaintext;
  } on SecretBoxAuthenticationError {
    throw FailedDecryption();
  }
}

//
// Checksums
//

// Blake2b
Future<List<int>> _blake2b(PackageData data, String aad) async {
  // Get a one-byte encoding of the AAD length
  if (aad.length > 0xFF) {
    throw BadAadLength();
  }
  
  final hasher = Blake2b();
  final streamer = hasher.newHashSink();
  streamer.add(<int>[aad.length]);
  streamer.add(utf8.encode(aad));
  streamer.add(<int>[data.parameters.version]);
  streamer.add(data.pbkdfNonce);
  streamer.add(data.aeadNonce);
  streamer.add(data.aeadTag);
  streamer.add(data.ciphertext);
  streamer.close();
  final checksum = await streamer.hash();

  return checksum.bytes;
}

//
// API functions
//

/// Encrypt data with a passphrase and return the raw data structure and checksum (useful for testing)
Future<Tuple2<PackageData, List<int>>> encryptRaw(String passphrase, Uint8List plaintext, {int? version}) async {
  // Get version parameters; this can fail
  final VersionParameters parameters = getVersion(version);

  // Random number generator; this MUST be cryptographically secure!
  // According to the API, it should fail if this condition is not met
  var rng = Random.secure();

  // Use the PBKDF to derive an AEAD key from the passphrase
  final pbkdfNonce = List<int>.generate(parameters.pbkdfNonceSize, (_) => rng.nextInt(0xFF + 1));
  final derivedKey = await parameters.pbkdf(passphrase, pbkdfNonce);
  
  // Use the AEAD to encrypt the plaintext
  final aeadNonce = List<int>.generate(parameters.aeadNonceSize, (_) => rng.nextInt(0xFF + 1));
  final blob = await parameters.aeadEncrypt(derivedKey, aeadNonce, plaintext);

  // Assemble data and add the checksum
  final data = PackageData(parameters, pbkdfNonce, aeadNonce, blob.mac.bytes, blob.cipherText);
  final checksum = await parameters.checksum(data);

  // Encode and return the data
  return Tuple2<PackageData, List<int>>(data, checksum);
}

/// Encrypt data with a passphrase and return the encoded data
Future<Uint8List> encrypt(String passphrase, Uint8List plaintext, {int? version}) async {
  Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintext, version: version);
  PackageData data = raw.item1;
  List<int> checksum = raw.item2;

  return data.encode(checksum);
}

// Decrypt data with a passphrase
Future<Uint8List> decrypt(String passphrase, Uint8List bytes) async {
  // Parse the bytes into data; this can fail
  PackageData data = await _parseBytes(bytes);

  // Use the PBKDF to derive an AEAD key from the passphrase
  final derivedKey = await data.parameters.pbkdf(passphrase, data.pbkdfNonce);

  // Use the AEAD to authenticate and decrypt the plaintext; this can fail
  final blob = SecretBox(
    data.ciphertext,
    nonce: data.aeadNonce,
    mac: Mac(data.aeadTag)
  );
  final plaintext = await data.parameters.aeadDecrypt(derivedKey, blob);

  return Uint8List.fromList(plaintext);
}
