/// This library provides utilities for secure storage of key/value data.
/// The security of Flutter's secure storage depends highly on your platform.
/// On some platforms, data is cryptographically secured against snoops and other applications.
/// On other platforms, data is opportunistically secured with only some protections.
/// To address this garbage fire, we can use a user-supplied passphrase to add a layer of security.
/// 
/// The overall idea is that we take name/value pairs and encrypt the values, binding them to names.
/// The key used for this encryption is itself encrypted with a key derived from the passphrase.
/// This allows us flexibility to change the passphrase without needing to encrypt all values again.
/// 
/// The basic cryptographic building blocks we use are:
/// - a password-based key derivation function (PBKDF)
/// - an authenticated encryption with associated data (AEAD) construction
/// 
/// Here's how it works.
/// 
/// When the user creates a passphrase, we do the following:
/// - Generate a random PBKDF salt
/// - Run the salt and passphrase through the PBKDF to derive an AEAD key, the _main key_
/// - Generate a random AEAD key, the _data key_
/// - Use the main key to encrypt the data key with the AEAD
/// - Encode the salt and encrypted data key to a Base64 string, the _key blob_
/// - Store the key blob in the device's secure storage
/// 
/// When we need to check a user-supplied passphrase for correctness, we do the following:
/// - Fetch the key blob from the device's secure storage
/// - Decode the key blob to bytes, and parse the salt and encrypted data key
/// - Run the salt and passphrase through the PBKDF to derive a candidate main key
/// - Use the candidate main key to authenticate and decrypt the encrypted data key, and return success or an error
/// 
/// When we then need to write a field name/value pair to the device's secure storage, we do the following:
/// - Use the data key to encrypt the value with the AEAD, binding it to the name
/// - Encode the encrypted value to a Base64 string
/// - Return the encoded encrypted value, which is safe to be written to the device's secure storage
/// It's also possible to pad the value to a multiple of a base length, which reduces information available to an adversary.
/// 
/// When we then need to read a field name/value pair from the device's secure storage, we do the following:
/// - Fetch the name and encoded encrypted value from the device's secure storage
/// - Decode the encoded encrypted value to bytes
/// - Use the data key to decrypt the encrypted value with the AEAD
/// - Return the value on success, or an error otherwise
/// If the original value was padded, we remove the padding.
/// 
/// The use of a stored key blob is to faciliate password changes without needing to encrypt data again.
/// When the user wishes to change their passphrase, we do the following:
/// - Generate a random PBKDF salt
/// - Run the salt and passphrase through the PBKDF to derive a new main key
/// - Use the main key to encrypt the data key with the AEAD
/// - Encode the salt and encrypted data key to a Base64 string, the new key blob
/// - Overwrite the existing key blob in the device's secure storage
/// Note that the existing data key is unchanged, so all encrypted name/value pairs are still accessible.
/// 
/// This library is intended to safely abstract this functionality.
/// In particular, it only exposes data that is safe to be passed to the device's secure storage.
/// Don't try to peek inside to extract other data; the robotic innards are not safe.
/// 
/// WARNING!
/// Field names are not encrypted here, since we don't have nonce-misuse-resistant AEAD functionality available to us.
/// We could add this, but there be dragons.
/// This is not part of our threat model anyway, but keep it in mind.
/// Don't use this library if you need private field names.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Get the PBKDF iterations for this version
/// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
int getPbkdfIterations(int version) {
  switch (version) {
    case 1:
      return 120000;
    case 2:
      return 210000;
    default:
      throw VersionError();
  }
}

/// Constants that should not be changed without good reason
const int saltLength = 16; // in bytes
const String dataKeyDomain = 'STACK_WALLET_DATA_KEY';
const String encryptionDomain = 'STACK_WALLET_ENCRYPTION';

/// 
/// Errors
/// 

/// The provided passphrase is incorrect
class IncorrectPassphraseOrVersion implements Exception {
  String errMsg() => 'Incorrect passphrase';
}

/// Decryption of key/value data failed
class BadDecryption implements Exception {
  String errMsg() => 'Bad decryption';
}

/// Data has an invalid length
class InvalidLength implements Exception {
  String errMsg() => 'Data has an invalid length';
}

/// Encoding is invalid
class EncodingError implements Exception {
  String errMsg() => 'There was an encoding error';
}

/// Version is invalid
class VersionError implements Exception {
  String errMsg() => 'Bad version';
}

/// Padding flag is invalid
class InvalidPadding implements Exception {
  String errMsg() => 'Padding flag is invalid';
}

/// 
/// StorageCryptoHandler
/// 

class StorageCryptoHandler {
  late Uint8List _salt; // PBKDF salt
  late Uint8List _mainKey; // main key, derived from the passphrase
  late final Uint8List _dataKey; // data key

  // Private constructor
  StorageCryptoHandler._(this._salt, this._mainKey, this._dataKey);

  /// Create a new handler
  static Future<StorageCryptoHandler> fromNewPassphrase(String passphrase, int version) async {
    // Generate a random salt
    final salt = _randomBytes(saltLength);

    // Use the passphrase and salt to derive the main key with the PBKDF
    final mainKey = await _pbkdf2(salt, _stringToBytes(passphrase), version);

    // Generate a random data key
    final dataKey = _randomBytes(Xchacha20.poly1305Aead().secretKeyLength);

    // Assemble the handler
    return StorageCryptoHandler._(salt, mainKey, dataKey);
  }

  /// Create a handler from an existing passphrase and key blob with a specified version
  static Future<StorageCryptoHandler> fromExisting(String passphrase, String keyBlob, int version) async {
    // Decode the encrypted data key
    Uint8List keyBlobBytes = _stringToBytesBase64(keyBlob);
    if (keyBlobBytes.length != saltLength + Xchacha20.poly1305Aead().nonceLength + Xchacha20.poly1305Aead().secretKeyLength + Poly1305().macLength) {
      throw InvalidLength();
    }

    Uint8List salt = keyBlobBytes.sublist(0, saltLength);
    Uint8List encryptedDataKey = keyBlobBytes.sublist(saltLength);

    // Derive the candidate main key
    final Uint8List mainKey = await _pbkdf2(salt, _stringToBytes(passphrase), version);

    // Determine if the main key is valid against the encrypted data key
    try {
      final Uint8List dataKey = await _xChaCha20Poly1305Decrypt(
        mainKey,
        SecretBox.fromConcatenation(
          encryptedDataKey,
          nonceLength: Xchacha20.poly1305Aead().nonceLength,
          macLength: Poly1305().macLength
        ),
        _stringToBytes(dataKeyDomain),
      );

      // Check the data key length
      if (dataKey.length != Xchacha20.poly1305Aead().secretKeyLength) {
        throw InvalidLength();
      }

      // Assemble the handler
      return StorageCryptoHandler._(salt, mainKey, dataKey);
    } on BadDecryption {
      throw IncorrectPassphraseOrVersion();
    }
  }

  /// Reset the passphrase, which resets the salt and main key
  Future<void> resetPassphrase(String passphrase, int version) async {
    // Generate a random salt
    _salt = _randomBytes(saltLength);

    // Use the passphrase and salt to derive the main key with the PBKDF
    _mainKey = await _pbkdf2(_salt, _stringToBytes(passphrase), version);
  }

  /// Get the key blob, which is safe to store
  /// This also bundles in the salt for convenience
  Future<String> getKeyBlob() async {
    // Encrypt the data key
    final SecretBox encryptedDataKey = await _xChaCha20Poly1305Encrypt(
      _mainKey,
      _randomBytes(Xchacha20.poly1305Aead().nonceLength),
      _dataKey,
      _stringToBytes(dataKeyDomain),
    );

    return _bytesToStringBase64(Uint8List.fromList(_salt + encryptedDataKey.concatenation()));
  }

  /// Encrypt a value and return it, which is safe to store
  Future<String> encryptValue(String name, String value, {int? padding}) async {
    Uint8List paddedValue;

    // If padding was provided, prepend the value with 0x01 and its encoded length, and append the padding
    if (padding != null) {
      // Must be greater than 1
      if (padding < 2) {
        throw InvalidLength();
      }

      // Value length must not exceed a 4-byte representation
      if (value.length > (1 << 32)) {
        throw InvalidLength();
      }

      // Convert the value length into a little-endian 4-byte representation
      final ByteData valueLengthBytes = ByteData(4);
      valueLengthBytes.setUint32(0, value.length, Endian.little);

      // Assemble the length, value, and padding as bytes
      final BytesBuilder valueBytes = BytesBuilder();
      valueBytes.addByte(0x01); // this is a padded value
      valueBytes.add(valueLengthBytes.buffer.asUint8List()); // value length
      valueBytes.add(_stringToBytes(value)); // value
      valueBytes.add(List<int>.filled(padding - (value.length % padding), 0x00)); // padding
      
      paddedValue = valueBytes.toBytes();
    }
    // If no padding was provided, prepend the value with 0x00
    else {
      final BytesBuilder valueBytes = BytesBuilder();
      valueBytes.addByte(0x00); // this is not a padded value
      valueBytes.add(_stringToBytes(value));

      paddedValue = valueBytes.toBytes();
    }

    // Bind the field name as associated data
    Uint8List domain = Uint8List.fromList(<int>[encryptionDomain.length] + _stringToBytes(encryptionDomain) + _stringToBytes(name));

    final SecretBox encryptedValue = await _xChaCha20Poly1305Encrypt(
      _dataKey,
      _randomBytes(Xchacha20.poly1305Aead().nonceLength),
      paddedValue,
      domain,
    );

    return _bytesToStringBase64(encryptedValue.concatenation());
  }

  /// Decrypt a value and return it, which _must not_ be stored
  Future<String> decryptValue(String name, String encryptedValue) async {
    Uint8List domain = Uint8List.fromList(<int>[encryptionDomain.length] + _stringToBytes(encryptionDomain) + _stringToBytes(name));

    try {
      // Bind the field name as associated data
      final Uint8List paddedValue = await _xChaCha20Poly1305Decrypt(
        _dataKey,
        SecretBox.fromConcatenation(
          _stringToBytesBase64(encryptedValue),
          nonceLength: Xchacha20.poly1305Aead().nonceLength,
          macLength: Poly1305().macLength
        ),
        domain,
      );

      // We must have at least the padding flag
      if (paddedValue.isEmpty) {
        throw InvalidLength();
      }

      // No padding is present, so return the value
      if (paddedValue[0] == 0x00) {
        return _bytesToString(paddedValue.sublist(1));
      }

      // The padding flag is invalid, which should never happen
      if (paddedValue[0] != 0x01) {
        throw InvalidPadding();
      }

      // Extract the value length
      if (paddedValue.sublist(1).length < 4) {
        throw InvalidLength();
      }
      final int valueLength = ByteData.sublistView(paddedValue.sublist(1, 1 + 4)).getUint32(0, Endian.little);

      // Ensure the length is valid
      if (paddedValue.sublist(1 + 4).length < valueLength) {
        throw InvalidLength();
      }

      return _bytesToString(paddedValue.sublist(1 + 4, 1 + 4 + valueLength));
    } on BadDecryption {
      throw BadDecryption();
    }
  }
}

/// 
/// Utility functions
/// 

/// Generate cryptographically-secure random bytes
Uint8List _randomBytes(int n) {
  Random rng = Random.secure();
  return Uint8List.fromList(List<int>.generate(n, (_) => rng.nextInt(0xFF + 1)));
}

/// Convert bytes to a string with UTF-8 encoding
String _bytesToString(Uint8List data) {
  try {
    return utf8.decode(data);
  } on FormatException {
    throw EncodingError();
  }
}

/// Convert a string to bytes with UTF-8 encoding
Uint8List _stringToBytes(String data) {
  return Uint8List.fromList(utf8.encode(data));
}

/// Convert bytes to a string with Base64 encoding
String _bytesToStringBase64(Uint8List data) {
  return base64.encode(data);
}

/// Convert a string to bytes with Base64 encoding
Uint8List _stringToBytesBase64(String data) {
  try {
    return base64.decode(data);
  } on FormatException {
    throw EncodingError();
  }
}

/// PBKDF2/SHA-512
Future<Uint8List> _pbkdf2(Uint8List salt, Uint8List passphrase, int version) async {
  // Set up the PBKDF
  final Pbkdf2 pbkdf = Pbkdf2(
    macAlgorithm: Hmac.sha512(),
    iterations: getPbkdfIterations(version),
    bits: Xchacha20.poly1305Aead().secretKeyLength * 8, // bytes to bits
  );

  // Hash the passphrase
  final SecretKey mainKey = await pbkdf.deriveKey(
    secretKey: SecretKey(passphrase),
    nonce: salt,
  );
  final List<int> mainKeyBytes = await mainKey.extractBytes();

  return Uint8List.fromList(mainKeyBytes);
}

/// XChaCha20-Poly1305 encryption
Future<SecretBox> _xChaCha20Poly1305Encrypt(Uint8List key, Uint8List nonce, Uint8List data, Uint8List aad) async {
  final Xchacha20 aead = Xchacha20.poly1305Aead();
  final SecretBox encryptedData = await aead.encrypt(
    data,
    secretKey: SecretKey(key),
    nonce: nonce,
    aad: aad
  );

  return encryptedData;
}

/// XChaCha20-Poly1305 decryption
Future<Uint8List> _xChaCha20Poly1305Decrypt(Uint8List key, SecretBox encryptedData, Uint8List aad) async {
  final Xchacha20 aead = Xchacha20.poly1305Aead();
  try {
    final List<int> data = await aead.decrypt(
      encryptedData,
      secretKey: SecretKey(key),
      aad: aad
    );

    return Uint8List.fromList(data);
  } on SecretBoxAuthenticationError {
    throw BadDecryption();
  }
}
