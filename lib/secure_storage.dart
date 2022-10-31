/// This library provides utilities for secure storage of key/value data.
/// The security of Flutter's secure storage depends highly on your platform.
/// On some platforms, data is cryptographically secured against snoops and other applications.
/// On other platforms, data is opportunistically secured with only some protections.
/// To address this garbage fire, we can use a user-supplied passphrase to add a layer of security.
/// 
/// When the user creates a passphrase, we do the following:
/// - Generate a random PBKDF salt and store it in the device's secure storage
/// - Run the salt and passphrase through a PBKDF to derive an AEAD key, the _main key_
/// - Generate a random AEAD key, the _data key_
/// - Use the main key to encrypt the data key with the AEAD, and store the encrypted data key in the device's secure storage
/// 
/// When we need to check a user-supplied passphrase for correctness, we do the following:
/// - Fetch the salt and encrypted data key from the device's secure storage
/// - Run the salt and passphrase through the PBKDF to derive a candidate main key
/// - Use the candidate main key to authenticate and decrypt the encrypted data key, and return success or an error
/// 
/// When we then need to write a field name/value pair to the device's secure storage, we do the following:
/// - Use the data key to encrypt the value with the AEAD, with the name as associated data
/// - Return the encrypted value, which is safe to be written to the device's secure storage
/// It's also possible to pad the value to a multiple of a base length, which reduces information available to an adversary.
/// 
/// When we then need to read a field name/value pair from the device's secure storage, we do the following:
/// - Use the data key to decrypt the value with the AEAD, with the name as associated data
/// - Return the decrypted value on success, or an error otherwise
/// 
/// The use of a stored encrypted data key is to faciliate password changes without needing to encrypt data again.
/// When the user wishes to change their passphrase, we do the following:
/// - Generate a random salt and overwrite the existing one in the device's secure storage
/// - Run the salt and passphrase through the PBKDF to derive a new main key
/// - Use the main key to encrypt the data key with the AEAD, and overwrite the existing encrypted data key in the device's secure storage
/// Note that the existing data key is unchanged, so all encrypted name/value pairs are still accessible.
/// This process should be done as atomically as possible, or data loss may occur.
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

/// Constants that should not be changed without good reason
const int owaspRecommendedPbkdf2Sha512Iterations = 120000; // OWASP recommendation: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
const int pbkdf2SaltLength = 16; // in bytes
const String dataKeyDomain = 'STACK_WALLET_DATA_KEY';

/// 
/// Errors
/// 

/// The provided passphrase is incorrect
class IncorrectPassphrase implements Exception {
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
  static Future<StorageCryptoHandler> fromNewPassphrase(String passphrase) async {
    // Generate a random salt
    final salt = _randomBytes(pbkdf2SaltLength);

    // Use the passphrase and salt to derive the main key with the PBKDF
    final mainKey = await _pbkdf2(salt, _stringToBytes(passphrase));

    // Generate a random data key
    final dataKey = _randomBytes(Xchacha20.poly1305Aead().secretKeyLength);

    // Assemble the handler
    return StorageCryptoHandler._(salt, mainKey, dataKey);
  }

  /// Create a handler from an existing passphrase, salt, and encrypted data key
  static Future<StorageCryptoHandler> fromExisting(String passphrase, Uint8List salt, Uint8List encryptedDataKey) async {
    // Check the salt length
    if (salt.length != pbkdf2SaltLength) {
      throw InvalidLength();
    }

    // Derive the candidate main key
    final Uint8List mainKey = await _pbkdf2(salt, _stringToBytes(passphrase));

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
      throw IncorrectPassphrase();
    }
  }

  /// Reset the passphrase, which resets the salt and main key
  Future<void> resetPassphrase(String passphrase) async {
    // Generate a random salt
    _salt = _randomBytes(pbkdf2SaltLength);

    // Use the passphrase and salt to derive the main key with the PBKDF
    _mainKey = await _pbkdf2(_salt, _stringToBytes(passphrase));
  }

  /// Get the salt, which is safe to store
  Uint8List getSalt() {
    return _salt;
  }

  /// Get the encrypted data key, which is safe to store
  Future<Uint8List> getEncryptedDataKey() async {
    // Encrypt the data key
    final SecretBox encryptedDataKey = await _xChaCha20Poly1305Encrypt(
      _mainKey,
      _randomBytes(Xchacha20.poly1305Aead().nonceLength),
      _dataKey,
      _stringToBytes(dataKeyDomain),
    );

    return encryptedDataKey.concatenation();
  }

  /// Encrypt a value and return it, which is safe to store
  Future<Uint8List> encryptValue(String name, Uint8List value, {int? padding}) async {
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
      valueBytes.add(value); // value
      valueBytes.add(List<int>.filled(padding - (padding % value.length), 0x00)); // padding
      
      paddedValue = valueBytes.toBytes();
    }
    // If no padding was provided, prepend the value with 0x00
    else {
      final BytesBuilder valueBytes = BytesBuilder();
      valueBytes.addByte(0x00); // this is not a padded value
      valueBytes.add(value);

      paddedValue = valueBytes.toBytes();
    }

    // Bind the field name as associated data
    final SecretBox encryptedValue = await _xChaCha20Poly1305Encrypt(
      _dataKey,
      _randomBytes(Xchacha20.poly1305Aead().nonceLength),
      paddedValue,
      _stringToBytes(name),
    );

    return encryptedValue.concatenation();
  }

  /// Decrypt a value and return it, which _must not_ be stored
  Future<Uint8List> decryptValue(String name, Uint8List encryptedValue) async {
    try {
      // Bind the field name as associated data
      final Uint8List paddedValue = await _xChaCha20Poly1305Decrypt(
        _dataKey,
        SecretBox.fromConcatenation(
          encryptedValue,
          nonceLength: Xchacha20.poly1305Aead().nonceLength,
          macLength: Poly1305().macLength
        ),
        _stringToBytes(name),
      );

      // We must have at least the padding flag
      if (paddedValue.isEmpty) {
        throw InvalidLength();
      }

      // No padding is present, so return the value
      if (paddedValue[0] == 0x00) {
        return paddedValue.sublist(1);
      }

      // The padding flag is invalid, which should never happen
      if (paddedValue[0] != 0x01) {
        throw BadDecryption();
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

      return paddedValue.sublist(1 + 4, 1 + 4 + valueLength);
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

/// Convert a string to UTF8 bytes
Uint8List _stringToBytes(String data) {
  return Uint8List.fromList(utf8.encode(data));
}

/// PBKDF2/SHA-512
Future<Uint8List> _pbkdf2(Uint8List salt, Uint8List passphrase) async {
  // Set up the PBKDF
  final Pbkdf2 pbkdf = Pbkdf2(
    macAlgorithm: Hmac.sha512(),
    iterations: owaspRecommendedPbkdf2Sha512Iterations,
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
