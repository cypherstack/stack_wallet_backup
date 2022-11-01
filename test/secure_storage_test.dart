import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/secure_storage.dart';

/// Generate cryptographically-secure random bytes
Uint8List _randomBytes(int n) {
  Random rng = Random.secure();
  return Uint8List.fromList(List<int>.generate(n, (_) => rng.nextInt(0xFF + 1)));
}

/// Generate cryptographically-secure random Base64 string
String _randomBase64(int n) {
  const String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
  Random rng = Random.secure();
  String result = '';
  for (int i = 0; i < n; i++) {
    result += alphabet[rng.nextInt(alphabet.length)];
  }

  return result;
}

const int saltLength = 16; // must match the library's value, which is private

void main() {
  /// Example operations
  test('examples', () async {
    // Create a storage handler from a new passphrase
    const String passphrase = 'test';
    StorageCryptoHandler handler = await StorageCryptoHandler.fromNewPassphrase(passphrase);

    // Fetch the key blob
    // We would then store it in the device's secure storage
    // WARNING: Make sure you don't accidentally overwrite this with another name/value pair!
    final String keyBlob = await handler.getKeyBlob();

    // Prepare name/value data for padded encryption
    // Names are strings, but values must be UTF8 byte lists
    String name = 'secret_data_that_should_be_padded';
    String value = 'the secret data to pad';

    // Encrypt the value, padding to the next multiple of an arbitrary base length
    // We would then store `(name, encryptedValue)` in the device's secure storage
    const int padding = 64; // in bytes
    String encryptedValue = await handler.encryptValue(name, value, padding: padding);

    // Decrypt the value, removing the padding automatically
    // We would have retrieved `(name, encryptedValue)` from the device's secure storage
    String decryptedValue = await handler.decryptValue(name, encryptedValue);
    expect(decryptedValue, value);

    // Now do the same for unpadded data, where we don't care about leaking the value length
    name = 'secret_data_that_should_not_be_padded';
    value = 'the secret data not to pad';
    encryptedValue = await handler.encryptValue(name, value);
    decryptedValue = await handler.decryptValue(name, encryptedValue);
    expect(decryptedValue, value);

    // Handle the case where the data was manipulated by an adversary
    final String evilEncryptedValue = _randomBase64(encryptedValue.length);
    expect(() => handler.decryptValue(name, evilEncryptedValue), throwsA(const TypeMatcher<BadDecryption>()));

    // Now suppose we want to create a storage handler where the user already has a passphrase and stored data
    // We would have retrived the key blob from the device's secure storage
    handler = await StorageCryptoHandler.fromExisting(passphrase, keyBlob);

    // Now we can decrypt as usual
    decryptedValue = await handler.decryptValue(name, encryptedValue);
    expect(decryptedValue, value);

    // Oh no! The user forgot their passphrase
    const incorrectPassphrase = 'pony';
    expect(() => StorageCryptoHandler.fromExisting(incorrectPassphrase, keyBlob), throwsA(const TypeMatcher<IncorrectPassphrase>()));

    // Now the user wants to change their passphrase on an existing storage handler
    const newPassphrase = 'my favorite color is blue';
    handler.resetPassphrase(newPassphrase);

    // Now the key blob has changed
    // It must be stored in the device's secure storage, presumably overwriting the old one
    // Without this, all the encrypted data is useless, so don't lose it!
    final newKeyBlob = handler.getKeyBlob();
    expect(newKeyBlob, isNot(keyBlob));
  });

  /// Padding
  test('padding', () async {
    // Create handler
    const String passphrase = 'test';
    final StorageCryptoHandler handler = await StorageCryptoHandler.fromNewPassphrase(passphrase);

    // Test padding
    const int padding = 64;
    const String name = 'field name';
    const String value = 'yay padding';

    for (int i = 1; i <= 2 * padding + 1; i++) {
      String encryptedValue = await handler.encryptValue(name, value, padding: padding);

      // Assert the padding is correct
      int paddedBytesLength = 
        base64.decode(encryptedValue).length
        - 1 // padding flag
        - 4 // encoded length
        - Xchacha20.poly1305Aead().nonceLength
        - Poly1305().macLength;
      expect(paddedBytesLength % padding, 0);

      // Assert that we recover the unpadded value
      final decryptedValue = await handler.decryptValue(name, encryptedValue);
      expect(decryptedValue, value);
    }
  });

  /// Failure modes
  test('failures', () async {
    // Create handler
    const String passphrase = 'test';
    final StorageCryptoHandler handler = await StorageCryptoHandler.fromNewPassphrase(passphrase);
    final String keyBlob = await handler.getKeyBlob();

    // Evil passphrase
    const String evilPassphrase = 'evil';
    expect(() => StorageCryptoHandler.fromExisting(evilPassphrase, keyBlob), throwsA(const TypeMatcher<IncorrectPassphrase>()));

    // Bad key blob size
    final String badKeyBlob = base64.encode(_randomBytes(
      saltLength
      + Xchacha20.poly1305Aead().nonceLength
      + Poly1305().macLength
    )); // too short
    expect(() => StorageCryptoHandler.fromExisting(passphrase, badKeyBlob), throwsA(const TypeMatcher<InvalidLength>()));

    // Evil key blob
    final String evilKeyBlob = base64.encode(_randomBytes(
      saltLength
      + Xchacha20.poly1305Aead().nonceLength
      + Xchacha20.poly1305Aead().secretKeyLength
      + Poly1305().macLength
    ));
    expect(() => StorageCryptoHandler.fromExisting(passphrase, evilKeyBlob), throwsA(const TypeMatcher<IncorrectPassphrase>()));

    // Encrypt some unpadded data
    const String name = 'field name';
    const String value = 'field value';
    String encryptedValue = await handler.encryptValue(name, value);

    // Evil name
    const String evilName = 'evil field name';
    expect(() => handler.decryptValue(evilName, encryptedValue), throwsA(const TypeMatcher<BadDecryption>()));

    // Bad encrypted value size
    String badEncryptedValue = base64.encode(_randomBytes(
      Xchacha20.poly1305Aead().nonceLength
      + 1 // padding flag
      + utf8.encode(value).length - 1 // too short!
      + Poly1305().macLength
    ));
    expect(() => handler.decryptValue(name, badEncryptedValue), throwsA(const TypeMatcher<BadDecryption>()));

    // Evil encrypted value
    String evilEncryptedValue = base64.encode(_randomBytes(
      Xchacha20.poly1305Aead().nonceLength
      + 1 // padding flag
      + utf8.encode(value).length
      + Poly1305().macLength
    ));
    expect(() => handler.decryptValue(name, evilEncryptedValue), throwsA(const TypeMatcher<BadDecryption>()));

    // Encrypt some padded data
    const int padding = 16; // arbitrary
    encryptedValue = await handler.encryptValue(name, value, padding: padding);

    // Evil name
    expect(() => handler.decryptValue(evilName, encryptedValue), throwsA(const TypeMatcher<BadDecryption>()));

    // Bad encrypted value size
    badEncryptedValue = base64.encode(_randomBytes(
      Xchacha20.poly1305Aead().nonceLength
      + 1 // padding flag
      + 4 // encoded length
      + utf8.encode(value).length
      + padding - (value.length % padding) - 1 // too short!
      + Poly1305().macLength
    ));
    expect(() => handler.decryptValue(name, badEncryptedValue), throwsA(const TypeMatcher<BadDecryption>()));

    // Evil encrypted value
    evilEncryptedValue = base64.encode(_randomBytes(
      Xchacha20.poly1305Aead().nonceLength
      + 1 // padding flag
      + 4 // encoded length
      + utf8.encode(value).length
      + padding - (value.length % padding) // padding
      + Poly1305().macLength
    ));
    expect(() => handler.decryptValue(name, evilEncryptedValue), throwsA(const TypeMatcher<BadDecryption>()));

  });
}
