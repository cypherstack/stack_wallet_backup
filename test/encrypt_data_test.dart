import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/encrypt_data.dart';

/// Utility function to generate random byte lists
List<int> randomBytes(int size) {
  var rng = Random.secure();
  return List<int>.generate(size, (_) => rng.nextInt(0xFF + 1));
}

void main() {
  /// Correct encryption and decryption succeeds
  test('success', () async {
    // Generate recipient keypair
    final SimpleKeyPair recipientKeyPair = await newKeyPair();
    final SimplePublicKey recipientPublicKey = await recipientKeyPair.extractPublicKey();

    // Generate random plaintext
    final Uint8List plaintext = Uint8List.fromList(randomBytes(256));

    // Encrypt
    final Uint8List ciphertext = await encrypt(recipientPublicKey, plaintext);

    // Decrypt
    final Uint8List decrypted = await decrypt(recipientKeyPair, ciphertext);

    expect(decrypted, plaintext);
  });

  /// Bad data length
  test('bad data length', () async {
    // Generate recipient keypair
    final SimpleKeyPair recipientKeyPair = await newKeyPair();

    // Minimum allowed data length
    final int minimumDataLength = KeyPairType.x25519.publicKeyLength + Xchacha20.poly1305Aead().nonceLength + Poly1305().macLength;

    expect(() => decrypt(recipientKeyPair, Uint8List.fromList(randomBytes(minimumDataLength - 1))), throwsA(const TypeMatcher<BadDataSize>()));
  });

  /// Wrong recipient key
  test('wrong recipient key', () async {
    // Generate recipient keypair
    final SimpleKeyPair recipientKeyPair = await newKeyPair();
    final SimplePublicKey recipientPublicKey = await recipientKeyPair.extractPublicKey();

    // Generate random plaintext
    final Uint8List plaintext = Uint8List.fromList(randomBytes(256));

    // Encrypt
    final Uint8List ciphertext = await encrypt(recipientPublicKey, plaintext);

    // Generate wrong key pair
    final SimpleKeyPair wrongRecipientKeyPair = await newKeyPair();

    expect(() => decrypt(wrongRecipientKeyPair, ciphertext), throwsA(const TypeMatcher<FailedDecryption>()));
  });

  /// Evil ephemeral public key
  test('evil ephemeral public key', () async {
    // Generate recipient keypair
    final SimpleKeyPair recipientKeyPair = await newKeyPair();
    final SimplePublicKey recipientPublicKey = await recipientKeyPair.extractPublicKey();

    // Generate random plaintext
    final Uint8List plaintext = Uint8List.fromList(randomBytes(256));

    // Encrypt
    final Uint8List ciphertext = await encrypt(recipientPublicKey, plaintext);

    // Replace the ephemeral public key
    final SimpleKeyPair evilEphemeralKeyPair = await newKeyPair();
    final SimplePublicKey evilEphemeralPublicKey = await evilEphemeralKeyPair.extractPublicKey();
    ciphertext.setRange(0, KeyPairType.x25519.publicKeyLength, evilEphemeralPublicKey.bytes);

    expect(() => decrypt(recipientKeyPair, ciphertext), throwsA(const TypeMatcher<FailedDecryption>()));
  });

  /// Evil nonce
  test('evil nonce', () async {
    // Generate recipient keypair
    final SimpleKeyPair recipientKeyPair = await newKeyPair();
    final SimplePublicKey recipientPublicKey = await recipientKeyPair.extractPublicKey();

    // Generate random plaintext
    final Uint8List plaintext = Uint8List.fromList(randomBytes(256));

    // Encrypt
    final Uint8List ciphertext = await encrypt(recipientPublicKey, plaintext);

    // Replace the nonce
    final int start = KeyPairType.x25519.publicKeyLength;
    final int end = start + Xchacha20.poly1305Aead().nonceLength;
    ciphertext.setRange(start, end, randomBytes(Xchacha20.poly1305Aead().nonceLength));

    expect(() => decrypt(recipientKeyPair, ciphertext), throwsA(const TypeMatcher<FailedDecryption>()));
  });

  /// Evil tag
  test('evil tag', () async {
    // Generate recipient keypair
    final SimpleKeyPair recipientKeyPair = await newKeyPair();
    final SimplePublicKey recipientPublicKey = await recipientKeyPair.extractPublicKey();

    // Generate random plaintext
    final Uint8List plaintext = Uint8List.fromList(randomBytes(256));

    // Encrypt
    final Uint8List ciphertext = await encrypt(recipientPublicKey, plaintext);

    // Replace the tag
    final int start = KeyPairType.x25519.publicKeyLength + Xchacha20.poly1305Aead().nonceLength;
    final int end = start + Poly1305().macLength;
    ciphertext.setRange(start, end, randomBytes(Poly1305().macLength));

    expect(() => decrypt(recipientKeyPair, ciphertext), throwsA(const TypeMatcher<FailedDecryption>()));
  });

  /// Evil ciphertext
  test('evil ciphertext', () async {
    // Generate recipient keypair
    final SimpleKeyPair recipientKeyPair = await newKeyPair();
    final SimplePublicKey recipientPublicKey = await recipientKeyPair.extractPublicKey();

    // Generate random plaintext
    final Uint8List plaintext = Uint8List.fromList(randomBytes(256));

    // Encrypt
    final Uint8List ciphertext = await encrypt(recipientPublicKey, plaintext);

    // Replace the ciphertext
    final int start = KeyPairType.x25519.publicKeyLength + Xchacha20.poly1305Aead().nonceLength + Poly1305().macLength;
    final int end = ciphertext.length;
    ciphertext.setRange(start, end, randomBytes(end - start));

    expect(() => decrypt(recipientKeyPair, ciphertext), throwsA(const TypeMatcher<FailedDecryption>()));
  });
}
