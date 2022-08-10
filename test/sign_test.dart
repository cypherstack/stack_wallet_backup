import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/sign.dart';

/// Utility function to generate random byte lists
List<int> randomBytes(int size) {
  var rng = Random.secure();
  return List<int>.generate(size, (_) => rng.nextInt(0xFF + 1));
}

void main() {
  // Successful signing and verification
  test('success', () async {
    // Generate keypair
    SimpleKeyPair keyPair = await newKeyPair();
    SimplePublicKey publicKey = await keyPair.extractPublicKey();

    // Generate random message
    final message = Uint8List.fromList(randomBytes(256));

    // Sign
    Uint8List signature = await sign(keyPair, message);

    // Verify
    await verify(publicKey, message, signature);
  });

  // Wrong verification key
  test('wrong verification key', () async {
    // Generate keypair
    SimpleKeyPair keyPair = await newKeyPair();

    // Generate random message
    final message = Uint8List.fromList(randomBytes(256));

    // Sign
    Uint8List signature = await sign(keyPair, message);

    // Generate wrong key pair
    SimpleKeyPair wrongKeyPair = await newKeyPair();
    SimplePublicKey wrongPublicKey = await wrongKeyPair.extractPublicKey();

    // Verify
    expect(() => verify(wrongPublicKey, message, signature), throwsA(const TypeMatcher<BadSignature>()));
  });

  // Evil message
  test('evil message', () async {
    // Generate keypair
    SimpleKeyPair keyPair = await newKeyPair();
    SimplePublicKey publicKey = await keyPair.extractPublicKey();

    // Generate random message
    final message = Uint8List.fromList(randomBytes(256));

    // Sign
    Uint8List signature = await sign(keyPair, message);

    // Replace message
    final evilMessage = Uint8List.fromList(randomBytes(256));

    // Verify
    expect(() => verify(publicKey, evilMessage, signature), throwsA(const TypeMatcher<BadSignature>()));
  });

  // Evil signature (random)
  test('evil signature (random)', () async {
    // Generate keypair
    SimpleKeyPair keyPair = await newKeyPair();
    SimplePublicKey publicKey = await keyPair.extractPublicKey();

    // Generate random message
    final message = Uint8List.fromList(randomBytes(256));

    // Sign
    Uint8List signature = await sign(keyPair, message);

    // Replace signature
    final evilSignature = Uint8List.fromList(randomBytes(signature.length));

    // Verify
    expect(() => verify(publicKey, message, evilSignature), throwsA(const TypeMatcher<BadSignature>()));
  });

  // Evil signature (other message)
  test('evil signature (other message)', () async {
    // Generate keypair
    SimpleKeyPair keyPair = await newKeyPair();
    SimplePublicKey publicKey = await keyPair.extractPublicKey();

    // Generate random message
    final message = Uint8List.fromList(randomBytes(256));

    // Sign
    Uint8List signature = await sign(keyPair, message);

    // Replace signature
    final otherMessage = Uint8List.fromList(randomBytes(256));
    Uint8List otherSignature = await sign(keyPair, otherMessage);

    // Verify
    expect(() => verify(publicKey, message, otherSignature), throwsA(const TypeMatcher<BadSignature>()));
  });
}
