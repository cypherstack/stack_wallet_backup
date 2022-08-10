/// This library signs data and verifies signatures.
///
/// It's effectively just a safe wrapper for library primitives.

import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Bad key type
class BadKeyType implements Exception {
  String errMsg() => 'Bad key type';
}

/// Bad signature
class BadSignature implements Exception {
  String errMsg() => 'Bad signature';
}

/// Generate a key pair
Future<SimpleKeyPair> newKeyPair() async {
  return await Ed25519().newKeyPair();
}

/// Sign data
Future<Uint8List> sign(SimpleKeyPair key, Uint8List message) async {
  // Verify the key is valid for Ed25519
  final keyData = await key.extract();
  if (keyData.type != KeyPairType.ed25519) {
    throw BadKeyType();
  }

  // Sign the data
  final signature = await Ed25519().sign(message, keyPair: key);

  return Uint8List.fromList(signature.bytes);
}

/// Verify a signature
Future<void> verify(SimplePublicKey key, Uint8List message, Uint8List signatureBytes) async {
  // Verify the key is valid for Ed25519
  if (key.type != KeyPairType.ed25519) {
    throw BadKeyType();
  }

  // Verify the signature
  final signature = Signature(signatureBytes, publicKey: key);
  final verified = await Ed25519().verify(message, signature: signature);
  if (!verified) {
    throw BadSignature();
  }
}
