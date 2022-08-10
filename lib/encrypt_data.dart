/// This library encrypts data for a recipient using a public key.
/// 
/// Given data and the recipient's public key, we generate an ephemeral private key and use it to perform an ECDH exchange.
/// The resulting shared secret is passed through a key derivation function to produce an AEAD key.
/// This AEAD key is used to encrypt the data, with the ephemeral public key and recipient public key bound as associated data.
/// The resulting output consists of the ephemeral public key and the AEAD nonce, ciphertext, and tag.
/// 
/// Note that because we use a stream cipher AEAD, the plaintext data length is trivially leaked.
/// This can be mitigated using padding, but we don't do this here.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Bad key type
class BadKeyType implements Exception {
  String errMsg() => 'Bad key type';
}

/// Bad data size
class BadDataSize implements Exception {
  String errMsg() => 'Bad data size';
}

/// Failed decryption
class FailedDecryption implements Exception {
  String errMsg() => 'Failed decryption';
}

/// Generate a key pair
Future<SimpleKeyPair> newKeyPair() async {
  return await X25519().newKeyPair();
}

/// Derive an AEAD key from an ECDH shared secret
Future<List<int>> kdf(SecretKey sharedSecret) async {
  final hasher = Blake2b();
  final streamer = hasher.newHashSink();
  streamer.add(utf8.encode("Stack Wallet data encryption key"));
  streamer.add(await sharedSecret.extractBytes());
  streamer.close();
  final output = await streamer.hash();

  // Sanity check that the key is the proper length
  if (output.bytes.length < Xchacha20.poly1305Aead().secretKeyLength) {
    throw BadDataSize();
  }

  return output.bytes.sublist(0, Xchacha20.poly1305Aead().secretKeyLength);

}

/// Encrypt data using a recipient public key
Future<Uint8List> encrypt(SimplePublicKey recipient, Uint8List data) async {
  // Verify the key is valid for X25519
  if (recipient.type != KeyPairType.x25519) {
    throw BadKeyType();
  }

  // Generate an ephemeral key pair
  final ephemeralKey = await X25519().newKeyPair();
  final ephemeralPublicKey = await ephemeralKey.extractPublicKey();

  // Produce an ECDH shared secret against the recipient public key
  final sharedSecret = await X25519().sharedSecretKey(keyPair: ephemeralKey, remotePublicKey: recipient);

  // Use a KDF to produce an AEAD key from the shared secret
  final aeadKey = await kdf(sharedSecret);

  // Encrypt the data with an AEAD
  var rng = Random.secure();
  final nonce = List<int>.generate(24, (_) => rng.nextInt(0xFF + 1));
  final ciphertext = await Xchacha20.poly1305Aead().encrypt(
    data,
    secretKey: SecretKey(aeadKey),
    nonce: nonce,
    aad: utf8.encode("Stack Wallet data encryption AEAD ") + ephemeralPublicKey.bytes
  );

  // Encode the output
  final bytes = BytesBuilder();
  bytes.add(ephemeralPublicKey.bytes);
  bytes.add(ciphertext.nonce);
  bytes.add(ciphertext.mac.bytes);
  bytes.add(ciphertext.cipherText);

  return bytes.toBytes();
}

/// Decrypt data
Future<Uint8List> decrypt(SimpleKeyPair key, Uint8List data) async {
  // Verify the key is valid for X25519
  SimpleKeyPairData keyData = await key.extract();
  if (keyData.type != KeyPairType.x25519) {
    throw BadKeyType();
  }

  // We need enough data
  if (data.length < KeyPairType.x25519.publicKeyLength + Xchacha20.poly1305Aead().nonceLength + Poly1305().macLength) {
    throw BadDataSize();
  }

  // Extract data from the ciphertext
  var counter = 0;
  final ephemeralPublicKey = data.sublist(counter, counter + KeyPairType.x25519.publicKeyLength);
  counter += KeyPairType.x25519.publicKeyLength;
  final nonce = data.sublist(counter, counter + Xchacha20.poly1305Aead().nonceLength);
  counter += Xchacha20.poly1305Aead().nonceLength;
  final mac = data.sublist(counter, counter + Poly1305().macLength);
  counter += Poly1305().macLength;
  final ciphertext = data.sublist(counter);

  // Produce an ECDH shared secret against the ephemeral public key
  final sharedSecret = await X25519().sharedSecretKey(keyPair: key, remotePublicKey: SimplePublicKey(ephemeralPublicKey, type: KeyPairType.x25519));

  // Use a KDF to produce an AEAD key from the shared secret
  final aeadKey = await kdf(sharedSecret);

  // Decrypt the data with an AEAD
  final aeadData = SecretBox(
    ciphertext,
    nonce: nonce,
    mac: Mac(mac)
  );
  try {
    final plaintext = await Xchacha20.poly1305Aead().decrypt(
      aeadData,
      secretKey: SecretKey(aeadKey),
      aad: utf8.encode("Stack Wallet data encryption AEAD ") + ephemeralPublicKey
    );

    return Uint8List.fromList(plaintext);
  } on SecretBoxAuthenticationError {
    throw FailedDecryption();
  }
}
