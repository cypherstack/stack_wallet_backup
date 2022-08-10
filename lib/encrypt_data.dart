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
  final Blake2b hasher = Blake2b();
  final HashSink streamer = hasher.newHashSink();
  streamer.add(utf8.encode("Stack Wallet data encryption key"));
  streamer.add(await sharedSecret.extractBytes());
  streamer.close();
  final Hash output = await streamer.hash();

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
  final SimpleKeyPair ephemeralKey = await X25519().newKeyPair();
  final SimplePublicKey ephemeralPublicKey = await ephemeralKey.extractPublicKey();

  // Produce an ECDH shared secret against the recipient public key
  final SecretKey sharedSecret = await X25519().sharedSecretKey(keyPair: ephemeralKey, remotePublicKey: recipient);

  // Use a KDF to produce an AEAD key from the shared secret
  final List<int> aeadKey = await kdf(sharedSecret);

  // Encrypt the data with an AEAD
  Random rng = Random.secure();
  final List<int> nonce = List<int>.generate(Xchacha20.poly1305Aead().nonceLength, (_) => rng.nextInt(0xFF + 1));
  final SecretBox ciphertext = await Xchacha20.poly1305Aead().encrypt(
    data,
    secretKey: SecretKey(aeadKey),
    nonce: nonce,
    aad: utf8.encode("Stack Wallet data encryption AEAD ") + ephemeralPublicKey.bytes + recipient.bytes
  );

  // Encode the output
  final BytesBuilder bytes = BytesBuilder();
  bytes.add(ephemeralPublicKey.bytes);
  bytes.add(ciphertext.nonce);
  bytes.add(ciphertext.mac.bytes);
  bytes.add(ciphertext.cipherText);

  return bytes.toBytes();
}

/// Decrypt data
Future<Uint8List> decrypt(SimpleKeyPair key, Uint8List data) async {
  // Verify the key is valid for X25519
  final SimplePublicKey publicKey = await key.extractPublicKey();
  if (publicKey.type != KeyPairType.x25519) {
    throw BadKeyType();
  }

  // We need enough data
  if (data.length < KeyPairType.x25519.publicKeyLength + Xchacha20.poly1305Aead().nonceLength + Poly1305().macLength) {
    throw BadDataSize();
  }

  // Extract data from the ciphertext
  int counter = 0;
  final Uint8List ephemeralPublicKey = data.sublist(counter, counter + KeyPairType.x25519.publicKeyLength);
  counter += KeyPairType.x25519.publicKeyLength;
  final Uint8List nonce = data.sublist(counter, counter + Xchacha20.poly1305Aead().nonceLength);
  counter += Xchacha20.poly1305Aead().nonceLength;
  final Uint8List mac = data.sublist(counter, counter + Poly1305().macLength);
  counter += Poly1305().macLength;
  final Uint8List ciphertext = data.sublist(counter);

  // Produce an ECDH shared secret against the ephemeral public key
  final SecretKey sharedSecret = await X25519().sharedSecretKey(keyPair: key, remotePublicKey: SimplePublicKey(ephemeralPublicKey, type: KeyPairType.x25519));

  // Use a KDF to produce an AEAD key from the shared secret
  final List<int> aeadKey = await kdf(sharedSecret);

  // Decrypt the data with an AEAD
  final SecretBox aeadData = SecretBox(
    ciphertext,
    nonce: nonce,
    mac: Mac(mac)
  );
  try {
    final List<int> plaintext = await Xchacha20.poly1305Aead().decrypt(
      aeadData,
      secretKey: SecretKey(aeadKey),
      aad: utf8.encode("Stack Wallet data encryption AEAD ") + ephemeralPublicKey + publicKey.bytes
    );

    return Uint8List.fromList(plaintext);
  } on SecretBoxAuthenticationError {
    throw FailedDecryption();
  }
}
