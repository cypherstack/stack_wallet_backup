import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:tuple/tuple.dart';

import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/stack_wallet_backup.dart';

/// Utility function to generate random byte lists
Uint8List randomBytes(int size) {
  Random rng = Random.secure();
  return Uint8List.fromList(List<int>.generate(size, (_) => rng.nextInt(0xFF + 1)));
}

void main() {
  ///
  /// Version-independent tests
  /// 

  /// All version numbers are valid
  test('version numbers are valid', () {
    // Sanity checks; versions cannot repeat and must fit in a single byte
    List<int> versionNumbers = [];
    for (VersionParameters version in getAllVersions()) {
      expect(version.version, lessThanOrEqualTo(0xFF));
      expect(versionNumbers.contains(version.version), false);

      versionNumbers.add(version.version);
    }
  });

  /// Ensure the default version is correct
  test('default version', () async {
    const String passphrase = 'passphrase';
    const String plaintext = 'A secret message to be encrypted';

    // Convert plaintext
    final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

    // Encrypt
    final Tuple2<PackageData, Uint8List> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes);
    final PackageData data = raw.item1;

    // Check that the version is the most recent
    expect(data.parameters.version, getAllVersions().map((item) => item.version).reduce(max));
  });

  /// Unsupported version
  test('evil version', () async {
    const String passphrase = 'passphrase';
    const String plaintext = 'A secret message to be encrypted';

    // Convert plaintext
    final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

    // Encrypt
    final Tuple2<PackageData, Uint8List> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes);
    final PackageData data = raw.item1;

    // Change to an unsupported version
    data.parameters.version = 0;

    // Encode with recomputed checksum
    final Uint8List checksum = await data.parameters.checksum(data);
    final Uint8List blob = data.encode(checksum);

    // Decrypt
    expect(() => decryptWithPassphrase(passphrase, blob), throwsA(const TypeMatcher<BadProtocolVersion>()));
  });

  ///
  /// Version-dependent tests
  /// 
  for (int version in getAllVersions().map((item) => item.version)) {
    /// Correct encryption and decryption succeeds with passphrase (manual backup)
    test('success, passphrase, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Uint8List blob = await encryptWithPassphrase(passphrase, plaintextBytes, version: version);

      // Decrypt, convert, and check correctness
      final Uint8List decryptedBytes = await decryptWithPassphrase(passphrase, blob);
      final String decrypted = utf8.decode(decryptedBytes);
      expect(decrypted, plaintext);
    });

    /// Correct encryption and decryption succeeds with ADK (automated backup)
    test('success, ADK, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Compute ADK (this would be stored in the device enclave and, if needed, later retrived for decryption)
      final Uint8List adk = await generateAdk(passphrase);

      // Encrypt
      final Uint8List blob = await encryptWithAdk(adk, plaintextBytes, version: version);

      // Decrypt with passphrase, convert, and check correctness
      // NOTE: This corresponds to an automated backup decrypted without access to the device enclave
      Uint8List decryptedBytes = await decryptWithPassphrase(passphrase, blob);
      String decrypted = utf8.decode(decryptedBytes);
      expect(decrypted, plaintext);

      // Decrypt with ADK, convert, and check correctness
      // NOTE: This corresponds to an automated backup decrypted with access to the device enclave
      decryptedBytes = await decryptWithAdk(adk, blob);
      decrypted = utf8.decode(decryptedBytes);
      expect(decrypted, plaintext);
    });

    /// Evil passphrase
    test('evil passphrase, version $version', () async {
      const String passphrase = 'passphrase';
      const String evilPassphrase = 'evil passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Uint8List blob = await encryptWithPassphrase(passphrase, plaintextBytes, version: version);

      // Decrypt with an evil passphrase
      expect(() => decryptWithPassphrase(evilPassphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Evil ADK
    test('evil ADK, version $version', () async {
      const String passphrase = 'passphrase';
      const String evilPassphrase = 'evil passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Compute ADK
      final Uint8List adk = await generateAdk(passphrase);

      // Encrypt
      final Uint8List blob = await encryptWithAdk(adk, plaintextBytes, version: version);

      // Compute evil ADK
      final Uint8List evilAdk = await generateAdk(evilPassphrase);

      // Decrypt with an evil ADK
      expect(() => decryptWithAdk(evilAdk, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    // Unlinkability under identical passphrase
    test('unlinkability, passphrase, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt twice to simulate multiple backups; we even use the same plaintext!
      final Tuple2<PackageData, Uint8List> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes, version: version);
      final PackageData data = raw.item1;
      final Uint8List checksum = raw.item2;

      final Tuple2<PackageData, Uint8List> otherRaw = await encryptRawWithPassphrase(passphrase, plaintextBytes, version: version);
      final PackageData otherData = otherRaw.item1;
      final Uint8List otherChecksum = otherRaw.item2;

      // Ensure that each non-version component of the data is distinct across backups, to assert no obvious linkability
      expect(data.parameters.version, otherData.parameters.version);
      expect(data.pbkdfSalt, isNot(equals(otherData.pbkdfSalt)));
      expect(data.aeadNonce, isNot(equals(otherData.aeadNonce)));
      expect(data.aeadTag, isNot(equals(otherData.aeadTag)));
      expect(data.ciphertext, isNot(equals(otherData.ciphertext)));
      expect(checksum, isNot(equals(otherChecksum)));
    });

    // Unlinkability under identical ADK
    test('unlinkability, adk, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Compute ADK
      final Uint8List adk = await generateAdk(passphrase);

      // Encrypt twice to simulate multiple backups; we even use the same plaintext!
      final Tuple2<PackageData, Uint8List> raw = await encryptRawWithAdk(adk, plaintextBytes, version: version);
      final PackageData data = raw.item1;
      final Uint8List checksum = raw.item2;

      final Tuple2<PackageData, Uint8List> otherRaw = await encryptRawWithAdk(adk, plaintextBytes, version: version);
      final PackageData otherData = otherRaw.item1;
      final Uint8List otherChecksum = otherRaw.item2;

      // Ensure that each non-version component of the data is distinct across backups, to assert no obvious linkability
      expect(data.parameters.version, otherData.parameters.version);
      expect(data.pbkdfSalt, isNot(equals(otherData.pbkdfSalt)));
      expect(data.aeadNonce, isNot(equals(otherData.aeadNonce)));
      expect(data.aeadTag, isNot(equals(otherData.aeadTag)));
      expect(data.ciphertext, isNot(equals(otherData.ciphertext)));
      expect(checksum, isNot(equals(otherChecksum)));
    });

    /// Evil version
    /// NOTE: In the future, parameter differences may require more hand-tuned tests
    for (int evilVersion in getAllVersions().map((item) => item.version)) {
      // Must be a different version
      if (evilVersion == version) {
        continue;
      }

      test('evil version, $version to $evilVersion', () async {
        const String passphrase = 'passphrase';
        const String plaintext = 'A secret message to be encrypted';

        // Convert plaintext
        final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

        // Encrypt
        final Tuple2<PackageData, Uint8List> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes, version: version);
        final PackageData data = raw.item1;

        // Change to an evil version
        data.parameters = getVersion(evilVersion);

        // Encode with recomputed checksum
        final Uint8List checksum = await data.parameters.checksum(data);
        final Uint8List blob = data.encode(checksum);

        // Decrypt
        expect(() => decryptWithPassphrase(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
      });
    }

    /// Evil PBKDF salt 
    test('evil PBKDF salt, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, Uint8List> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes, version: version);
      final PackageData data = raw.item1;

      // Change to an evil PBKDF salt
      data.pbkdfSalt = randomBytes(data.parameters.pbkdfSaltSize);

      // Encode with recomputed checksum
      final Uint8List checksum = await data.parameters.checksum(data);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decryptWithPassphrase(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Evil AEAD nonce
    test('evil AEAD nonce, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, Uint8List> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes, version: version);
      PackageData data = raw.item1;

      // Change to an evil AEAD nonce
      data.aeadNonce = randomBytes(data.parameters.aeadNonceSize);

      // Encode with recomputed checksum
      final Uint8List checksum = await data.parameters.checksum(data);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decryptWithPassphrase(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Evil AEAD tag
    test('evil AEAD tag, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, List<int>> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes, version: version);
      final PackageData data = raw.item1;

      // Change to an evil AEAD tag
      data.aeadTag = randomBytes(data.parameters.aeadTagSize);

      // Encode with recomputed checksum
      final Uint8List checksum = await data.parameters.checksum(data);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decryptWithPassphrase(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Corrupted checksum
    test('corrupted checkum, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, Uint8List> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes, version: version);
      final PackageData data = raw.item1;

      // Encode with corrupted checksum
      final Uint8List checksum = randomBytes(data.parameters.checksumSize);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decryptWithPassphrase(passphrase, blob), throwsA(const TypeMatcher<BadChecksum>()));
    });

    /// Evil ciphertext
    test('evil ciphertext, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, Uint8List> raw = await encryptRawWithPassphrase(passphrase, plaintextBytes, version: version);
      final PackageData data = raw.item1;

      // Change to an evil ciphertext
      data.ciphertext = randomBytes(data.ciphertext.length);

      // Encode with recomputed checksum
      final Uint8List checksum = await data.parameters.checksum(data);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decryptWithPassphrase(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Blob truncation
    test('truncation, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Uint8List blob = await encryptWithPassphrase(passphrase, plaintextBytes, version: version);

      // Decrypt with trunated blob
      final VersionParameters parameters = getVersion(version);
      final int minimumBlobSize = 1 + parameters.pbkdfSaltSize + parameters.aeadNonceSize + parameters.aeadTagSize + parameters.checksumSize;
      expect(() => decryptWithPassphrase(passphrase, blob.sublist(0, minimumBlobSize - 1)), throwsA(const TypeMatcher<BadDataLength>()));
    });

    /// Corrupted data
    test('corrupted data, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Uint8List blob = await encryptWithPassphrase(passphrase, plaintextBytes);

      // Corrupt the blob
      blob[1] = randomBytes(1)[0];

      // Decrypt
      expect(() => decryptWithPassphrase(passphrase, blob), throwsA(const TypeMatcher<BadChecksum>()));
    });
  }
}
