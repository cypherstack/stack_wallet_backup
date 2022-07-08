import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:tuple/tuple.dart';

import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/stack_wallet_backup.dart';
import 'package:stack_wallet_backup/stack_wallet_backup_platform_interface.dart';
import 'package:stack_wallet_backup/stack_wallet_backup_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockStackWalletBackupPlatform 
    with MockPlatformInterfaceMixin
    implements StackWalletBackupPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

/// Utility function to generate random byte lists
List<int> randomBytes(int size) {
  var rng = Random.secure();
  return List<int>.generate(size, (_) => rng.nextInt(0xFF));
}

void main() {
  final StackWalletBackupPlatform initialPlatform = StackWalletBackupPlatform.instance;

  test('$MethodChannelStackWalletBackup is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelStackWalletBackup>());
  });

  test('getPlatformVersion', () async {
    StackWalletBackup stackWalletBackupPlugin = StackWalletBackup();
    MockStackWalletBackupPlatform fakePlatform = MockStackWalletBackupPlatform();
    StackWalletBackupPlatform.instance = fakePlatform;
  
    expect(await stackWalletBackupPlugin.getPlatformVersion(), '42');
  });
  
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

  /// Correct encryption and decryption succeeds with default version
  test('success, default version', () async {
    const String passphrase = 'passphrase';
    const String plaintext = 'A secret message to be encrypted';

    // Convert plaintext
    final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

    // Encrypt
    final Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintextBytes);
    PackageData data = raw.item1;

    // Check the version is the most recent
    expect(data.parameters.version, getAllVersions().map((item) => item.version).reduce(max));

    // Encode
    final List<int> checksum = await data.parameters.checksum(data);
    final Uint8List blob = data.encode(checksum);

    // Decrypt
    final Uint8List decryptedBytes = await decrypt(passphrase, blob);

    // Convert ciphertext
    final String decrypted = utf8.decode(decryptedBytes);

    expect(decrypted, plaintext);
  });

  /// Unsupported version
  test('evil version', () async {
    const String passphrase = 'passphrase';
    const String plaintext = 'A secret message to be encrypted';

    // Convert plaintext
    final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

    // Encrypt
    final Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintextBytes);
    PackageData data = raw.item1;

    // Change to an unsupported version
    data.parameters.version = 0;

    // Encode with recomputed checksum
    final List<int> checksum = await data.parameters.checksum(data);
    final Uint8List blob = data.encode(checksum);

    // Decrypt
    expect(() => decrypt(passphrase, blob), throwsA(const TypeMatcher<BadProtocolVersion>()));
  });

  for (int version in getAllVersions().map((item) => item.version)) {
    /// Correct encryption and decryption succeeds
    test('success, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Uint8List blob = await encrypt(passphrase, plaintextBytes, version: version);

      // Decrypt
      final Uint8List decryptedBytes = await decrypt(passphrase, blob);

      // Convert ciphertext
      final String decrypted = utf8.decode(decryptedBytes);

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
      final Uint8List blob = await encrypt(passphrase, plaintextBytes, version: version);

      // Decrypt with an evil passphrase
      expect(() => decrypt(evilPassphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
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
        final Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintextBytes, version: version);
        PackageData data = raw.item1;

        // Change to an evil version
        data.parameters = getVersion(evilVersion);

        // Encode with recomputed checksum
        final List<int> checksum = await data.parameters.checksum(data);
        final Uint8List blob = data.encode(checksum);

        // Decrypt
        expect(() => decrypt(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
      });
    }

    /// Evil PBKDF nonce
    test('evil PBKDF nonce, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintextBytes, version: version);
      PackageData data = raw.item1;

      // Change to an evil PBKDF nonce
      data.pbkdfNonce = randomBytes(data.parameters.pbkdfNonceSize);

      // Encode with recomputed checksum
      final List<int> checksum = await data.parameters.checksum(data);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decrypt(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Evil AEAD nonce
    test('evil AEAD nonce, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintextBytes, version: version);
      PackageData data = raw.item1;

      // Change to an evil AEAD nonce
      data.aeadNonce = randomBytes(data.parameters.aeadNonceSize);

      // Encode with recomputed checksum
      final List<int> checksum = await data.parameters.checksum(data);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decrypt(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Evil AEAD tag
    test('evil AEAD tag, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintextBytes, version: version);
      PackageData data = raw.item1;

      // Change to an evil AEAD tag
      data.aeadTag = randomBytes(data.parameters.aeadTagSize);

      // Encode with recomputed checksum
      final List<int> checksum = await data.parameters.checksum(data);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decrypt(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Corrupted checksum
    test('corrupted checkum, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintextBytes, version: version);
      PackageData data = raw.item1;

      // Encode with corrupted checksum
      final List<int> checksum = randomBytes(data.parameters.checksumSize);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decrypt(passphrase, blob), throwsA(const TypeMatcher<BadChecksum>()));
    });

    /// Evil ciphertext
    test('evil ciphertext, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Tuple2<PackageData, List<int>> raw = await encryptRaw(passphrase, plaintextBytes, version: version);
      PackageData data = raw.item1;

      // Change to an evil ciphertext
      data.ciphertext = randomBytes(data.ciphertext.length);

      // Encode with recomputed checksum
      final List<int> checksum = await data.parameters.checksum(data);
      final Uint8List blob = data.encode(checksum);

      // Decrypt
      expect(() => decrypt(passphrase, blob), throwsA(const TypeMatcher<FailedDecryption>()));
    });

    /// Blob truncation
    test('truncation, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Uint8List blob = await encrypt(passphrase, plaintextBytes, version: version);

      // Decrypt with trunated blob
      final VersionParameters parameters = getVersion(version);
      final int minimumBlobSize = 1 + parameters.pbkdfNonceSize + parameters.aeadNonceSize + parameters.aeadTagSize + parameters.checksumSize;
      expect(() => decrypt(passphrase, blob.sublist(0, minimumBlobSize - 1)), throwsA(const TypeMatcher<BadDataLength>()));
    });

    /// Corrupted data
    test('corrupted data, version $version', () async {
      const String passphrase = 'passphrase';
      const String plaintext = 'A secret message to be encrypted';

      // Convert plaintext
      final Uint8List plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));

      // Encrypt
      final Uint8List blob = await encrypt(passphrase, plaintextBytes);

      // Corrupt the blob
      blob[1] = randomBytes(1)[0];

      // Decrypt
      expect(() => decrypt(passphrase, blob), throwsA(const TypeMatcher<BadChecksum>()));
    });
  }
}
