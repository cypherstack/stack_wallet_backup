import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/secure_storage.dart';

void main() {
  /// Example operations
  test('examples', () async {
    // Create a storage handler from a new passphrase
    const String passphrase = 'test';
    StorageCryptoHandler handler = await StorageCryptoHandler.fromNewPassphrase(passphrase);

    // Fetch the salt and encrypted data key
    // We should then store `salt` and `encryptedDataKey` in the device's secure storage
    // WARNING: Make sure you don't accidentally overwrite these with a later name/value pair!
    final Uint8List salt = handler.getSalt();
    final Uint8List encryptedDataKey = await handler.getEncryptedDataKey();

    // Prepare name/value data for padded encryption
    // Names are strings, but values must be UTF8 byte lists
    String name = 'secret_data_that_should_be_padded';
    Uint8List value = Uint8List.fromList(utf8.encode('the secret data to pad'));

    // Encrypt the value, padding to the next multiple of (arbitrarily) 64 bytes
    // We could then store `(name, encryptedValue)` in the device's secure storage
    Uint8List encryptedValue = await handler.encryptValue(name, value, padding: 64);

    // Decrypt the value, removing the padding automatically
    // We would have retrieved `(name, encryptedValue)` from the device's secure storage
    Uint8List decryptedValue = await handler.decryptValue(name, encryptedValue);
    expect(decryptedValue, value);

    // Now do the same for unpadded data, where we don't care about leaking the value length
    name = 'secret_data_that_should_not_be_padded';
    value = Uint8List.fromList(utf8.encode('the secret data not to pad'));
    encryptedValue = await handler.encryptValue(name, value);
    decryptedValue = await handler.decryptValue(name, encryptedValue);
    expect(decryptedValue, value);

    // Handle the case where the data was manipulated by an adversary
    encryptedValue[0] = ~encryptedValue[0]; // an evil byte flip
    expect(() => handler.decryptValue(name, encryptedValue), throwsA(const TypeMatcher<BadDecryption>()));
    encryptedValue[0] = ~encryptedValue[0]; // flip it back

    // Now suppose we want to create a storage handler where the user already has a passphrase and stored data
    // We would have retrived `salt` and `encryptedDataKey` from the device's secure storage
    const correctPassphrase = 'test';
    handler = await StorageCryptoHandler.fromExisting(correctPassphrase, salt, encryptedDataKey);

    // Now we can decrypt as usual
    decryptedValue = await handler.decryptValue(name, encryptedValue);
    expect(decryptedValue, value);

    // Oh no! The user forgot their passphrase
    const incorrectPassphrase = 'pony';
    expect(() => StorageCryptoHandler.fromExisting(incorrectPassphrase, salt, encryptedDataKey), throwsA(const TypeMatcher<IncorrectPassphrase>()));

    // Now the user wants to change their passphrase on an existing storage handler
    const newPassphrase = 'my favorite color is blue';
    handler.resetPassphrase(newPassphrase);

    // Now `salt` and `encryptedDataKey` have changed
    // They must be stored in the device's secure storage, replacing the old ones
    // Without these, all the encrypted data is useless, so don't lose them!
    final newSalt = handler.getSalt();
    final newEncryptedDataKey = handler.getEncryptedDataKey();
    expect(newSalt, isNot(salt));
    expect(newEncryptedDataKey, isNot(encryptedDataKey));
  });
}
