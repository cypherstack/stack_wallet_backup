import 'dart:convert';
import 'dart:typed_data';

import 'package:stack_wallet_backup/stack_wallet_backup.dart';

Future<void> main() async {
  const String passphrase = 'correct horse battery staple';
  final Uint8List plaintext =
      Uint8List.fromList(utf8.encode('A secret message to be backed up'));

  // Encrypt with a passphrase
  final Uint8List blob = await encryptWithPassphrase(passphrase, plaintext);
  print('Encrypted ${plaintext.length} bytes to a ${blob.length} byte blob');

  // Decrypt with the same passphrase
  final Uint8List decrypted = await decryptWithPassphrase(passphrase, blob);
  print('Decrypted: ${utf8.decode(decrypted)}');
}
