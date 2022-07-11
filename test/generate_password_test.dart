import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/generate_password.dart';

void main() {
  // Character set is valid
  test('character set is valid', () {
    final String characters = getCharacterSet();

    // The character set has the length we expected when writing it
    expect(characters.length, 56);

    // No duplicates
    for (int i = 0; i < characters.length - 1; i++) {
      expect(characters.contains(characters[i], i + 1), false);
    }

    // No invalid symbols
    List<String> invalid = ['o', 'O', '0', 'l', 'I', '1'];
    for (String symbol in invalid) {
      expect(characters.contains(symbol), false);
    }
  });

  // Default password length
  test('default length', () {
    // With our character set, a 128-bit effective entropy target should generate a 23-character password
    String password = generatePassword();
    expect(password.length, getDefaultLength());
    expect(getDefaultLength(), 23);
  });

  // Other password lengths
  List<int> lengths = [0, 1, 2, 32, 64, 128];
  for (int length in lengths) {
    test('length $length', () {
      expect(generatePassword(length).length, length);
    });
  }

  // Entropy from length
  test('entropy from length', () {
    // With our character set, a 16-character password has ~92 bits of effective entropy
    expect(entropyFromLength(16), 92);
  });
}
