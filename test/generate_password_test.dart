import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/generate_password.dart';

void main() {
  // Character set is valid
  test('character set is valid', () {
    final String characters = getCharacterSet();

    // Correct number of symbols
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
    expect(generatePassword().length, getPasswordLength());
  });

  // Other password lengths
  List<int> lengths = [0, 1, 2, 32, 64, 128];
  for (int length in lengths) {
    test('length $length', () {
      expect(generatePassword(length: length).length, length);
    });
  }
  
}
