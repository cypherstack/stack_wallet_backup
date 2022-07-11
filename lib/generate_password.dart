/// This library generates secure passwords with a very limited character set.
/// It is intended for use cases where the target implementation restricts to alphanumeric values only.
/// 
/// Our character set is a subset of `[0-9a-zA-Z]` where we exclude similar-looking symbols.
/// To help the user, we exclude the following set: `{o, O, 0, l, I, 1}`
/// This means our character set contains (10 + 26 + 26 - 6) = 56 symbols.
/// By using a 16-character password, we achive `log2(56^16) ~ 93` bits, which should be plenty.
/// 
/// This is the default length, but you can override it.

import 'dart:math';

const String _safeLowerCase = 'abcdefghijkmnpqrstuvwxyz'; // all letters except `l, o`
const String _safeUpperCase = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // all letters except 'I, O'
const String _safeDigits = '23456789'; // all digits except `0, 1`
const int _passwordLength = 16; // about 93 bits of effective entropy using this character set

// Returns the default length for testing purposes
int getPasswordLength() {
  return _passwordLength;
}

// Returns the full character set for testing purposes
String getCharacterSet() {
  // Set up the complete character set
  return _safeLowerCase + _safeUpperCase + _safeDigits;
}

String generatePassword({int length = _passwordLength}) {
  // Require a cryptographically-secure RNG
  var rng = Random.secure();

  // Get the full character set
  final String characters = getCharacterSet();

  // Select random elements and build the password
  String result = '';
  for (int i = 0; i < length; i++) {
    result += characters[rng.nextInt(characters.length)];
  }

  return result;
}
