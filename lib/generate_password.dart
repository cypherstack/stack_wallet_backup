/// This library generates secure passwords with a very limited character set.
/// It is intended for use cases where the target implementation restricts to alphanumeric values only.
/// 
/// Our character set is a subset of `[0-9a-zA-Z]` where we exclude similar-looking symbols.
/// To help the user, we exclude the following set: `{o, O, 0, l, I, 1}`
/// This means our character set contains (10 + 26 + 26 - 6) = 56 symbols.
/// 
/// By default, we play it super safe and generate a 128-bit password, which assumes no subsequent PBKDF is used.
/// This is the default behavior, but you can specify your own password length.
/// You can also use the `lengthFromEntropy` function to compute the length required for a target entropy level, and pass this length instead.
/// This might be useful if you know the password is passed through a suitable PBKDF and can tolerate lower effective entropy.
/// Your call.

import 'dart:math';

const String _safeLowerCase = 'abcdefghijkmnpqrstuvwxyz'; // all letters except `l, o`
const String _safeUpperCase = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // all letters except 'I, O'
const String _safeDigits = '23456789'; // all digits except `0, 1`
const int _entropyTarget = 128; // this assumes no subsequent PBKDF

/// Return the default length for testing purposes
int getDefaultLength() {
  return lengthFromEntropy(_entropyTarget);
}

/// Return the full character set for testing purposes
String getCharacterSet() {
  // Set up the complete character set
  return _safeLowerCase + _safeUpperCase + _safeDigits;
}

/// Estimate the effective entropy (in bits) associated to a random password of a given length
/// This will round down to be safe; there is a loss of precision associated with this construction anyway
/// NOTE: This is only valid for a random password!
int entropyFromLength(int length) {
  return length*log(getCharacterSet().length) ~/ log(2); // log2([size of character set]^[length of password])
}

/// Estimate the password length required to meet an entropy target (in bits)
/// This will round up to be safe; there is a loss of precision associated with this construction anyway
/// NOTE: This is only valid for a random password!
int lengthFromEntropy(int entropy) {
  return (entropy*log(2) ~/ log(getCharacterSet().length)) + 1;
}

/// Generate a random password of a given length using the hardcoded character set
/// If you leave out the length, a password of 128-bit effective entropy is generated
String generatePassword([int? length]) {
  // Use the default if required
  length ??= getDefaultLength();

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
