import unittest
from string import ascii_uppercase

from crypto.ciphers import VigenereCipher, VigenereCipherKey
from tests.ciphers.cipher_test_case import CipherTestCase


class VigenereCipherTests(CipherTestCase):
    raw_key = 'OTAGO'
    key = VigenereCipherKey('OTAGO')

    def test_input_validation(self):
        super(VigenereCipherTests, self).input_validation_test(VigenereCipher)

    def test_keyspace_is_correct(self):
        pass_cases = [
            ascii_uppercase,
            'A',  # I mean it's valid, but not a very secure key...
            'THECATSATONTHEMAT'
        ]

        fail_cases = [
            '',  # empty string
            'THE CAT DID NOT SIT ON THE MAT',  # contains spaces
            'BAD CAT.',  # contains punctuation
            '3 BAD CaTs.',  # contains numbers
            None,
            dict(),
            42.0,
            42,
            'this is deFinitely not a valid key',
            'n0r i5 th15 ##!!#(&814',
            set(),
            set(ascii_uppercase)
        ]

        super(VigenereCipherTests, self) \
            .keyspace_is_correct_test(VigenereCipherKey, pass_cases, fail_cases)

    def test_can_set_key(self):
        super(VigenereCipherTests, self).can_set_key_test(VigenereCipher, self.raw_key, self.key)

    def test_generates_valid_ciphertext(self):
        super(VigenereCipherTests, self).generates_valid_ciphertext_test(VigenereCipher, self.key)

    def test_generates_valid_plaintext(self):
        super(VigenereCipherTests, self).generates_valid_plaintext_test(VigenereCipher, self.key)

    def test_identity_key(self):
        super(VigenereCipherTests, self).identity_key_test(VigenereCipher)

    def test_is_symmetric(self):
        super(VigenereCipherTests, self).is_symmetric_test(VigenereCipher, self.key)


if __name__ == '__main__':
    unittest.main()
