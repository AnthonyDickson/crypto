import unittest

from crypto.ciphers import VigenereCipher, VigenereCipherKey
from crypto.ciphers.caesar import CaesarCipher, CaesarCipherKey
from crypto.types import KeySpace
from tests.ciphers.cipher_test_case import CipherTestCase


class VigenereCipherTests(CipherTestCase):
    raw_key = 'OTAGO'
    key = VigenereCipherKey('OTAGO')

    def test_input_validation(self):
        super(VigenereCipherTests, self).input_validation_test(VigenereCipher)

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
