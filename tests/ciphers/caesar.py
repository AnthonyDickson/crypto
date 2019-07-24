import unittest

from crypto.ciphers.caesar import CaesarCipher, CaesarCipherKey
from crypto.types import KeySpace
from tests.ciphers.cipher_test_case import CipherTestCase


class CaeserCipherTests(CipherTestCase):
    raw_key = 3
    key = CaesarCipherKey(3)

    def test_input_validation(self):
        super(CaeserCipherTests, self).input_validation_test(CaesarCipher)

    def test_keyspace_is_correct(self):
        expected_key_space = KeySpace({CaesarCipherKey(i) for i in range(0, 26)})

        super(CaeserCipherTests, self).keyspace_is_correct_test(CaesarCipherKey, expected_key_space)

    def test_can_set_key(self):
        super(CaeserCipherTests, self).can_set_key_test(CaesarCipher, self.raw_key, self.key)

    def test_generates_valid_ciphertext(self):
        super(CaeserCipherTests, self).generates_valid_ciphertext_test(CaesarCipher, self.key)

    def test_generates_valid_plaintext(self):
        super(CaeserCipherTests, self).generates_valid_plaintext_test(CaesarCipher, self.key)

    def test_identity_key(self):
        super(CaeserCipherTests, self).identity_key_test(CaesarCipher)

    def test_is_symmetric(self):
        super(CaeserCipherTests, self).is_symmetric_test(CaesarCipher, self.key)


if __name__ == '__main__':
    unittest.main()
