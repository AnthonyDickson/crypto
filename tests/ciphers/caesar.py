import unittest

from crypto.ciphers.caesar import CaesarCipher, CaesarCipherKey
from tests.ciphers.cipher_test_case import CipherTestCase


class CaeserCipherTests(CipherTestCase):
    raw_key = 3
    key = CaesarCipherKey(3)

    def test_input_validation(self):
        super(CaeserCipherTests, self).input_validation_test(CaesarCipher)

    def test_keyspace_is_correct(self):
        pass_cases = list(range(0, 26))
        fail_cases = [None, -1, 99, 0.0, 26.0, '', [], dict(), set(),
                      '13', 'abcde', '!#&*(#@']

        super(CaeserCipherTests, self).keyspace_is_correct_test(CaesarCipherKey,
                                                                pass_cases,
                                                                fail_cases)

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
