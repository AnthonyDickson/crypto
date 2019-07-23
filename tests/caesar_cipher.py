import unittest

from crypto.ciphers.caesar import CaesarCipher
from crypto.types import Key


class CaeserCipherTests(unittest.TestCase):

    def test_input_validation(self):
        m = 'Invalid message 1234567890!@#$%^&*()'

        cc = CaesarCipher()

        try:
            cc.encrypt(m, Key(0))
        except AssertionError:
            # AssertionError correctly raised for invalid input, all good!
            return

        self.fail('Encrypt method should throw an error for incorrectly formatted input.')

    def test_keyspace_is_correct(self):
        expected = set(Key(k) for k in range(26))
        actual = CaesarCipher.KEY_SPACE

        self.assertSetEqual(expected, actual,
                            msg='The key space for CaesarCipher is incorrect.')

    def test_generates_valid_ciphertext(self):
        cc = CaesarCipher()

        k = Key(3)
        m = 'HELLO WORLD'

        c = cc.encrypt(m, k)

        self.assertTrue(CaesarCipher.is_valid(c), '\'%s\' is not a valid ciphertext!' % c)

    def test_generates_valid_plaintext(self):
        cc = CaesarCipher()

        k = Key(3)
        c = 'HELLO WORLD'

        m = cc.decrypt(c, k)

        self.assertTrue(CaesarCipher.is_valid(m), '\'%s\' is not valid plaintext!' % c)

    def test_zero_shift(self):
        """Ensure that using a shift of zero results in the same message and
        ciphertext.
        """
        k = Key(0)
        m = 'HELLO WORLD'

        cc = CaesarCipher()
        E = cc.encrypt

        self.assertEqual(E(m, k), m,
                         msg='Encrypting a message with a shift of zero should produce the original message!')

    def test_is_symmetric(self):
        """Ensure that decrypting the cipher text with the same key that it was
        encrypted with produces the original message.
        """
        m = 'HELLO WORLD'

        cc = CaesarCipher()
        E = cc.encrypt
        D = cc.decrypt

        for k in cc.key_space():
            self.assertEqual(D(E(m, k), k), m, msg='The cipher is not symmetric for the key \'%s\'!' % k)


if __name__ == '__main__':
    unittest.main()
