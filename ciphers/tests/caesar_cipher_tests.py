import unittest

from ciphers.caesar import CaesarCipher
from crypto.interfaces import Key


class CaeserCipherTests(unittest.TestCase):

    def test_input_validation(self):
        m = 'Invalid message 1234567890!@#$%^&*()'

        cc = CaesarCipher()

        self.assertRaises(AssertionError, cc.encode, m, Key(0))

    def test_generates_valid_ciphertext(self):
        cc = CaesarCipher()

        k = Key(3)
        m = 'HELLO WORLD'

        c = cc.encode(m, k)

        self.assertTrue(CaesarCipher.is_valid(c), '\'%s\' is not a valid ciphertext!' % c)

    def test_generates_valid_plaintext(self):
        cc = CaesarCipher()

        k = Key(3)
        c = 'HELLO WORLD'

        m = cc.decode(c, k)

        self.assertTrue(CaesarCipher.is_valid(m), '\'%s\' is not valid plaintext!' % c)

    def test_zero_shift(self):
        """Ensure that using a shift of zero results in the same message and
        ciphertext.
        """
        k = Key(0)
        m = 'HELLO WORLD'

        cc = CaesarCipher()
        E = cc.encode

        self.assertEqual(m, E(m, k)) # shift amount is zero so there should be no change

    def test_is_symmetric(self):
        """Ensure that decoding the cipher text with the same key that it was
        encoded with produces the original message.
        """
        m = 'HELLO WORLD'

        cc = CaesarCipher()
        E = cc.encode
        D = cc.decode

        for k in cc.K:
            self.assertEqual(m, D(E(m, k), k))


if __name__ == '__main__':
    unittest.main()
