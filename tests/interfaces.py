import unittest

from crypto.interfaces import AttackI, EncrypterI, DecrypterI


class TestInterfaces(unittest.TestCase):
    def test_raises_error_on_init(self):
        self.assertRaises(NotImplementedError, AttackI().from_cipher, '')
        self.assertRaises(NotImplementedError, EncrypterI().encrypt, '')
        self.assertRaises(NotImplementedError, DecrypterI().decrypt, '')


if __name__ == '__main__':
    unittest.main()
