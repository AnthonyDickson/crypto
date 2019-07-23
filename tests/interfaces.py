import unittest

from crypto.interfaces import AttackI, BruteForceAttackI, CipherI, DecrypterI, EncrypterI


class TestInterfaces(unittest.TestCase):
    def test_raises_error_on_init(self):
        self.assertRaises(TypeError, AttackI)
        self.assertRaises(TypeError, BruteForceAttackI)
        self.assertRaises(TypeError, CipherI)
        self.assertRaises(TypeError, DecrypterI)
        self.assertRaises(TypeError, EncrypterI)


if __name__ == '__main__':
    unittest.main()
