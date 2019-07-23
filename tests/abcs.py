import unittest

from crypto.abcs import CipherABC


class TestABCs(unittest.TestCase):
    def test_raises_error_on_init(self):
        """Ensure abstract classes cannot be instantiated..."""
        self.assertRaises(TypeError, CipherABC)


if __name__ == '__main__':
    unittest.main()
