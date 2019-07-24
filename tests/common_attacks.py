import unittest

from crypto.ciphers.caesar import CaesarCipher, CaesarCipherKey
from crypto.common_attacks import LetterFrequencyAttack, DictionaryAttack
from crypto.types import Message


class TestCommonAttacks(unittest.TestCase):
    def test_letter_frequency_attack_generates_valid_output(self):
        m = Message('HELLO WORLD')
        k = CaesarCipherKey(5)

        cipher = CaesarCipher()
        c = cipher.encrypt(m, k)

        attack = LetterFrequencyAttack()
        message, key = attack.from_cipher(c, CaesarCipher, CaesarCipherKey)

        self.assertIn(key, CaesarCipherKey.get_space(), 'Attack method generated an invalid key \'%s\'.' % key)
        self.assertTrue(cipher.is_valid(message), 'Attack method generated an invalid message \'%s\'' % message)

    def test_dictionary_attack_generates_valid_output(self):
        m = Message('HELLO WORLD')
        k = CaesarCipherKey(5)

        cipher = CaesarCipher()
        c = cipher.encrypt(m, k)

        attack = DictionaryAttack()
        message, key = attack.from_cipher(c, CaesarCipher, CaesarCipherKey)

        self.assertIn(key, CaesarCipherKey.get_space(), 'Attack method generated an invalid key \'%s\'.' % key)
        self.assertTrue(cipher.is_valid(message), 'Attack method generated an invalid message \'%s\'' % message)


if __name__ == '__main__':
    unittest.main()
