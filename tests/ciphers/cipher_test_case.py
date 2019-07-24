import unittest
from typing import Type, Any, Callable, Union, Optional

from crypto.abcs import CipherABC
from crypto.interfaces import KeyI
from crypto.types import Message, KeySpace, CipherText


# noinspection PyPep8Naming
class CipherTestCase(unittest.TestCase):
    """Defines some common tests for ciphers."""

    def input_validation_test(self, cipher_type: Type[CipherABC],
                              invalid_msg: str = 'InVaLiD mEsSaGe 1234567890 !@#$%^&*()'):
        """Encrypt and decrypt methods should throw an error for incorrectly formatted input.

        :param cipher_type: The type of cipher to test.
        :param invalid_msg: A message that should be considered invalid by the given cipher type.
        """
        m = Message(invalid_msg)

        cipher = cipher_type()

        self.assertRaises(AssertionError, cipher.encrypt, m)
        self.assertRaises(AssertionError, cipher.decrypt, m)

    def keyspace_is_correct_test(self, key_type: Type[KeyI], expected_key_space: Union[KeySpace, Callable]):
        """Ensure that the key space for a cipher is correct.

        :param key_type: The type of key the cipher uses.
        :param expected_key_space: The expected key space or a generator that generates the key space.
        """
        self.assertSetEqual(expected_key_space if type(expected_key_space) is set else set(expected_key_space()),
                            set(key_type.get_space()),
                            msg='The key space for CaesarCipher is incorrect.')

    def can_set_key_test(self, cipher_type: Type[CipherABC], raw_key: Any, expected_key: KeyI):
        """Ensure that the key for a cipher can be set correctly.

        :param cipher_type: The type of cipher to test.
        :param raw_key: The key to initialise the cipher with.
        :param expected_key: The key that should be given by the cipher's `key()` function.
        """
        cipher = cipher_type(raw_key)
        actual_key = cipher.key

        self.assertEqual(expected_key, actual_key, 'Key is not the same as the one it was set to!\n'
                                                   'Expected \'%s\', but instead got \'%s\'' %
                         (expected_key, actual_key))

    def generates_valid_ciphertext_test(self, cipher_type: Type[CipherABC], key: Optional[KeyI] = None):
        """Ensure that the cipher generates valid ciphertext.

        :param cipher_type: The type of cipher to test.
        :param key: The key to use.
        """
        m = Message('HELLO WORLD')

        cipher = cipher_type()
        c = cipher.encrypt(m, key)

        self.assertTrue(cipher.is_valid(c), '\'%s\' is not a valid ciphertext!' % c)

    def generates_valid_plaintext_test(self, cipher_type: Type[CipherABC], key: Optional[KeyI] = None):
        """Ensure that the cipher generates valid messages.

        :param cipher_type: The type of cipher to test.
        :param key: The key to use.
        :return:
        """
        c = CipherText('HELLO WORLD')

        cipher = cipher_type()
        m = cipher.decrypt(c, key)

        self.assertTrue(cipher.is_valid(m), '\'%s\' is not valid plaintext!' % c)

    def identity_key_test(self, cipher_type: Type[CipherABC]):
        """Ensure that using the identity key results in the same message and
        ciphertext.

        :param cipher_type:
        """
        # Ciphers use their identity key if no key is specified.
        cipher = cipher_type()
        E = cipher.encrypt
        m = Message('HELLO WORLD')

        self.assertEqual(E(m), m,
                         msg='Encrypting a message with a shift of zero should produce the original message!')

    def is_symmetric_test(self, cipher_type: Type[CipherABC], key: Optional[KeyI] = None):
        """Ensure that decrypting the cipher text with the same key that it was
        encrypted with produces the original message.

        :param cipher_type:
        :param key: The key to use.
        """
        m = Message('HELLO WORLD')

        cipher = cipher_type()
        E = cipher.encrypt
        D = cipher.decrypt

        self.assertEqual(D(E(m, key), key), m, msg='The cipher is not symmetric for the key \'%s\'!' % key)
