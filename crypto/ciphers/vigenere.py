import itertools
from random import SystemRandom
from string import ascii_uppercase
from typing import Optional, Union, Generator

from crypto.abcs import CipherABC, KeyABC
from crypto.types import CipherText, Message


class VigenereCipherKey(KeyABC):
    def __init__(self, value: str):
        super().__init__(value)

    @staticmethod
    def key_space_contains(k: str) -> bool:
        # Any length string that consists of uppercase letter
        return k and type(k) is str and set(k).issubset(set(ascii_uppercase))

    @staticmethod
    def get_identity() -> 'VigenereCipherKey':
        return VigenereCipherKey('A')

    @staticmethod
    def generate_random(max_length=20) -> 'VigenereCipherKey':
        """Generate a random key.
        For the Vigenere cipher only keys up to a given length are generated.

        :param max_length: The longest key to generate.
        :return: A randomly generated key.
        """
        r = SystemRandom()
        return r.choices(list(ascii_uppercase), k=r.randint(1, max_length))

    @staticmethod
    def get_space(max_length=20) -> Generator['VigenereCipherKey', None, None]:
        """Get the key space, or the set of all valid keys.
        For the Vigenere cipher this is defined up to a maximum key length.

        :param max_length: The longest key to consider.
        :return: A generator that yields a sequence of valid keys.
        """
        for r in range(max_length):
            for permutation in itertools.permutations(ascii_uppercase, r):
                yield VigenereCipherKey(''.join(permutation))

    @staticmethod
    def get_space_size(max_length=20) -> int:
        """Get the number of elements in the key space.
        For the Vigenere cipher this is defined up to a maximum key length.

        :param max_length: The longest key to consider.
        :return: The size of the key space.
        """
        return 26 ** max_length  # 26 is the number of letters in the alphabet


# noinspection PyMissingConstructor
class VigenereCipher(CipherABC):
    """The Vigenere cipher where a string of a certain length is used to
    encrypt messages.
    """

    def __init__(self, key: Optional[VigenereCipherKey] = None):
        """Create a substitution cipher

        :param key: A dictionary encoding letter (uppercase alphabet) to letter mappings.
        """
        if key:
            self._key = key
        else:
            self._key = VigenereCipherKey.get_identity()

    @property
    def key(self) -> VigenereCipherKey:
        return self._key

    @staticmethod
    def is_valid(x: Union[Message, CipherText]) -> bool:
        """Check if a given message or ciphertext are in a valid format.

        :param x: The message or ciphertext to check.
        :return: True if the message or ciphertext is valid, False otherwise.
        """
        return all((char.isalpha() and char.isupper()) or char.isspace()
                   for char in x)

    def encrypt(self, m: Message, k: Optional[VigenereCipherKey] = None) -> CipherText:
        assert self.is_valid(m), 'Invalid message.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if k:
            k = k.value
        else:
            k = self.key.value

        c = CipherText('')
        i = 0

        for char in m:
            if char.isspace():
                c += char
            else:
                c += chr(ord('A') + (ord(char) + ord(k[i % len(k)])) % 26)
                i += 1

        return c

    def decrypt(self, c: CipherText, k: Optional[VigenereCipherKey] = None) -> Message:
        assert self.is_valid(c), 'Invalid ciphertext.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if k:
            k = k.value
        else:
            k = self.key.value

        m = Message('')
        i = 0

        for char in c:
            if char.isspace():
                m += char
            else:
                m += chr(ord('A') + (ord(char) - ord(k[i % len(k)])) % 26)
                i += 1

        return m
