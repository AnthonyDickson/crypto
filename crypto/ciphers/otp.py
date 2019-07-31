import random
from typing import Optional, Generator

from crypto.abcs import CipherABC, KeyABC
from crypto.ciphers.utils import is_valid
from crypto.types import CipherText, Message


class OneTimePadCipherKey(KeyABC):
    def __init__(self, value: int):
        super().__init__(value)

    @staticmethod
    def key_space_contains(k: int) -> bool:
        return type(k) is int  # all integers, and by extension bit strings are valid keys.

    @staticmethod
    def get_identity() -> 'OneTimePadCipherKey':
        return OneTimePadCipherKey(0)

    @staticmethod
    def generate_random(length=64) -> 'OneTimePadCipherKey':
        return OneTimePadCipherKey(random.getrandbits(length))

    @staticmethod
    def get_space(length=64) -> Generator['OneTimePadCipherKey', None, None]:
        for n in range(2 ** length):
            yield OneTimePadCipherKey(n)

    @staticmethod
    def get_space_size(length=64) -> int:
        return 2 ** length - 1


# noinspection PyMissingConstructor
class OneTimePadCipher(CipherABC):
    """The one time pad cipher where a bit string is used to encrypt messages."""

    def __init__(self, key: Optional[OneTimePadCipherKey] = None):
        """Create a substitution cipher

        :param key: A dictionary encoding letter (uppercase alphabet) to letter mappings.
        """
        if key:
            self._key = key
        else:
            self._key = OneTimePadCipherKey.get_identity()

    @property
    def key(self) -> OneTimePadCipherKey:
        return self._key

    def encrypt(self, m: Message, k: Optional[OneTimePadCipherKey] = None) -> CipherText:
        assert is_valid(m), 'Invalid message.' \
                            '\nMessage must be all uppercase letters ' \
                            'or spaces.'

        if k:
            k = k.value
        else:
            bits_in_m = 8 * len(m)
            k = OneTimePadCipherKey.generate_random(bits_in_m).value

        # Convert message to bit string
        m_bit_string = 0

        for char in m:
            m_bit_string = m_bit_string << 8  # shift left by a byte for ASCII chars
            m_bit_string += ord(char)

        c_bit_string = m_bit_string ^ k

        # Convert bit string to string
        c = CipherText('')

        for _ in range(len(m)):
            c = chr(c_bit_string & 0xff) + c  # grab lowest byte of the bit string
            c_bit_string = c_bit_string >> 8  # drop lowest byte

        return c

    def decrypt(self, c: CipherText, k: Optional[OneTimePadCipherKey] = None) -> Message:
        assert is_valid(c), 'Invalid ciphertext.' \
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
                m += '%c' % (ord('A') + (ord(char) - ord(k[i % len(k)])) % 26)
                i += 1

        return m
