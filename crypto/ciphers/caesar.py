from random import SystemRandom
from typing import Optional, Union

from crypto.abcs import CipherABC, KeyABC
from crypto.types import CipherText, Message


class CaesarCipherKey(KeyABC):
    """A key used in the Caesar cipher.
    This is defined as an integer in the range [0, 25].
    A key of zero results in no effect, i.e. if k = 0 then E(m, k) = c = D(c, k) = m.
    """

    def __init__(self, value: int):
        """Create a Caesar cipher key.

        :param value: The value of the key to use. This value is set to itself modulo 26.
        """
        super().__init__(value)

    def __len__(self):
        return 1  # A key is just a single integer.

    def __eq__(self, other: Union['CaesarCipherKey', int]):
        if isinstance(other, CaesarCipherKey):
            return self.value == other.value
        else:
            return self.value == other

    __hash__ = KeyABC.__hash__

    @staticmethod
    def key_space_contains(k: int) -> bool:
        return type(k) is int and k in range(0, 26)

    @staticmethod
    def get_identity():
        return CaesarCipherKey(0)

    @staticmethod
    def generate_random():
        r = SystemRandom()

        return CaesarCipherKey(r.randrange(0, 26))

    @staticmethod
    def get_space():
        for i in range(0, 26):
            yield CaesarCipherKey(i)

    @staticmethod
    def get_space_size():
        return 26


# noinspection PyMissingConstructor
class CaesarCipher(CipherABC):
    def __init__(self, key: Optional[CaesarCipherKey] = None):
        if not key:
            self._key = CaesarCipherKey.get_identity()
        else:
            self._key = key

    @property
    def key(self) -> CaesarCipherKey:
        return self._key

    @staticmethod
    def is_valid(x: Union[Message, CipherText]) -> bool:
        return all((char.isalpha() and char.isupper()) or char.isspace()
                   for char in x)

    def encrypt(self, m: Message, k: Optional[CaesarCipherKey] = None) -> CipherText:
        assert self.is_valid(m), 'Invalid message.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if k:
            k = k.value
        else:
            k = self.key.value

        c = CipherText('')

        for char in m:
            if char.isspace():
                c += char
            else:
                c += '%c' % (ord('A') + (ord(char) - ord('A') + k) % 26)

        return c

    def decrypt(self, c: CipherText, k: Optional[CaesarCipherKey] = None) -> Message:
        assert self.is_valid(c), 'Invalid Ciphertext.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if k:
            k = k.value
        else:
            k = self.key.value

        m = Message('')

        for char in c:
            if char.isspace():
                m += char
            else:
                m += '%c' % (ord('A') + (ord(char) - ord('A') - k) % 26)

        return m
