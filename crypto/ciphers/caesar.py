from typing import Optional, Union

from crypto.abcs import CipherABC
from crypto.types import Key, CipherText, Message


# noinspection PyMissingConstructor
class CaesarCipher(CipherABC):
    KEY_SPACE = set(Key(str(k)) for k in range(0, 26))
    IDENTITY_KEY = 0

    def __init__(self, key: Optional[int] = None):
        if not key:
            self._key = CaesarCipher.IDENTITY_KEY
        else:
            self._key = key

    def key(self) -> Key:
        # The key that is used internally is an integer, but a Key is defined as a string...
        return Key(str(self._key))

    def is_valid(self, x: Union[Message, CipherText]) -> bool:
        return all((char.isalpha() and char.isupper()) or char.isspace()
                   for char in x)

    def encrypt(self, m: Message, k: Optional[Key] = None) -> CipherText:
        assert self.is_valid(m), 'Invalid message.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if not k:
            k = self._key
        else:
            k = int(k)

        c = CipherText('')

        for char in m:
            if char.isspace():
                c += char
            else:
                c += '%c' % (ord('A') + (ord(char) - ord('A') + k) % 26)

        return c

    def decrypt(self, c: CipherText, k: Optional[Key] = None) -> Message:
        assert self.is_valid(c), 'Invalid Ciphertext.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if not k:
            k = self._key
        else:
            k = int(k)

        m = Message('')

        for char in c:
            if char.isspace():
                m += char
            else:
                m += '%c' % (ord('A') + (ord(char) - ord('A') - k) % 26)

        return m
