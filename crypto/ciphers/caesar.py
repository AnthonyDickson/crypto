from typing import Optional, Union

from crypto.abcs import CipherABC
from crypto.types import Key, CipherText, Message


class CaesarCipher(CipherABC):
    KEY_SPACE = set(Key(k) for k in range(0, 26))

    def __init__(self, shift_by=0):
        self._key = Key(shift_by)

    def key(self) -> Key:
        return self._key

    @staticmethod
    def is_valid(x: Union[Message, CipherText]) -> bool:
        """Check if a given message or ciphertext are in a valid format.

        :param x: The message or ciphertext to check.
        :return: True if the message or ciphertext is valid, False otherwise.
        """
        return all((char.isalpha() and char.isupper()) or char.isspace()
                   for char in x)

    def encrypt(self, m: Message, k: Optional[Key] = None) -> CipherText:
        assert CaesarCipher.is_valid(m), 'Invalid message.' \
                                         '\nMessage must be all uppercase letters ' \
                                         'or spaces.'

        if not k:
            k = int(self.key())
        else:
            k = int(k)

        c: CipherText = ''

        for char in m:
            if char.isspace():
                c += char
            else:
                c += '%c' % (ord('A') + (ord(char) - ord('A') + k) % 26)

        return c

    def decrypt(self, c: CipherText, k: Optional[Key] = None) -> Message:
        assert CaesarCipher.is_valid(c), 'Invalid Ciphertext.' \
                                         '\nMessage must be all uppercase letters ' \
                                         'or spaces.'

        if not k:
            k = int(self.key())
        else:
            k = int(k)

        m: Message = ''

        for char in c:
            if char.isspace():
                m += char
            else:
                m += '%c' % (ord('A') + (ord(char) - ord('A') - k) % 26)

        return m


