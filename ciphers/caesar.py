from typing import Optional, Union

from crypto.interfaces import Key, Message, CipherText, CipherI, KeySpace


class CaesarCipher(CipherI):
    def __init__(self, shift_by=0):
        self._key = Key(shift_by)
        self._key_space = set(Key(k) for k in range(0, 26))

    def get_key(self) -> Key:
        return self._key

    def get_key_space(self) -> KeySpace:
        return self._key_space

    @staticmethod
    def is_valid(x: Union[Message, CipherText]) -> bool:
        """Check if a given message or ciphertext are in a valid format.

        :param x: The message or ciphertext to check.
        :return: True if the message or ciphertext is valid, False otherwise.
        """
        return all((char.isalpha() and char.isupper()) or char.isspace()
                   for char in x)

    def encode(self, m: Message, k: Optional[Key] = None) -> CipherText:
        assert CaesarCipher.is_valid(m), 'Invalid message.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if not k:
            k = int(self.get_key())
        else:
            k = int(k)

        c: CipherText = ''

        for char in m:
            if char.isspace():
                c += char
            else:
                c += '%c' % (ord('A') + (ord(char) - ord('A') + k) % 26)

        return c

    def decode(self, c: CipherText, k: Optional[Key] = None) -> Message:
        assert CaesarCipher.is_valid(c), 'Invalid Ciphertext.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if not k:
            k = int(self.get_key())
        else:
            k = int(k)

        m: Message = ''

        for char in c:
            if char.isspace():
                m += char
            else:
                m += '%c' % (ord('A') + (ord(char) - ord('A') - k) % 26)

        return m
