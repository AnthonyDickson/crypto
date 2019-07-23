from typing import Optional, Tuple, Union

import numpy as np

from crypto.interfaces import AttackI, Cipher
from crypto.types import Key, CipherText, Message


class CaesarCipher(Cipher):
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


class LetterFrequencyAttack(AttackI):
    """A simple attack that guesses the key used by a Caesar cipher to encrypt
    a given ciphertext using approximate relative letter frequencies found in
    the English language.
    """

    def __init__(self):
        # Column vector of letter frequencies from a-z.
        self.letter_frequencies = np.array([[0.08167],
                                            [0.01492],
                                            [0.02782],
                                            [0.04253],
                                            [0.12702],
                                            [0.02228],
                                            [0.02015],
                                            [0.06094],
                                            [0.06966],
                                            [0.00153],
                                            [0.00772],
                                            [0.04025],
                                            [0.02406],
                                            [0.06749],
                                            [0.07507],
                                            [0.01929],
                                            [0.00095],
                                            [0.05987],
                                            [0.06327],
                                            [0.09056],
                                            [0.02758],
                                            [0.00978],
                                            [0.02360],
                                            [0.00150],
                                            [0.01974],
                                            [0.00074]])

    def from_cipher(self, c: CipherText) -> Tuple[Message, Optional[Key]]:
        # |K| x 26 matrix of letter frequencies
        letter_frequencies = np.zeros(shape=(len(CaesarCipher.KEY_SPACE), 26))

        # Calculate the empirical letter frequencies for the cipher text
        # decrypted with each key in the key space.
        for k in CaesarCipher.KEY_SPACE:
            k = int(k)

            for char in c:
                if not char.isspace():
                    # All characters are uppercase, so treat the first
                    # uppercase letter as zero.
                    char_i = (ord(char) - ord('A') - k) % 26
                    letter_frequencies[k, char_i] += 1

        # Convert absolute frequency counts to relative frequencies.
        letter_frequencies /= len(c)

        # The column of the letter frequencies matrix that maximises the dot
        # product with the reference letter frequencies has most similar
        # distribution to the reference letter frequencies.
        k: int = np.argmax(letter_frequencies.dot(self.letter_frequencies))

        # Reconstruct the original message using the guessed key.
        m: Message = ''

        for char in c:
            if char.isspace():
                m += char
            else:
                m += '%c' % (ord('A') + (ord(char) - ord('A') - k) % 26)

        return m, Key(k)
