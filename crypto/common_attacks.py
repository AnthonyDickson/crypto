from typing import Type, Tuple, Optional

import enchant
import numpy as np

from crypto.interfaces import BruteForceAttackI, CipherI
from crypto.types import CipherText, Message, Key


class LetterFrequencyAttack(BruteForceAttackI):
    """A simple attack that guesses the key used by a cipher to encrypt
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

    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI]) -> Tuple[Message, Optional[Key]]:
        cipher = cipher_type()

        # |K| x 26 matrix of letter frequencies
        letter_frequencies = np.zeros(shape=(len(cipher.key_space()), 26))

        # Calculate the empirical letter frequencies for the cipher text
        # decrypted with each key in the key space.
        for k in cipher.key_space():
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
        # noinspection PyTypeChecker
        k: int = np.argmax(letter_frequencies.dot(self.letter_frequencies))

        # Reconstruct the original message using the guessed key.
        m: Message = cipher.decrypt(c, Key(k))

        return m, Key(k)


class DictionaryAttack(BruteForceAttackI):
    """A simple attack that guesses the key used by a cipher to encrypt
    a given ciphertext using brute force and a dictionary of the English language.
    """

    def __init__(self):
        self.dict = enchant.Dict('en')

    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI]) -> Tuple[Message, Optional[Key]]:
        cipher = cipher_type()

        ratio_tokens_in_dict = dict()

        for k in cipher.key_space():
            m = cipher.decrypt(c, k)

            # Calculate the ratio of the white-space separated tokens in `m` are actual words.
            n_tokens_in_dict = 0
            tokens = m.split(' ')

            for token in tokens:
                if self.dict.check(token):
                    n_tokens_in_dict += 1

            ratio_tokens_in_dict[k] = n_tokens_in_dict / len(tokens)

        # The key that is most probable is the one that has highest proportion of actual words in it.
        k: Key = max(ratio_tokens_in_dict, key=lambda dict_key: ratio_tokens_in_dict[dict_key])

        # Reconstruct the original message using the guessed key.
        m: Message = cipher.decrypt(c, k)

        return m, k
