from collections import Counter
from string import ascii_uppercase
from typing import Type, Tuple, Optional

import enchant
import numpy as np

from crypto.abcs import KeyABC
from crypto.interfaces import BruteForceAttackI, CipherI, KeyI
from crypto.types import CipherText, Message


class LetterFrequencyAttack(BruteForceAttackI):
    """A simple attack that guesses the key used by a cipher to encrypt
    a given ciphertext using approximate relative letter frequencies found in
    the English language.
    """

    # noinspection PyMissingConstructor
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

    # TODO: Implement some sort of random guessing alternative for ciphers with large key spaces
    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI],
                    key_type: Type[KeyI]) -> Tuple[Message, Optional[KeyI]]:
        cipher = cipher_type()
        best_dot_prod = -1
        the_message = None
        the_key = None

        # Calculate the empirical letter frequencies for the cipher text
        # decrypted with each key in the key space.
        for k in key_type.get_space():
            m = cipher.decrypt(c, k)
            letter_frequency_counts = Counter(m)
            letter_frequency_counts_vec = np.array([letter_frequency_counts[key]
                                                    for key in ascii_uppercase])

            dot_prod = letter_frequency_counts_vec.dot(self.letter_frequencies)

            if dot_prod > best_dot_prod:
                best_dot_prod = dot_prod
                the_message = m
                the_key = k

        return the_message, the_key


class DictionaryAttack(BruteForceAttackI):
    """A simple attack that guesses the key used by a cipher to encrypt
    a given ciphertext using brute force and a dictionary of the English language.
    """

    # noinspection PyMissingConstructor
    def __init__(self):
        self.dict = enchant.Dict('en')

    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI],
                    key_type: Type[KeyI]) -> Tuple[Message, Optional[KeyI]]:
        cipher = cipher_type()

        ratio_tokens_in_dict = dict()

        for k in key_type.get_space():
            m = cipher.decrypt(c, k)

            # Calculate the ratio of the white-space separated tokens in `m` are actual words.
            n_tokens_in_dict = 0
            tokens = m.split(' ')

            for token in tokens:
                if self.dict.check(token):
                    n_tokens_in_dict += 1

            ratio_tokens_in_dict[k] = n_tokens_in_dict / len(tokens)

        # The key that is most probable is the one that has highest proportion of actual words in it.
        k: KeyABC = max(ratio_tokens_in_dict, key=lambda dict_key: ratio_tokens_in_dict[dict_key])

        # Reconstruct the original message using the guessed key.
        m: Message = cipher.decrypt(c, k)

        return m, k
