from collections import Counter
from string import ascii_uppercase
from typing import Type, Tuple, Optional

import enchant
import numpy as np

from crypto.abcs import BruteForceAttackABC
from crypto.interfaces import CipherI, KeyI, SamplingStrategyI
from crypto.metrics import cosine_similarity, ratio_tokens_in_dict
from crypto.types import CipherText, Message


class LetterFrequencyAttack(BruteForceAttackABC):
    """A simple attack that guesses the key used by a cipher to encrypt
    a given ciphertext using approximate relative letter frequencies found in
    the English language.
    """

    def __init__(self, sampling_strategy: SamplingStrategyI):
        super().__init__(sampling_strategy)

        # Vector of letter frequencies from a-z.
        self.letter_frequencies = np.array([0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
                                            0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                                            0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                                            0.00978, 0.02360, 0.00150, 0.01974, 0.00074])

    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI],
                    key_type: Type[KeyI]) -> Tuple[Message, Optional[KeyI]]:
        cipher = cipher_type()
        best_score = -1
        the_message = None
        the_key = None

        # Calculate the empirical letter frequencies for the cipher text
        # decrypted with each key in the key space.
        for k in self.sampling_strategy.sample(key_type):
            m = cipher.decrypt(c, k)
            letter_dist = Counter(m)
            letter_dist_vec = np.array([letter_dist[key] for key in ascii_uppercase])

            score = cosine_similarity(self.letter_frequencies, letter_dist_vec)

            if score > best_score:
                best_score = score
                the_message = m
                the_key = k

            if best_score > 0.99:
                break

        return the_message, the_key


class DictionaryAttack(BruteForceAttackABC):
    """A simple attack that guesses the key used by a cipher to encrypt
    a given ciphertext using brute force and a dictionary of the English language.
    """

    def __init__(self, sampling_strategy: SamplingStrategyI):
        super().__init__(sampling_strategy)

        self.dict = enchant.Dict('en')

    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI],
                    key_type: Type[KeyI]) -> Tuple[Message, Optional[KeyI]]:
        cipher = cipher_type()

        best_score = -1
        the_message = None
        the_key = None

        for k in self.sampling_strategy.sample(key_type):
            m = cipher.decrypt(c, k)

            score = ratio_tokens_in_dict(m)

            if score > best_score:
                best_score = score
                the_message = m
                the_key = k

            if best_score > 0.99:
                break

        return the_message, the_key


class LanguageAnalysisAttack(BruteForceAttackABC):
    """A simple attack that combines the approaches of `LetterFrequencyAttack` and `DictionaryAttack`."""

    def __init__(self, sampling_strategy: SamplingStrategyI):
        super().__init__(sampling_strategy)

        self.dict = enchant.Dict('en')

        # Vector of letter frequencies from a-z.
        self.letter_frequencies = np.array([0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
                                            0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                                            0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                                            0.00978, 0.02360, 0.00150, 0.01974, 0.00074])

    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI],
                    key_type: Type[KeyI]) -> Tuple[Message, Optional[KeyI]]:
        cipher = cipher_type()

        best_score = -1
        the_message = None
        the_key = None

        for k in self.sampling_strategy.sample(key_type):
            m = cipher.decrypt(c, k)

            letter_dist = Counter(m)
            letter_dist_vec = np.array([letter_dist[key] for key in ascii_uppercase])

            score = cosine_similarity(self.letter_frequencies, letter_dist_vec) + ratio_tokens_in_dict(m)
            score *= 0.5

            if score > best_score:
                best_score = score
                the_message = m
                the_key = k

            if best_score > 0.99:
                break

        return the_message, the_key
