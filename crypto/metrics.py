from collections import Counter
from datetime import datetime
from statistics import mean
from string import ascii_uppercase
from typing import Iterable, Union, Type

import enchant
import numpy as np

from crypto.interfaces import BruteForceAttackI, CipherI, KeyI
from crypto.types import Message, CipherText


def cosine_similarity(a: Iterable[Union[float, int]], b: Iterable[Union[float, int]]) -> float:
    """Calculate the cosine similarity between two vectors.

    :param a: A vector.
    :param b: A vector.
    :return: The cosine similarity between the vectors `a` and `b` in the range [0.0, 1.0].
    """
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


def letter_distribution(m: Message) -> np.ndarray:
    """Calculate the frequency distribution of the letters in a message.

    :param m: The message to process.
    :return: The calculated frequency distribution of letters in the message `m` as a vector.
    """
    dist = Counter(m)

    dist_vec = np.zeros(26)  # 26 is the number of letters in the alphabet

    for i, char in enumerate(ascii_uppercase):
        dist_vec[i] = dist[char]

    return dist_vec


def ratio_tokens_in_dict(m: Message, language: str = 'en') -> float:
    """Calculate the ratio of tokens in a message that are found in a dictionary.

    :param m: The message to process.
    :param language: The language of the dictionary to use (See https://abiword.github.io/enchant/ for details on the
                     dictionary.)
    :return: The ratio of tokens in the message that are in a dictionary in the range [0.0, 1.0].
    """
    en_dict = enchant.Dict(language)
    n_in_dictionary = 0
    tokens = m.split()

    for token in tokens:
        if en_dict.check(token):
            n_in_dictionary += 1

    return n_in_dictionary / len(tokens)


def positional_similarity(message, other_message) -> float:
    """Calculate a measure of how similar two messages are based on how many characters at each position in the
    pairs of messages are the same.

    :param message: The first message to compare.
    :param other_message: The other message to compare.
    :return: A ratio in the range [0.0, 1.0] relating to the ratio of matching characters taking into account position.
    """
    return sum(1 if c1 == c2 else 0 for c1, c2 in zip(message, other_message)) / len(message)


def distributional_similarity(message, other_message) -> float:
    """Calculate how similar the letter frequency distributions of two messages are.

    :param message: The first message to compare.
    :param other_message: The other message to compare.
    :return: A ratio in the range [0.0, 1.0] denoting how simliar the letter frequency distributions are.
    """
    return cosine_similarity(letter_distribution(message), letter_distribution(other_message))


def aggregate_score(message, other_message) -> float:
    """Calculate an aggregate score comparing the similarity of two messages.

    This uses the following metrics:
    - distributional_similarity
    - positional_similarity
    - ratio_tokens_in_dict.

    :param message: The first message to compare.
    :param other_message: The other message to compare.
    :return: A score in the range [0.0, 1.0] where 0.0 indicates the messages are completely different, and 1.0
             indicates the messages are exactly the same.
    """
    return mean([distributional_similarity(message, other_message), positional_similarity(message, other_message),
                 ratio_tokens_in_dict(message, other_message)])


def print_attack_summary(attack: BruteForceAttackI, message: Message, ciphertext: CipherText,
                         cipher_type: Type[CipherI], key_type: Type[KeyI]):
    """Perform an attack on a given ciphertext and print a summary of how well the attacker did.

    :param attack: The attack to perform.
    :param ciphertext: The ciphertext the attack should use to try recover the original plaintext.
    :param message: The original plaintext messasge that the attacker is trying to recover.
    :param cipher_type: The type of cipher that was used to generate the ciphertext.
    :param key_type: The type of key that was used to generate the ciphertext.
    """
    start = datetime.now()

    estimated_message, estimated_key = attack.from_cipher(ciphertext, cipher_type, key_type)

    delta = datetime.now() - start
    exact_match = estimated_message == message
    pos_similarity = positional_similarity(message, estimated_message)
    dist_similarity = distributional_similarity(message, estimated_message)
    sensibility = ratio_tokens_in_dict(estimated_message)

    print('\n%s Solution:'
          '\n\tElapsed Time: %s'
          '\n\tMessage: %s'
          '\n\tKey: %s'
          '\n\tExact Match: %s'
          '\n\tLetter Position Similarity: %.2f'
          '\n\tLetter Distribution Similarity: %.2f'
          '\n\tRatio of Tokens in Dictionary: %.2f' % (attack.__class__.__name__,
                                                       str(delta),
                                                       estimated_message,
                                                       estimated_key,
                                                       str(exact_match),
                                                       pos_similarity,
                                                       dist_similarity,
                                                       sensibility))
