from typing import Iterable, Union

import numpy as np
import plac

from crypto.ciphers.caesar import CaesarCipher, LetterFrequencyAttack
from crypto.interfaces import AttackI
from crypto.types import Key, CipherText, Message


# TODO: refactor generalisable summary stuff to own package/file

def cosine_similarity(a: Iterable[Union[float, int]], b: Iterable[Union[float, int]]) -> float:
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


def letter_distribution(m: str) -> Iterable[float]:
    dist = np.zeros(shape=(26,))

    for char in m:
        if not char.isspace():
            char_i = ord(char) - ord('A')  # Treat 'A' as zero
            dist[char_i] += 1

    return dist


def print_attack_summary(attack: AttackI, ciphertext: CipherText, message: Message):
    estimated_message, estimated_key = attack.from_cipher(ciphertext)
    exact_match = estimated_message == message
    pos_similarity = sum(1 if c1 == c2 else 0 for c1, c2 in zip(message, estimated_message)) / len(message)
    dist_similarity = cosine_similarity(letter_distribution(message),
                                        letter_distribution(estimated_message))

    print('Cipher-Only Attack Solution:'
          '\n\tMessage: %s'
          '\n\tKey: %s'
          '\n\tExact Match: %s'
          '\n\tLetter Position Similarity: %.2f'
          '\n\tLetter Distribution Similarity: %.2f' % (estimated_message,
                                                        estimated_key,
                                                        str(exact_match),
                                                        pos_similarity,
                                                        dist_similarity))


@plac.annotations(
    key=plac.Annotation("The key to use for the caesar cipher. This is typically an integer in the range [0, 25].",
                        type=int),
)
def main(key=1):
    """A demonstration of the Caesar cipher."""
    cc = CaesarCipher()
    key = Key(key)
    message = input('Enter a message to encrypt: ')
    ciphertext = cc.encrypt(message, key)

    while not CaesarCipher.is_valid(message):
        print('Invalid message format.\n'
              'Messages must be a string of all uppercase letters and spaces.')
        message = input('Enter a message to encrypt: ')

    print('\nMessage: %s' % message)
    print('Key: %s' % key)
    print('Ciphertext: %s' % ciphertext)
    print()

    attacker = LetterFrequencyAttack()
    print_attack_summary(attacker, ciphertext, message)


if __name__ == '__main__':
    plac.call(main)
