from typing import Iterable, Union, Type, Optional

import enchant
import numpy as np
import plac

from crypto.ciphers.caesar import CaesarCipher, CaesarCipherKey
from crypto.common_attacks import LetterFrequencyAttack, DictionaryAttack
from crypto.interfaces import CipherI, BruteForceAttackI, KeyI
from crypto.types import CipherText, Message


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


def num_tokens_in_dict(m: Message) -> float:
    en_dict = enchant.Dict('en')
    n_in_dictionary = 0
    tokens = m.split(' ')

    for token in tokens:
        if en_dict.check(token):
            n_in_dictionary += 1

    return n_in_dictionary / len(tokens)


def print_attack_summary(attack: BruteForceAttackI, ciphertext: CipherText, message: Message,
                         cipher_type: Type[CipherI], key_type: Type[KeyI]):
    estimated_message, estimated_key = attack.from_cipher(ciphertext, cipher_type, key_type)
    exact_match = estimated_message == message
    pos_similarity = sum(1 if c1 == c2 else 0 for c1, c2 in zip(message, estimated_message)) / len(message)
    dist_similarity = cosine_similarity(letter_distribution(message),
                                        letter_distribution(estimated_message))
    sensibility = num_tokens_in_dict(estimated_message)

    print('\n%s Solution:'
          '\n\tMessage: %s'
          '\n\tKey: %s'
          '\n\tExact Match: %s'
          '\n\tLetter Position Similarity: %.2f'
          '\n\tLetter Distribution Similarity: %.2f'
          '\n\tRatio of Tokens in Dictionary: %.2f' % (attack.__class__.__name__,
                                                       estimated_message,
                                                       estimated_key,
                                                       str(exact_match),
                                                       pos_similarity,
                                                       dist_similarity,
                                                       sensibility))


@plac.annotations(
    key=plac.Annotation("The key to use for the caesar cipher. This is typically an integer in the range [0, 25].",
                        type=int),
    filename=plac.Annotation('The name of a file to use as the message.', kind='option', type=str, abbrev='f')
)
def main(key=1, filename: Optional[str] = None) -> int:
    """A demonstration of the Caesar cipher."""
    cc = CaesarCipher()
    key = CaesarCipherKey(key)

    if filename:
        with open(filename, 'r') as f:
            message = Message(f.read())
    else:
        message = Message(input('Enter a message to encrypt: '))

    ciphertext = cc.encrypt(message, key)

    while not CaesarCipher.is_valid(message):
        print('Invalid message format.\n'
              'Messages must be a string of all uppercase letters and spaces.')
        message = input('Enter a message to encrypt: ')

    print('\nMessage: %s' % message)
    print('Key: %s' % key)
    print('Ciphertext: %s' % ciphertext)

    attacker = LetterFrequencyAttack()
    print_attack_summary(attacker, ciphertext, message, CaesarCipher, CaesarCipherKey)

    attacker2 = DictionaryAttack()
    print_attack_summary(attacker2, ciphertext, message, CaesarCipher, CaesarCipherKey)

    return 0


if __name__ == '__main__':
    plac.call(main)
