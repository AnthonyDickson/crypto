from typing import Optional

import plac

from crypto.ciphers.caesar import CaesarCipher, CaesarCipherKey
from crypto.ciphers.utils import is_valid
from crypto.common_attacks import LetterFrequencyAttack, DictionaryAttack, LanguageAnalysisAttack
from crypto.metrics import print_attack_summary
from crypto.strategies import ExhaustiveSampling
from crypto.types import Message


@plac.annotations(
    key=plac.Annotation("The key to use for the caesar cipher. This is typically an integer in the range [0, 25]."
                        "If not specified then a key is chosen at random.", kind='option', type=int),
    filename=plac.Annotation('The name of a file to use as the message.', kind='option', type=str, abbrev='f')
)
def main(key: Optional[int] = None, filename: Optional[str] = None) -> int:
    """A demonstration of the Caesar cipher."""

    if filename:
        with open(filename, 'r') as f:
            message = Message(f.read())
    else:
        message = Message(input('Enter a message to encrypt: '))

    cipher = CaesarCipher()
    key = CaesarCipherKey(key) if key else CaesarCipherKey.generate_random()
    ciphertext = cipher.encrypt(message, key)

    while not is_valid(message):
        print('Invalid message format.\n'
              'Messages must be a string of all uppercase letters and spaces.')
        message = input('Enter a message to encrypt: ')

    print('\nMessage: %s' % message)
    print('Key: %s' % key)
    print('Ciphertext: %s' % ciphertext)

    sampling_strategy = ExhaustiveSampling()

    attacker = LetterFrequencyAttack(sampling_strategy)
    print_attack_summary(attacker, message, ciphertext, CaesarCipher, CaesarCipherKey)

    attacker2 = DictionaryAttack(sampling_strategy)
    print_attack_summary(attacker2, message, ciphertext, CaesarCipher, CaesarCipherKey)

    attacker3 = LanguageAnalysisAttack(sampling_strategy)
    print_attack_summary(attacker3, message, ciphertext, CaesarCipher, CaesarCipherKey)

    return 0


if __name__ == '__main__':
    plac.call(main)
