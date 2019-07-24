from typing import Optional

import plac

from crypto.ciphers.caesar import CaesarCipher, CaesarCipherKey
from crypto.common_attacks import LetterFrequencyAttack, DictionaryAttack
from crypto.metrics import print_attack_summary
from crypto.strategies import ExhaustiveSampling
from crypto.types import Message


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

    attacker = LetterFrequencyAttack(ExhaustiveSampling())
    print_attack_summary(attacker, message, ciphertext, CaesarCipher, CaesarCipherKey)

    attacker2 = DictionaryAttack(ExhaustiveSampling())
    print_attack_summary(attacker2, message, ciphertext, CaesarCipher, CaesarCipherKey)

    return 0


if __name__ == '__main__':
    plac.call(main)
