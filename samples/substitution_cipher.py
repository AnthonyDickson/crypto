from typing import Optional

import plac

from crypto.ciphers.substitution import SubstitutionCipher, SubstitutionCipherKey
from crypto.ciphers.utils import is_valid
from crypto.common_attacks import LetterFrequencyAttack, DictionaryAttack, LanguageAnalysisAttack
from crypto.metrics import print_attack_summary
from crypto.strategies import RandomSampling
from crypto.types import Message


# TODO: Allow key to be set by user
@plac.annotations(
    n_samples=plac.Annotation(
        "The max number of keys an attacker can sample. Set to a higher number if you are willing to wait longer.",
        kind='option',
        type=int),
    filename=plac.Annotation('The name of a file to use as the message.', kind='option', type=str, abbrev='f')
)
def main(n_samples: int = 1000, filename: Optional[str] = None) -> int:
    """A demonstration of the substitution cipher."""
    cipher = SubstitutionCipher()
    key = SubstitutionCipherKey.generate_random()

    if filename:
        with open(filename, 'r') as f:
            message = Message(f.read())
    else:
        message = Message(input('Enter a message to encrypt: '))

    ciphertext = cipher.encrypt(message, key)

    while not is_valid(message):
        print('Invalid message format.\n'
              'Messages must be a string of all uppercase letters and spaces.')
        message = input('Enter a message to encrypt: ')

    print('\nMessage: %s' % message)
    print('Key: %s' % key)
    print('Ciphertext: %s' % ciphertext)

    sampling_strategy = RandomSampling(n_samples)

    attacker = LetterFrequencyAttack(sampling_strategy)
    print_attack_summary(attacker, message, ciphertext, SubstitutionCipher, SubstitutionCipherKey)

    attacker2 = DictionaryAttack(sampling_strategy)
    print_attack_summary(attacker2, message, ciphertext, SubstitutionCipher, SubstitutionCipherKey)

    attacker3 = LanguageAnalysisAttack(sampling_strategy)
    print_attack_summary(attacker3, message, ciphertext, SubstitutionCipher, SubstitutionCipherKey)

    return 0


if __name__ == '__main__':
    plac.call(main)
