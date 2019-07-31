import itertools
from random import SystemRandom
from string import ascii_uppercase
from typing import Optional, Union, Generator

from crypto.abcs import CipherABC, KeyABC
from crypto.types import CipherText, Message


class SubstitutionCipherKey(KeyABC):
    """A key used in the Substitution cipher.
    This is defined as a set of one-to-one mappings between a set uppercase letters from the alphabet and another set
    of uppercase letters. For example, {A: B, B: C, C: D, ..., Z: A} would be an example of a key where each letter maps
    to the letter that comes after it in the alphabet, wrapping around to the start again at 'Z'.
    A key of where each letter is mapped to itself results in no effect, i.e. E(m, k) = c = D(c, k) = m.
    """

    def __init__(self, value: dict):
        super().__init__(value)

        self._inverse_mappings = {v: k for k, v in value.items()}

    def __hash__(self):
        return sum([hash((k, v)) for k, v in self.value.items()])

    @property
    def value(self) -> dict:
        return self._value

    @property
    def inverse_mappings(self) -> dict:
        """Get the inverted key mappings where values in the original mappings are now the keys.

        :return: The inverted key mappings.
        """
        return self._inverse_mappings

    @staticmethod
    def key_space_contains(k: dict) -> bool:
        if not k or not type(k) is dict:
            return False

        if not set(k.keys()) == set(ascii_uppercase):
            return False

        if not set(k.values()) == set(ascii_uppercase):
            return False

        return True

    @staticmethod
    def get_identity() -> 'SubstitutionCipherKey':
        return SubstitutionCipherKey({char: char for char in ascii_uppercase})

    @staticmethod
    def generate_random() -> 'SubstitutionCipherKey':
        shuffled_letters = list(ascii_uppercase)
        SystemRandom().shuffle(shuffled_letters)

        letter_mappings = SubstitutionCipherKey.get_identity().value

        for key, value in zip(letter_mappings.keys(), shuffled_letters):
            letter_mappings[key] = value

        return SubstitutionCipherKey(letter_mappings)

    @staticmethod
    def get_space() -> Generator['SubstitutionCipherKey', None, None]:
        for value_permutations in itertools.permutations(ascii_uppercase):
            yield SubstitutionCipherKey({k: v for k, v in zip(ascii_uppercase, value_permutations)})

    @staticmethod
    def get_space_size() -> int:
        return int(4.0329146e+26)  # approximately 26!


# noinspection PyMissingConstructor
class SubstitutionCipher(CipherABC):
    """The substitution cipher where a lookup table is used to encrypt messages."""

    def __init__(self, key: Optional[SubstitutionCipherKey] = None):
        """Create a substitution cipher

        :param key: A dictionary encoding letter (uppercase alphabet) to letter mappings.
        """
        if key:
            self._key = key
        else:
            self._key = SubstitutionCipherKey.get_identity()

    @property
    def key(self) -> SubstitutionCipherKey:
        return self._key

    @staticmethod
    def is_valid(x: Union[Message, CipherText]) -> bool:
        """Check if a given message or ciphertext are in a valid format.

        :param x: The message or ciphertext to check.
        :return: True if the message or ciphertext is valid, False otherwise.
        """
        return all((char.isalpha() and char.isupper()) or char.isspace()
                   for char in x)

    def encrypt(self, m: Message, k: Optional[SubstitutionCipherKey] = None) -> CipherText:
        assert self.is_valid(m), 'Invalid message.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if k:
            k = k.value
        else:
            k = self.key.value

        c = CipherText('')

        for char in m:
            if char.isspace():
                c += char
            else:
                c += k[char]

        return c

    def decrypt(self, c: CipherText, k: Optional[SubstitutionCipherKey] = None) -> Message:
        assert self.is_valid(c), 'Invalid ciphertext.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if k:
            k = k.inverse_mappings
        else:
            k = self.key.inverse_mappings

        m = Message('')

        for char in c:
            if char.isspace():
                m += char
            else:
                m += k[char]

        return m
