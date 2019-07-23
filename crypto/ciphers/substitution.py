import itertools
from collections import Counter
from string import ascii_uppercase
from typing import Optional, Union

from crypto.abcs import CipherABC
from crypto.types import CipherText, Key, Message, KeySpace


# noinspection PyMissingConstructor
class SubstitutionCipher(CipherABC):
    # A valid key should contain each letter of the alphabet exactly twice.
    KEY_FORMAT = Counter({char: 2 for char in ascii_uppercase})

    # The identity key simply maps letters to themselves.
    IDENTITY_KEY = {char: char for char in ascii_uppercase}

    def __init__(self, key: Optional[dict] = None):
        """Create a substitution cipher

        :param key: A dictionary encoding letter (uppercase alphabet) to letter mappings.
        """
        if not key:
            key = SubstitutionCipher.IDENTITY_KEY

        self._key_dict: dict = key
        self._inverse_key_dict = {v: k for k, v in self._key_dict.items()}
        self._key = SubstitutionCipher.key_from_dict(key)

    def key(self) -> Key:
        return self._key

    def key_space(self) -> KeySpace:
        for permutation in itertools.permutations(ascii_uppercase):
            yield {key: value for key, value in zip(ascii_uppercase, permutation)}

    def is_valid(self, x: Union[Message, CipherText]) -> bool:
        """Check if a given message or ciphertext are in a valid format.

        :param x: The message or ciphertext to check.
        :return: True if the message or ciphertext is valid, False otherwise.
        """
        return all((char.isalpha() and char.isupper()) or char.isspace()
                   for char in x)

    @staticmethod
    def is_valid_key(key: Key):
        """Check if a given key is a valid substitution cipher key.

        :param key: The key to validate.
        :return: True if the key is a valid key, False otherwise.
        """
        # A key encodes one-to-one mappings so the length of the key must be even.
        if len(key) % 2 != 0:
            return False

        # The key must have exactly two of each uppercase letter.
        letter_frequencies = Counter(key)

        if not letter_frequencies == SubstitutionCipher.KEY_FORMAT:
            return False

        # The letters representing the letters that are being mapped should be listed in alphabetical order
        for i, char in enumerate(ascii_uppercase):
            if key[2 * i] != char:
                return False

        return True

    @staticmethod
    def key_from_dict(key_dict: dict) -> Key:
        """Create a key from a dictionary.

        :param key_dict: The dictionary from which to create the key.
        :return: The generated key. A `KeyError` is raised if the dictionary produces an invalid key.
        """
        key = Key(''.join([''.join((key_dict, value)) for (key_dict, value) in key_dict.items()]))

        if not SubstitutionCipher.is_valid_key(key):
            raise KeyError('Invalid key format.\n'
                           'Ensure that the key contains each letter of the alphabet exactly twice and that the '
                           'letters in odd-numbered positions are sorted alphabetically.')

        return key

    @staticmethod
    def dict_from_key(key: Key) -> dict:
        """Create a key dictionary from a key.

        :param key: The key from which to create the dictionary.
        :return: The generated dictionary. A `KeyError` is raised if the given key is invalid.
        """
        if not SubstitutionCipher.is_valid_key(key):
            raise KeyError('Invalid key format.\n'
                           'Ensure that the key contains each letter of the alphabet exactly twice and that the '
                           'letters in odd-numbered positions are sorted alphabetically.')

        key_dict = {}

        for i in range(len(key) - 1):
            key_, value_ = key[i], key[i + 1]
            key_dict[key_] = value_

        return key_dict

    def encrypt(self, m: Message, k: Optional[Key] = None) -> CipherText:
        assert self.is_valid(m), 'Invalid message.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if not k:
            k = self._key_dict
        else:
            k = SubstitutionCipher.dict_from_key(k)

        c = CipherText('')

        for char in m:
            if char.isspace():
                c += char
            else:
                c += k[char]

        return c

    def decrypt(self, c: CipherText, k: Optional[Key] = None) -> Message:
        assert self.is_valid(c), 'Invalid ciphertext.' \
                                 '\nMessage must be all uppercase letters ' \
                                 'or spaces.'

        if not k:
            k = self._key_dict
        else:
            k = SubstitutionCipher.dict_from_key(k)
            k = {value: key for key, value in k.items()}

        m = Message('')

        for char in c:
            if char.isspace():
                m += char
            else:
                m += k[char]

        return m
