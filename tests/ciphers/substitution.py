import random
from string import ascii_uppercase

from crypto.ciphers.substitution import SubstitutionCipher, SubstitutionCipherKey
from tests.ciphers.cipher_test_case import CipherTestCase


class SubstitutionCipherTests(CipherTestCase):
    raw_key = {key: value for key, value in zip(ascii_uppercase, reversed(ascii_uppercase))}
    key = SubstitutionCipherKey(raw_key)

    def test_input_validation(self):
        super(SubstitutionCipherTests, self).input_validation_test(SubstitutionCipher)

    def test_keyspace_is_correct(self):
        shuffled_ascii = ascii_uppercase
        random.shuffle(list(shuffled_ascii))

        pass_cases = [
            {char: char for char in ascii_uppercase},
            {k: v for k, v in zip(ascii_uppercase, reversed(ascii_uppercase))},
            {k: v for k, v in zip(ascii_uppercase, shuffled_ascii)}
        ]

        fail_cases = [
            None,
            dict(),  # empty dict
            {'A': 'B'},  # missing entries
            {0: char for char in ascii_uppercase},  # wrong key type
            {char: 0 for char in ascii_uppercase},  # wrong value type
            42.0,
            42,
            'this is definitely not a valid key',
            'n0r i5 th15 ##!!#(&814',
            set(),
            set(ascii_uppercase)
        ]

        super(SubstitutionCipherTests, self) \
            .keyspace_is_correct_test(SubstitutionCipherKey, pass_cases, fail_cases)

    def test_can_set_key(self):
        super(SubstitutionCipherTests, self).can_set_key_test(SubstitutionCipher, self.raw_key, self.key)

    def test_generates_valid_ciphertext(self):
        super(SubstitutionCipherTests, self).generates_valid_ciphertext_test(SubstitutionCipher, self.key)

    def test_generates_valid_plaintext(self):
        super(SubstitutionCipherTests, self).generates_valid_plaintext_test(SubstitutionCipher, self.key)

    def test_identity_key(self):
        super(SubstitutionCipherTests, self).identity_key_test(SubstitutionCipher)

    def test_is_symmetric(self):
        super(SubstitutionCipherTests, self).is_symmetric_test(SubstitutionCipher, self.key)
