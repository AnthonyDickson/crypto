from string import ascii_uppercase

from crypto.ciphers.substitution import SubstitutionCipher, SubstitutionCipherKey
from tests.ciphers.cipher_test_case import CipherTestCase


class SubstitutionCipherTests(CipherTestCase):
    raw_key = {key: value for key, value in zip(ascii_uppercase, reversed(ascii_uppercase))}
    key = SubstitutionCipherKey(raw_key)

    def test_input_validation(self):
        super(SubstitutionCipherTests, self).input_validation_test(SubstitutionCipher)

    # # This is way to slow, 26! is too big :(
    # def test_keyspace_is_correct(self):
    #     def expected_key_space_gen():
    #         for permutation in itertools.permutations(ascii_uppercase):
    #             yield ''.join([''.join((key, value)) for key, value in zip(ascii_uppercase, permutation)])
    #
    #     super(SubstitutionCipherTests, self).keyspace_is_correct_test(SubstitutionCipher, expected_key_space_gen)

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
