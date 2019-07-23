from abc import ABC
from typing import Optional, Set, Tuple

Key = str
KeySpace = Set[Key]
CipherText = str
Message = str


class EncrypterI:
    """Interface for an encryption algorithm"""

    def encrypt(self, m: Message, k: Optional[Key] = None) -> CipherText:
        """Encrypt a message.

        :param m: The message to encrypt.
        :param k: The key to use for encrypting the message with. If None then
                  the key returned by `get_key()` is used.
        :return: The ciphertext (the encrypted message).
        """
        raise NotImplementedError


class DecrypterI:
    """Intferface for a decryption algorithm."""

    def decrypt(self, c: CipherText, k: Optional[Key] = None) -> Message:
        """Decrypt a ciphertext.

        :param c: The ciphertext to decrypt.
        :param k: The key to use for decrypting the message with. If None then
                  the key returned by `get_key()` is used.
        :return: The decrypted message.
        """
        raise NotImplementedError


class CipherI(EncrypterI, DecrypterI, ABC):
    """The interface for a cipher."""

    def get_key(self) -> Key:
        """Get the key for the encoder.

        :return: The key the encoder uses for encoding messages.
        """
        raise NotImplementedError

    def get_key_space(self) -> KeySpace:
        """Get the key space for a cipher.

        :return: The key space for the cipher.
        """
        raise NotImplementedError

    @property
    def k(self):
        """The key for a cipher. An alias for `get_key()`."""
        return self.get_key()

    @property
    def K(self):
        """The key space for a cipher. An alias for `get_key_space()`."""
        return self.get_key_space()


class AttackerI:
    """The interface for an attacker that tries to break an encryption scheme."""

    def from_cipher(self, c: CipherText) -> Tuple[Message, Optional[Key]]:
        """Decrypt a message from the ciphertext alone.

        :param c: The ciphertext.
        :return: The attacker's guess at the original message and the possibly
                 the key.
        """
        raise NotImplementedError
