from abc import ABC
from typing import Tuple, Optional

from crypto.types import Key, KeySpace, CipherText, Message


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


class Cipher(EncrypterI, DecrypterI, ABC):
    """The abstract base class for a cipher."""

    # Override this!
    KEY_SPACE: KeySpace = []

    def key(self) -> Key:
        """Get the key for the encoder.

        :return: The key the encoder uses for encoding messages.
        """
        raise NotImplementedError

    def key_space(self) -> KeySpace:
        """Get the key space for a cipher.

        :return: The key space for the cipher.
        """
        return self.KEY_SPACE


class AttackI:
    """The interface for an attacker that tries to break an encryption scheme."""

    def from_cipher(self, c: CipherText) -> Tuple[Message, Optional[Key]]:
        """Decrypt a message from the ciphertext alone.

        :param c: The ciphertext.
        :return: The attacker's guess at the original message and the possibly
                 the key.
        """
        raise NotImplementedError
