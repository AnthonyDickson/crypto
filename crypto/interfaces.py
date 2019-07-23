from abc import abstractmethod
from typing import Tuple, Optional

from crypto.types import Key, CipherText, Message


class EncrypterI:
    """Interface for an encryption algorithm"""

    @abstractmethod
    def encrypt(self, m: Message, k: Optional[Key] = None) -> CipherText:
        """Encrypt a message.

        :param m: The message to encrypt.
        :param k: The key to use for encrypting the message with. If None then
                  the key returned by `get_key()` is used.
        :return: The ciphertext (the encrypted message).
        """
        raise NotImplementedError


class DecrypterI:
    """Interface for a decryption algorithm."""

    @abstractmethod
    def decrypt(self, c: CipherText, k: Optional[Key] = None) -> Message:
        """Decrypt a ciphertext.

        :param c: The ciphertext to decrypt.
        :param k: The key to use for decrypting the message with. If None then
                  the key returned by `get_key()` is used.
        :return: The decrypted message.
        """
        raise NotImplementedError


class AttackI:
    """The interface for an attacker that tries to break an encryption scheme."""

    @abstractmethod
    def from_cipher(self, c: CipherText) -> Tuple[Message, Optional[Key]]:
        """Decrypt a message from the ciphertext alone.

        :param c: The ciphertext.
        :return: The attacker's guess at the original message and the possibly
                 the key.
        """
        raise NotImplementedError
