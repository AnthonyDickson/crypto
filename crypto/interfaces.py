from abc import abstractmethod, ABC
from typing import Tuple, Optional, Type

from crypto.types import Key, CipherText, Message, KeySpace


class EncrypterI(ABC):
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


class DecrypterI(ABC):
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


class CipherI(EncrypterI, DecrypterI, ABC):
    """Interface for a cipher algorithm."""

    @abstractmethod
    def key(self) -> Key:
        """Get the key for the encoder.

        :return: The key the encoder uses for encoding messages.
        """
        raise NotImplementedError

    def key_space(self) -> KeySpace:
        """Get the key space for a cipher.

        :return: The key space for the cipher.
        """
        raise NotImplementedError


class AttackI(ABC):
    """The interface for an attacker that tries to break an encryption scheme."""

    @abstractmethod
    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI]) -> Tuple[Message, Optional[Key]]:
        """Decrypt a message from the ciphertext and a known cipher

        :param c: The ciphertext.
        :param cipher_type: The type of cipher that is being used.
        :return: The attacker's guess at the original message and the possibly
                 the key.
        """
        raise NotImplementedError


class BruteForceAttackI(AttackI, ABC):
    """The interface for an attacker that tries to break an encryption scheme through brute force."""

    @abstractmethod
    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI]) -> Tuple[Message, Optional[Key]]:
        """Decrypt a message from the ciphertext and a known cipher

        :param c: The ciphertext.
        :param cipher_type: The type of cipher that is being used.
        :return: The attacker's guess at the original message and the possibly
                 the key.
        """
        raise NotImplementedError
