from abc import abstractmethod, ABC
from typing import Tuple, Optional, Type, TypeVar, Generator, Union

from crypto.types import CipherText, Message

T = TypeVar('T')


class KeyI(ABC):
    @property
    @abstractmethod
    def value(self) -> T:
        """Get the value of the key.

        :return: The value of the key.
        """
        raise NotImplementedError

    @abstractmethod
    def is_valid(self) -> bool:
        """Check whether or not a key is valid.

        :return: True if the key is valid, False otherwise.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_identity() -> 'KeyI':
        """Get the identity key, or the key that when used from encrypting has no effect (yields the original message).

        :return: The identity key.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def generate_random() -> 'KeyI':
        """Generate a random key.

        :return: A randomly generated key.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_space() -> Generator['KeyI', None, None]:
        """Get the key space, or the set of all valid keys.

        :return: A generator that yields a sequence of valid keys.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_space_size() -> int:
        """Get the number of elements in the key space

        :return: The size of the key space.
        """
        raise NotImplementedError


class EncrypterI(ABC):
    """Interface for an encryption algorithm"""

    @abstractmethod
    def encrypt(self, m: Message, k: Optional[KeyI] = None) -> CipherText:
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
    def decrypt(self, c: CipherText, k: Optional[KeyI] = None) -> Message:
        """Decrypt a ciphertext.

        :param c: The ciphertext to decrypt.
        :param k: The key to use for decrypting the message with. If None then
                  the key returned by `get_key()` is used.
        :return: The decrypted message.
        """
        raise NotImplementedError


class CipherI(EncrypterI, DecrypterI, ABC):
    """Interface for a cipher algorithm."""

    @property
    @abstractmethod
    def key(self) -> KeyI:
        """Get the key for the encoder.

        :return: The key the encoder uses for encoding messages.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def is_valid(x: Union[Message, CipherText]) -> bool:
        """Check if a given message or ciphertext are in a valid format.

        :param x: The message or ciphertext to check.
        :return: True if the message or ciphertext is valid, False otherwise.
        """
        raise NotImplementedError


class AttackI(ABC):
    """The interface for an attacker that tries to break an encryption scheme."""

    @abstractmethod
    def __init__(self):
        pass


class BruteForceAttackI(AttackI, ABC):
    """The interface for an attacker that tries to break an encryption scheme through brute force."""

    @abstractmethod
    def from_cipher(self, c: CipherText, cipher_type: Type[CipherI],
                    key_type: Type[KeyI]) -> Tuple[Message, Optional[KeyI]]:
        """Decrypt a message from the ciphertext and a known cipher and key type.

        :param c: The ciphertext.
        :param cipher_type: The type of cipher that is being used.
        :param key_type: The type of key the cipher uses.
        :return: The attacker's guess at the original message and the possibly
                 the key.
        """
        raise NotImplementedError


class SamplingStrategyI(ABC):
    """An interface for a strategy of sampling a key space."""

    @abstractmethod
    def sample(self, key_type: Type[KeyI]) -> Generator[KeyI, None, None]:
        """Generate samples from a key space.

        :param key_type: The type of key whose key space should be sampled.
        :return: Yields keys sampled from a key space.
        """
        raise NotImplementedError
