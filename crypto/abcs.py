"""This module defines any abstract base classes (ABCs)."""

from abc import ABC, abstractmethod
from typing import Optional, Union

from crypto.interfaces import CipherI
from crypto.types import KeySpace, Key, CipherText, Message


class CipherABC(CipherI, ABC):
    """The abstract base class for a cipher."""

    # Override this!
    KEY_SPACE: KeySpace = []

    # And override this too!
    IDENTITY_KEY = Key('')

    @abstractmethod
    def __init__(self, key: Optional[Key] = None):
        raise NotImplementedError

    @abstractmethod
    def key(self) -> Key:
        """Get the key for the encoder.

        :return: The key the encoder uses for encoding messages.
        """
        raise NotImplementedError

    def key_space(self) -> KeySpace:
        """Get the key space for a cipher.
        WARNING: This be very slow for ciphers with large key spaces!

        :return: The key space for the cipher.
        """
        return self.KEY_SPACE

    @abstractmethod
    def is_valid(self, x: Union[Message, CipherText]) -> bool:
        """Check if a given message or ciphertext are in a valid format.

        :param x: The message or ciphertext to check.
        :return: True if the message or ciphertext is valid, False otherwise.
        """
        raise NotImplementedError
