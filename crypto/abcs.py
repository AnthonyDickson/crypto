"""This module defines any abstract base classes (ABCs)."""

from abc import ABC, abstractmethod

from crypto.interfaces import EncrypterI, DecrypterI
from crypto.types import KeySpace, Key


class CipherABC(EncrypterI, DecrypterI, ABC):
    """The abstract base class for a cipher."""

    # Override this!
    KEY_SPACE: KeySpace = []

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
        return self.KEY_SPACE
