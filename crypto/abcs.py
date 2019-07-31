"""This module defines any abstract base classes (ABCs)."""

from abc import ABC, abstractmethod
from typing import Optional

from crypto.interfaces import CipherI, KeyI, BruteForceAttackI, SamplingStrategyI
from crypto.types import T


class KeyABC(KeyI, ABC):
    """Abstract base class representing a key for a cipher"""

    def __init__(self, value: T):
        """Create a new key.

        :param value: The value of the key, or the key itself.
        """
        assert self.__class__.key_space_contains(value), 'Invalid key \'%s\'.' % str(value)

        self._value = value

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self):
        return '%s(value=%s)' % (self.__class__.__name__, self.value)

    def __len__(self) -> int:
        return len(self.value)

    def __eq__(self, other: 'KeyABC') -> bool:
        return self.value == other.value

    def __hash__(self):
        return hash(self.value)

    @property
    def value(self) -> T:
        """Get the value of the key.

        :return: The value of the key.
        """
        return self._value


class CipherABC(CipherI, ABC):
    """The abstract base class for a cipher."""

    # noinspection PyUnusedLocal
    @abstractmethod
    def __init__(self, key: Optional[KeyI] = None):
        raise NotImplementedError


class BruteForceAttackABC(BruteForceAttackI, ABC):
    """Abstract base class representing a brute-force attack."""

    def __init__(self, sampling_strategy: SamplingStrategyI):
        """Create a new brute-force attack.

        :param sampling_strategy: The strategy to use for sampling key spaces.
        """
        super().__init__()

        self.sampling_strategy = sampling_strategy
