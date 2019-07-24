from typing import Type, Generator, Optional

from crypto.interfaces import SamplingStrategyI, KeyI


class ExhaustiveSampling(SamplingStrategyI):
    def sample(self, key_type: Type[KeyI]) -> Generator[KeyI, None, None]:
        yield from key_type.get_space()


class RandomSampling(SamplingStrategyI):
    def __init__(self, n: int = 1000):
        """Create a random sampler.

        :param n: Default number of samples to generate before stopping.
        """
        self.n = n

    def sample(self, key_type: Type[KeyI], n: Optional[int] = None) -> Generator[KeyI, None, None]:
        """Generate samples from a key space.

        :param n: Number of samples to generate before stopping. If None then the default value set via the
                  constructor is used.
        :param key_type: The type of key whose key space should be sampled.
        :return: Yields keys sampled from a key space.
        """
        for _ in range(n if n else self.n):
            yield key_type.generate_random()
