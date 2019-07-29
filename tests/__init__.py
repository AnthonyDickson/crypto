"""This package contains unit tests for the `crypto` package."""

# Import test suites so that they can be automatically found by unittest.
from tests.abcs import TestABCs
from tests.ciphers.caesar import CaeserCipherTests
from tests.ciphers.substitution import SubstitutionCipherTests
from tests.ciphers.vigenere import VigenereCipherTests
from tests.common_attacks import TestCommonAttacks
from tests.interfaces import TestInterfaces
from tests.samples import TestSamples
