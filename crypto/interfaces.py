from abc import ABC
from typing import Optional, Set

Key = str
KeySpace = Set[Key]
CipherText = str
Message = str


class EncoderI:
    """Interface for an encoder"""

    def encode(self, m: Message, k: Optional[Key] = None) -> CipherText:
        """Encode a message.

        :param m: The message to encode.
        :param k: The key to encode the message with. If None then the key
                  returned by `get_key()` is used.
        :return: The ciphertext (encoded message).
        """
        raise NotImplementedError


class DecoderI:
    """Inferface for a decoder."""

    def decode(self, c: CipherText, k: Optional[Key] = None) -> Message:
        """Decode a ciphertext.

        :param c: The ciphertext to decode.
        :param k: The key to decode the message with. If None then the key
                  returned by `get_key()` is used.
        :return: The decoded message.
        """
        raise NotImplementedError


class CipherI(EncoderI, DecoderI, ABC):
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

    def from_cipher(self, c: CipherText) -> Message:
        """Decode a message from the ciphertext alone.

        :param c: The ciphertext.
        :return: The attacker's guess at the original message.
        """
        raise NotImplementedError
