from typing import Union

from crypto.types import Message, CipherText


def is_valid(x: Union[Message, CipherText]) -> bool:
    """Check if a given message or ciphertext are in a valid format.

    :param x: The message or ciphertext to check.
    :return: True if the message or ciphertext is valid, False otherwise.
    """
    return all((char.isalpha() and char.isupper()) or char.isspace()
               for char in x)
