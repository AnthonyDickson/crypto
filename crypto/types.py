from typing import NewType, TypeVar

T = TypeVar('T')
KeySpace = NewType('KeySpace', set)  # Set[KeyI]
CipherText = NewType('CipherText', str)
Message = NewType('Message', str)
