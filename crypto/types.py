from typing import NewType

Key = NewType('Key', str)
KeySpace = NewType('KeySpace', set)  # Set[Key]
CipherText = NewType('CipherText', str)
Message = NewType('Message', str)
