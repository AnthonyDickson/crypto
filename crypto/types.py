from typing import NewType, Set, Union

Key = NewType('Key', Union[int, str])
KeySpace = NewType('KeySpace', Set[Key])
CipherText = NewType('CipherText', str)
Message = NewType('Message', str)
