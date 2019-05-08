from typing import Generic, Tuple
from abc import abstractmethod

from ..types import IPAddressType


class BaseProtocol(Generic[IPAddressType]):
    __slots__ = ("_src", "_dst")

    def __init__(self, src: Tuple[IPAddressType, int], dst: Tuple[IPAddressType, int]) -> None:
        self._src: Tuple[IPAddressType, int] = src
        self._dst: Tuple[IPAddressType, int] = dst

    @property
    @abstractmethod
    def port(self) -> int:
        # Should be overwritten by a ClassVar
        pass

    @abstractmethod
    def pull_data(self, length_hint: int = None) -> bytes:
        pass

    @abstractmethod
    def push_data(self, data: bytes) -> None:
        pass
