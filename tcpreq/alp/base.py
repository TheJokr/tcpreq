from typing import Generic, ClassVar, Tuple, Optional
from abc import abstractmethod

from ..types import IPAddressType, ScanHost


class BaseProtocol(Generic[IPAddressType]):
    ports: ClassVar[Tuple[int, ...]] = ()

    __slots__ = ("_src", "_dst")

    def __init__(self, src: ScanHost[IPAddressType], dst: ScanHost[IPAddressType]) -> None:
        self._src: ScanHost[IPAddressType] = src
        self._dst: ScanHost[IPAddressType] = dst

    @abstractmethod
    def pull_data(self, length_hint: int = None) -> Optional[bytes]:
        pass

    @abstractmethod
    def push_data(self, data: bytes) -> None:
        pass
