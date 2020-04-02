from typing import Generic, ClassVar, Tuple, Optional
from abc import abstractmethod

from ..types import IPAddressType, ScanHost


class BaseProtocol(Generic[IPAddressType]):
    # MUST be overwritten in derived classes: ports for which to use this ALP
    ports: ClassVar[Tuple[int, ...]] = ()

    __slots__ = ("_src", "_dst")

    def __init__(self, src: ScanHost[IPAddressType], dst: ScanHost[IPAddressType]) -> None:
        self._src: ScanHost[IPAddressType] = src
        self._dst: ScanHost[IPAddressType] = dst

    @abstractmethod
    def pull_data(self, length_hint: int = None) -> Optional[bytes]:
        """Generate protocol-specific payload data, if possible."""
        pass

    def push_data(self, data: bytes) -> None:
        """Optionally handle response payload data in stateful protocols."""
        pass
