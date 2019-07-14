from typing import TYPE_CHECKING, TypeVar, Generic, Dict, Union
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from asyncio import Future

if TYPE_CHECKING:
    from .tcp import Segment

IPAddressType = TypeVar("IPAddressType", IPv4Address, IPv6Address)
AnyIPAddress = Union[IPv4Address, IPv6Address]
AnyIPNetwork = Union[IPv4Network, IPv6Network]


# ScanHosts are immutable
class ScanHost(Generic[IPAddressType]):
    __slots__ = ("ip", "port", "host", "raw")

    def __init__(self, ip: IPAddressType, port: int, host: str = None, raw: Dict = None) -> None:
        self.ip: IPAddressType = ip
        self.port = port
        self.host = host

        if raw is None:
            self.raw: Dict = {"ip": str(ip), "port": port, "host": host}
        else:
            self.raw = raw

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScanHost):
            return NotImplemented
        return self.ip == other.ip and self.port == other.port

    def __hash__(self) -> int:
        return hash((self.ip, self.port))


class OutgoingPacket(Generic[IPAddressType]):
    __slots__ = ("dst_addr", "ttl", "seg", "fut")

    def __init__(self, seg: "Segment", dst_addr: IPAddressType,
                 ttl: int = None, fut: "Future[None]" = None) -> None:
        self.dst_addr: IPAddressType = dst_addr
        self.ttl = ttl
        self.seg = seg
        self.fut = fut
