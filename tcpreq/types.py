from typing import TypeVar, Generic, Dict, Union
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

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
        return self.ip == other.ip and self.port == other.port and self.host == other.host

    def __hash__(self) -> int:
        return hash((self.ip, self.port, self.host))
