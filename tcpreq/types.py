from typing import TypeVar, Union
from ipaddress import IPv4Address, IPv6Address

IPAddressType = TypeVar("IPAddressType", IPv4Address, IPv6Address)
AnyIPAddress = Union[IPv4Address, IPv6Address]
