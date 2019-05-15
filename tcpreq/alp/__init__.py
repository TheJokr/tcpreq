from typing import Type, Dict

from .base import BaseProtocol
from .http import HTTPProtocol
from .tls import TLSProtocol

PORT_MAP: Dict[int, Type[BaseProtocol]] = {}
for proto in (HTTPProtocol, TLSProtocol):
    for port in proto.ports:  # type: ignore
        assert port not in PORT_MAP, "Port {} is assigned to multiple ALP classes".format(port)
        PORT_MAP[port] = proto  # type: ignore
