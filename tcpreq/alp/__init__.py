from typing import Type, Dict

from .base import BaseProtocol
from .http import HTTPProtocol
from .tls import TLSProtocol

ALP_MAP: Dict[int, Type[BaseProtocol]] = {}
for proto in (HTTPProtocol, TLSProtocol):
    for port in proto.ports:
        assert port not in ALP_MAP, "Port {} is assigned to multiple ALP classes".format(port)
        ALP_MAP[port] = proto  # type: ignore
