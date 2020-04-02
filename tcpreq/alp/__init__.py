from typing import Type, Dict

from .base import BaseProtocol

# To register a custom ALP, make it a subclass of BaseProtocol and import it here
from .http import HTTPProtocol
from .tls import TLSProtocol

ALP_MAP: Dict[int, Type[BaseProtocol]] = {}
for proto in BaseProtocol.__subclasses__():
    for port in proto.ports:
        assert port not in ALP_MAP, "Port {} is assigned to multiple ALP classes".format(port)
        ALP_MAP[port] = proto  # type: ignore
