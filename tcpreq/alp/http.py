from typing import ClassVar, List, Tuple
from urllib.parse import quote as http_quote

from .base import BaseProtocol
from ..types import IPAddressType


# HTTP 1.1 only
class HTTPProtocol(BaseProtocol[IPAddressType]):
    ports: ClassVar[Tuple[int, ...]] = (80,)
    _TYPES: ClassVar[List[bytes]] = [
        b"*/*; q=0.300", b"text/html; q=0.999", b"application/xhtml+xml; q=1.000",
        b"application/xml; q=0.900", b"text/xml; q=0.900", b"application/json; q=0.650",
        b"application/pdf; q=0.800", b"image/*; q=0.700", b"image/png; q=0.775",
        b"image/gif; q=0.750", b"image/jpeg; q=0.725", b"text/*; q=0.500", b"video/*; q=0.100",
        b"audio/*; q=0.200", b"application/rtf; q=0.675", b"text/markdown; q=0.600",
        b"text/plain; q=0.400", b"application/atom+xml; q=0.900"
    ]
    _CHARSETS: ClassVar[List[bytes]] = [
        b"*; q=0.200", b"utf-8; q=1.000", b"us-ascii; q=0.100",
        b"utf-16le; q=0.900", b"utf-16; q=0.850", b"utf-16be; q=0.800",
        b"utf-32le; q=0.700", b"utf-32; q=0.650", b"utf-32be; q=0.600",
        b"iso-8859-15; q=0.500", b"windows-1252; q=0.400", b"iso-8859-1; q=0.300"
    ]
    _LANGS: ClassVar[List[bytes]] = [
        b"*; q=0.100", b"en-US; q=1.000", b"en; q=0.900", b"en-GB; q=0.850", b"en-CA; q=0.950",
        b"en-AU; q=0.800", b"de-DE; q=0.600", b"de; q=0.500", b"de-CH; q=0.550", b"de-AT; q=0.450",
        b"es; q=0.300", b"es-MX; q=0.350", b"es-ES; q=0.250", b"pt; q=0.200", b"fr; q=0.200"
    ]
    _ENCS: ClassVar[List[bytes]] = [b"identity; q=1.000", b"*; q=0.000"]
    assert _TYPES and _CHARSETS and _LANGS and _ENCS

    __slots__ = ()

    def pull_data(self, length_hint: int = None) -> bytes:
        res = bytearray(b"GET / HTTP/1.1\r\nHost: ")
        if self._dst.host is not None:
            res += http_quote(self._dst.host).encode("ascii")
        res += b"\r\nUser-Agent: tcpreq (TCP research scan)\r\n"
        if length_hint is None or length_hint - len(res) <= 2:
            return res + b"\r\n"

        # Caching
        res += b"Cache-Control: max-age=3600, max-stale=1600, no-transform\r\n"
        if length_hint - len(res) <= 2:
            return res + b"\r\n"

        # Pragma
        res += b"Pragma: no-cache\r\n"
        if length_hint - len(res) <= 2:
            return res + b"\r\n"

        # Referer
        res += b"Referer: about:blank\r\n"
        if length_hint - len(res) <= 2:
            return res + b"\r\n"

        # Accept, Accept-Charset, Accept-Language, Accept-Encoding
        for name, vals in ((b"Accept: ", self._TYPES), (b"Accept-Charset: ", self._CHARSETS),
                           (b"Accept-Language: ", self._LANGS), (b"Accept-Encoding: ", self._ENCS)):
            rem = length_hint - (len(res) + len(name))
            ret = True
            for idx, v in enumerate(vals):
                rem -= len(v) + 2  # Add 2 for next separator (", ")
                if rem <= 2:
                    break
            else:
                ret = False

            res += name
            res += b", ".join(vals[:idx + 1])
            res += b"\r\n"

            if ret:
                break

        return res + b"\r\n"

    # No need to implement push_data: HTTP is stateless (except for cookies), response can be ignored
