from typing import ClassVar, Tuple, Optional
import ssl

from .base import BaseProtocol
from ..types import IPAddressType, ScanHost


class TLSProtocol(BaseProtocol):
    # HTTPS, SMTPS, NNTPS, LDAPS, DNS over TLS, FTPS (data), FTPS (control), Telnet over TLS
    # IMAPS, POP3S, XMPP over TLS (client-server), XMPP over TLS (server-server), IRC over TLS
    ports: ClassVar[Tuple[int, ...]] = (443, 465, 563, 636, 853, 989, 990, 992,
                                        993, 995, 5223, 5270, 6697)
    # Ignore TLS version/certificate validity/cipher
    _SSL_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS)
    _SSL_CTX.set_ciphers("ALL:COMPLEMENTOFALL")
    _SSL_CTX.options = ssl.OP_ALL | ssl.OP_NO_COMPRESSION
    _SSL_CTX.verify_mode = ssl.CERT_NONE

    __slots__ = ("_in_bio", "_out_bio", "_ssl")

    def __init__(self, src: ScanHost[IPAddressType], dst: ScanHost[IPAddressType]) -> None:
        super(TLSProtocol, self).__init__(src, dst)

        self._in_bio = ssl.MemoryBIO()
        self._out_bio = ssl.MemoryBIO()
        self._ssl = self._SSL_CTX.wrap_bio(self._in_bio, self._out_bio, server_side=False)

    def pull_data(self, length_hint: int = None) -> Optional[bytes]:
        try:
            self._ssl.do_handshake()
            if not self._out_bio.pending:
                self._ssl.unwrap()
        except ssl.SSLWantReadError:
            pass

        if self._out_bio.pending:
            return self._out_bio.read(length_hint or 536)
        return None

    def push_data(self, data: bytes) -> None:
        # Pass all data directly to OpenSSL
        # Processing is performed in pull_data (if necessary)
        self._in_bio.write(data)
