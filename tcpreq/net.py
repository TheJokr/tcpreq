from abc import abstractmethod
from typing import Generic, ClassVar, Dict, List, Tuple, Deque, Optional
import sys
from collections import Counter, deque
from ipaddress import IPv4Address, IPv6Address
import socket
import asyncio

from .types import IPAddressType, ScanHost, OutgoingPacket, ICMPQuote
from .limiter import TokenBucket, OutOfTokensError
from .tests import BaseTest
from .tcp import Segment

# Workaround for missing attributes
# See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
_IPPROTO_IPV6: int = getattr(socket, "IPPROTO_IPV6", 41)
_IPPROTO_ICMPV6: int = getattr(socket, "IPPROTO_ICMPV6", 58)

# See https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
_IPV6_EXT_HEAD_TYPES = {0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254}

# See https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
_ICMP_TIME_EXCEEDED: int = getattr(socket, "ICMP_TIME_EXCEEDED", 11)
_ICMP_EXC_TTL: int = getattr(socket, "ICMP_EXC_TTL", 0)

# See https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
_ICMPV6_TIME_EXCEED: int = getattr(socket, "ICMPV6_TIME_EXCEED", 3)
_ICMPV6_EXC_HOPLIMIT: int = getattr(socket, "ICMPV6_EXC_HOPLIMIT", 0)

# Workaround for attributes available only on Linux
_IS_LINUX = sys.platform == "linux"
if _IS_LINUX:
    # See linux/include/uapi/asm-generic/socket.h
    _SO_RCVBUFFORCE: int = getattr(socket, "SO_RCVBUFFORCE", 33)

    # See linux/include/uapi/linux/in.h
    _IP_MTU_DISCOVER: int = getattr(socket, "IP_MTU_DISCOVER", 10)
    _IP_PMTUDISC_PROBE: int = getattr(socket, "IP_PMTUDISC_PROBE", 3)

    # See linux/include/uapi/linux/in6.h
    _IPV6_MTU_DISCOVER: int = getattr(socket, "IPV6_MTU_DISCOVER", 23)
    _IPV6_PMTUDISC_PROBE: int = getattr(socket, "IPV6_PMTUDISC_PROBE", 3)

    # See linux/include/uapi/linux/icmp.h
    _ICMP_FILTER: int = getattr(socket, "ICMP_FILTER", 1)

    # See linux/include/uapi/linux/icmpv6.h
    _ICMPV6_FILTER: int = getattr(socket, "ICMPV6_FILTER", 1)
else:
    # Fall back to SO_RCVBUF
    _SO_RCVBUFFORCE = socket.SO_RCVBUF


class BaseTestMultiplexer(Generic[IPAddressType]):
    """Multiplex multiple TCP streams over a single raw IP socket."""
    # Ignore connection after _RST_THRESHOLD attempted resets
    _RST_THRESHOLD: ClassVar[int] = 3

    @abstractmethod
    def __init__(self, sock_fam: socket.AddressFamily, icmp_proto: int, src: IPAddressType,
                 send_limiter: TokenBucket, *, loop: asyncio.AbstractEventLoop = None) -> None:
        tcp_sock = socket.socket(sock_fam, socket.SOCK_RAW, socket.IPPROTO_TCP)
        icmp_sock = socket.socket(sock_fam, socket.SOCK_RAW, icmp_proto)
        for sock in (tcp_sock, icmp_sock):
            sock.setblocking(False)
            sock.setsockopt(socket.SOL_SOCKET, _SO_RCVBUFFORCE, 8_388_608)
            sock.bind((str(src), 0))

        if loop is None:
            loop = asyncio.get_event_loop()
        loop.add_reader(tcp_sock.fileno(), self._handle_read)
        loop.add_reader(icmp_sock.fileno(), self._handle_icmp_read)
        loop.add_writer(tcp_sock.fileno(), self._handle_write)

        self._sock = tcp_sock
        self._icmp_sock = icmp_sock
        self._src_addr: IPAddressType = src
        self._test_map: Dict[Tuple[int, bytes, int], "BaseTest[IPAddressType]"] = {}
        self._send_queue: Deque[OutgoingPacket[IPAddressType]] = deque()
        self._send_limiter = send_limiter
        self._sent_rsts: Dict[Tuple[int, bytes, int], int] = {}
        self._loop = loop

    @staticmethod
    def _test_map_key(test: BaseTest[IPAddressType]) -> Tuple[int, bytes, int]:
        # Local address is verified in register_test and handled by OS
        return test.src.port, test.dst.ip.packed, test.dst.port

    def register_test(self, test: BaseTest[IPAddressType]) -> None:
        if test.send_queue is not None:
            raise ValueError("Test is already registered with a multiplexer")
        if test.src.ip != self._src_addr:
            raise ValueError("Test's source address doesn't match socket's source address")

        test.send_queue = self._send_queue
        self._test_map[self._test_map_key(test)] = test

    def unregister_test(self, test: BaseTest[IPAddressType]) -> None:
        if test.send_queue is not self._send_queue:
            raise ValueError("Test is not registered with this multiplexer")

        del self._test_map[self._test_map_key(test)]
        test.send_queue = None

    @abstractmethod
    def _handle_read(self) -> None:
        pass

    def _handle_bytes(self, src_addr: IPAddressType, data: bytearray) -> None:
        if len(data) < 4:
            # Discard segments not containing both ports silently
            return

        sport = int.from_bytes(data[0:2], "big")
        dport = int.from_bytes(data[2:4], "big")
        try:
            self._test_map[(dport, src_addr.packed, sport)].recv_queue.put_nowait(data)
        except KeyError:
            return self._handle_unk_src(src_addr, data)

    def _handle_unk_src(self, src_addr: IPAddressType, data: bytearray) -> None:
        try:
            seg = Segment.from_bytes(src_addr.packed, self._src_addr.packed, data)
        except ValueError:
            return

        # tcpreq always uses ephemeral ports. Don't interfere with other connections.
        if seg.dst_port < 49152 or seg.flags & 0x04:
            return

        # Give up after sending _RST_THRESHOLD resets
        key = (seg.dst_port, src_addr.packed, seg.src_port)
        rsts = self._sent_rsts.get(key, 0)
        if rsts >= self._RST_THRESHOLD:
            return

        self._send_queue.append(OutgoingPacket(
            seg.make_reset(ScanHost(self._src_addr, key[0]), ScanHost(src_addr, key[2])),
            src_addr
        ))
        self._sent_rsts[key] = rsts + 1

    @abstractmethod
    def _handle_icmp_read(self) -> None:
        pass

    def _handle_icmp_time_exceeded(self, icmp_src: IPAddressType, src_addr: bytes,
                                   dst_addr: bytes, quote: bytes, hop: int) -> None:
        if len(quote) < 4:
            # Discard invalid quotes silently
            return

        src_port = int.from_bytes(quote[0:2], "big")
        dst_port = int.from_bytes(quote[2:4], "big")
        try:
            self._test_map[(src_port, dst_addr, dst_port)].quote_queue.append(
                ICMPQuote(icmp_src, src_addr, hop, quote)
            )
        except KeyError:
            pass

    @abstractmethod
    def _handle_write(self) -> None:
        pass


class IPv4TestMultiplexer(BaseTestMultiplexer[IPv4Address]):
    _DEFAULT_TOS: ClassVar[int] = 0x00
    _DEFAULT_TTL: ClassVar[int] = 64

    # version/IHL, TOS, total length (2), ID (2), flags/fragment offset (2),
    # TTL, protocol, checksum (2), src_addr (4), dst_addr (4) [, no options]
    _IP_HEAD: ClassVar[bytes] = bytes((0x45, _DEFAULT_TOS, 0x00, 0x00,
                                       0x00, 0x00, 1 << 6, 0x00,
                                       _DEFAULT_TTL, socket.IPPROTO_TCP, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00))
    assert len(_IP_HEAD) == 20

    def __init__(self, src: IPv4Address, send_limiter: TokenBucket,
                 *, loop: asyncio.AbstractEventLoop = None) -> None:
        super(IPv4TestMultiplexer, self).__init__(socket.AF_INET, socket.IPPROTO_ICMP,
                                                  src, send_limiter, loop=loop)

        # Enable IP_HDRINCL to modify Identification field in traces
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self._send_next: Optional[Tuple[bytes, Tuple[str, int]]] = None
        self._next_fut: Optional["asyncio.Future[None]"] = None

        if _IS_LINUX:
            self._sock.setsockopt(socket.IPPROTO_IP, _IP_MTU_DISCOVER, _IP_PMTUDISC_PROBE)

            # See linux/net/ipv4/raw.c
            allow = (1 << _ICMP_TIME_EXCEEDED)
            self._icmp_sock.setsockopt(socket.IPPROTO_RAW, _ICMP_FILTER,
                                       (~allow & 0xffff_ffff).to_bytes(4, sys.byteorder))

    def _handle_read(self) -> None:
        try:
            while True:
                # Raw IPv4 sockets include header
                data, src = self._sock.recvfrom(4096)  # TODO: increase if necessary
                data = bytearray(data)
                dlen = len(data)

                if dlen < 20:
                    continue
                head_len = (data[0] << 2) & 0b00111100  # == (data[0] & 0x0f) * 4
                if dlen < head_len:
                    continue

                self._handle_bytes(IPv4Address(src[0]), data[head_len:])
        except BlockingIOError:
            pass

    def _handle_icmp_read(self) -> None:
        try:
            while True:
                # Raw IPv4 sockets include header
                data, src = self._icmp_sock.recvfrom(4096)  # TODO: increase if necessary
                dlen = len(data)

                if dlen < 28:
                    continue
                head_len = (data[0] << 2) & 0b00111100  # == (data[0] & 0x0f) * 4
                if dlen < head_len + 8:
                    continue

                if data[head_len] == _ICMP_TIME_EXCEEDED and data[head_len + 1] == _ICMP_EXC_TTL:
                    # TODO: verify ICMP checksum?
                    data = data[head_len + 8:]
                    dlen = len(data)

                    if dlen < 20 or data[9] != socket.IPPROTO_TCP:
                        continue
                    head_len = (data[0] << 2) & 0b00111100  # == (data[0] & 0x0f) * 4
                    total_len = int.from_bytes(data[2:4], "big")
                    if dlen < head_len:
                        continue

                    self._handle_icmp_time_exceeded(IPv4Address(src[0]), data[12:16], data[16:20],
                                                    data[head_len:total_len], hop=self._recover_ttl(data))
        except BlockingIOError:
            pass

    @staticmethod
    def _recover_ttl(data: bytes) -> int:
        # Parse ID field
        enc = int.from_bytes(data[4:6], "big")
        val, cnt = Counter((enc >> i) & 0x1f for i in (11, 5, 0)).most_common(1)[0]
        if cnt >= 2:
            # Random chance (3): 2^6 in 2^16 <=> 1 in 1024
            # Random chance (2): 3 * (2^11 - 2^6) in 2^16  <=> 1 in ~11
            return val

        # Fallback for unknown TTL
        return 0

    def _handle_write(self) -> None:
        # Send segment dequeued last during previous invocation if present
        if self._send_next is not None:
            try:
                self._send_limiter.take()
                self._sock.sendto(*self._send_next)
                if self._next_fut is not None:
                    self._next_fut.set_result(None)
            except (OutOfTokensError, BlockingIOError):
                return
            else:
                self._send_next = None
                self._next_fut = None

        try:
            while True:
                item = self._send_queue.popleft()
                dst = (str(item.dst_addr), 0)
                data = bytearray(self._IP_HEAD)
                data[16:20] = item.dst_addr.packed
                data.extend(bytes(item.seg))

                if item.ttl is not None:
                    # Set TTL
                    data[8] = item.ttl

                    # Encode TTL into ID field (bits 15-11, 9-5, and 4-0)
                    enc = item.ttl
                    enc |= (enc << 11) | (enc << 5)
                    data[4:6] = enc.to_bytes(2, "big")

                self._send_limiter.take()
                self._sock.sendto(data, dst)
                if item.fut is not None:
                    item.fut.set_result(None)
        except IndexError:
            pass
        except (OutOfTokensError, BlockingIOError):
            self._send_next = (data, dst)
            self._next_fut = item.fut


class IPv6TestMultiplexer(BaseTestMultiplexer[IPv6Address]):
    def __init__(self, src: IPv6Address, send_limiter: TokenBucket,
                 *, loop: asyncio.AbstractEventLoop = None) -> None:
        super(IPv6TestMultiplexer, self).__init__(socket.AF_INET6, _IPPROTO_ICMPV6,
                                                  src, send_limiter, loop=loop)

        self._send_next: Optional[Tuple[bytes, Tuple[str, int], List[Tuple[int, int, bytes]]]] = None
        self._next_fut: Optional["asyncio.Future[None]"] = None

        if _IS_LINUX:
            self._sock.setsockopt(_IPPROTO_IPV6, _IPV6_MTU_DISCOVER, _IPV6_PMTUDISC_PROBE)

            # See linux/net/ipv6/raw.c
            allow = [0] * 8
            allow[_ICMPV6_TIME_EXCEED >> 5] |= (1 << (_ICMPV6_TIME_EXCEED & 0x1f))
            buf = b''.join((~v & 0xffff_ffff).to_bytes(4, sys.byteorder) for v in allow)
            self._icmp_sock.setsockopt(_IPPROTO_ICMPV6, _ICMPV6_FILTER, buf)

    def _handle_read(self) -> None:
        try:
            while True:
                # Raw IPv6 sockets don't include header
                data, src = self._sock.recvfrom(4096)  # TODO: increase if necessary
                self._handle_bytes(IPv6Address(src[0]), bytearray(data))
        except BlockingIOError:
            pass

    def _handle_icmp_read(self) -> None:
        try:
            while True:
                # Raw IPv6 sockets don't include header
                # Kernel verifies checksum for ICMPv6 sockets
                data, src = self._icmp_sock.recvfrom(4096)  # TODO: increase if necessary
                dlen = len(data)
                if dlen < 8:
                    continue

                if data[0] == _ICMPV6_TIME_EXCEED and data[1] == _ICMPV6_EXC_HOPLIMIT:
                    if dlen < 48:
                        continue

                    total_len = data[4] or None
                    if total_len is not None:
                        total_len += 8

                    next_head = data[14]
                    src_addr = data[16:32]
                    dst_addr = data[32:48]
                    data = data[48:total_len]

                    quote = self._walk_header_chain(next_head, data)
                    if quote is None:
                        continue

                    # Number of hops is not encoded into IPv6 packets
                    self._handle_icmp_time_exceeded(IPv6Address(src[0]), src_addr,
                                                    dst_addr, quote, hop=0)
        except BlockingIOError:
            pass

    @staticmethod
    def _walk_header_chain(next_head: int, data: bytes) -> Optional[bytes]:
        # Walk header chain til TCP header is reached
        while next_head != socket.IPPROTO_TCP:
            dlen = len(data)
            if next_head not in _IPV6_EXT_HEAD_TYPES or dlen < 2:
                return None

            # Fragment Header (44) is the only extension header without a length field
            # All other extension headers are required to have one (RFC 8200, section 4.8)
            head_len = 8 if next_head == 44 else data[1]
            if dlen < head_len:
                return None

            next_head = data[0]
            data = data[head_len:]

        return data

    def _handle_write(self) -> None:
        # Send segment dequeued last during previous invocation if present
        if self._send_next is not None:
            try:
                msg = self._send_next
                self._send_limiter.take()
                if msg[2]:
                    self._sock.sendmsg((msg[0],), msg[2], 0, msg[1])
                else:
                    self._sock.sendto(msg[0], msg[1])
                if self._next_fut is not None:
                    self._next_fut.set_result(None)
            except (OutOfTokensError, BlockingIOError):
                return
            else:
                self._send_next = None
                self._next_fut = None

        try:
            while True:
                item = self._send_queue.popleft()
                dst = (str(item.dst_addr), 0)
                data = bytes(item.seg)
                ancil: List[Tuple[int, int, bytes]] = []

                if item.ttl is not None:
                    # Set hop limit
                    ancil.append((_IPPROTO_IPV6, socket.IPV6_HOPLIMIT,
                                  item.ttl.to_bytes(4, sys.byteorder)))

                    # Can't encode TTL into flow label because Linux
                    # requires a lot of internal setup to overwrite it,
                    # which is not available from Python

                if ancil:
                    self._sock.sendmsg((data,), ancil, 0, dst)
                else:
                    self._sock.sendto(data, dst)
                if item.fut is not None:
                    item.fut.set_result(None)
        except IndexError:
            return
        except (OutOfTokensError, BlockingIOError):
            self._send_next = (data, dst, ancil)
            self._next_fut = item.fut
