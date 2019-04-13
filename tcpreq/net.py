from abc import abstractmethod
from typing import Generic, ClassVar, Dict, List, Tuple, Union, Optional
import sys
import itertools
from ipaddress import IPv4Address, IPv6Address
import socket
import asyncio

from .types import IPAddressType
from .limiter import TokenBucket, OutOfTokensError
from .tests import BaseTest
from .tcp import Segment

# Workaround for missing attributes on Windows
# See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
_IPPROTO_IPV6: int = getattr(socket, "IPPROTO_IPV6", 41)
_IPPROTO_ICMPV6: int = getattr(socket, "IPPROTO_ICMPV6", 58)

# Workaround for missing attributes (only available on Linux)
_IS_LINUX = sys.platform == "linux"
if _IS_LINUX:
    # See linux/include/uapi/linux/icmp.h
    _ICMP_FILTER: int = getattr(socket, "ICMP_FILTER", 1)
    _ICMP_TIME_EXCEEDED: int = getattr(socket, "ICMP_TIME_EXCEEDED", 11)

    # See linux/include/uapi/linux/icmpv6.h
    _ICMPV6_FILTER: int = getattr(socket, "ICMPV6_FILTER", 1)
    _ICMPV6_TIME_EXCEED: int = getattr(socket, "ICMPV6_TIME_EXCEED", 3)


class BaseTestMultiplexer(Generic[IPAddressType]):
    """Multiplex multiple TCP streams over a single raw IP socket."""
    _RST_THRESHOLD: ClassVar[int] = 3

    def __init__(self, sock_fam: socket.AddressFamily, icmp_proto: int, src: IPAddressType,
                 send_limiter: TokenBucket, loop: asyncio.AbstractEventLoop = None) -> None:
        tcp_sock = socket.socket(sock_fam, socket.SOCK_RAW, socket.IPPROTO_TCP)
        icmp_sock = socket.socket(sock_fam, socket.SOCK_RAW, icmp_proto)
        for sock in (tcp_sock, icmp_sock):
            sock.setblocking(False)
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
        self._send_queue: ("asyncio.Queue[Union[Tuple[Segment, IPAddressType],"
                           "Tuple[Segment, IPAddressType, int]]]") = asyncio.Queue(loop=loop)
        self._send_limiter = send_limiter
        self._sent_rsts: Dict[Tuple[int, bytes, int], int] = {}
        self._loop = loop

    @staticmethod
    def _test_map_key(test: BaseTest[IPAddressType]) -> Tuple[int, bytes, int]:
        # Local address is verified in register_test and handled by OS
        return test.src[1], test.dst[0].packed, test.dst[1]

    def register_test(self, test: BaseTest[IPAddressType]) -> None:
        if test.send_queue is not None:
            raise ValueError("Test is already registered with a multiplexer")
        if test.src[0] != self._src_addr:
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
        remote_src = src_addr.packed
        try:
            seg = Segment.from_bytes(remote_src, self._src_addr.packed, data)
        except ValueError:
            # Discard invalid segments silently
            return
        try:
            self._test_map[(seg.dst_port, remote_src, seg.src_port)].recv_queue.put_nowait(seg)
        except KeyError:
            return self._handle_unk_src(src_addr, seg)

    def _handle_unk_src(self, src_addr: IPAddressType, seg: Segment) -> None:
        # tcpreq always uses ephemeral ports. Don't interfere with other connections.
        if seg.dst_port < 49152 or seg.flags & 0x04:
            return

        # Give up after sending _RST_THRESHOLD resets
        key = (seg.dst_port, src_addr.packed, seg.src_port)
        rsts = self._sent_rsts.get(key, 0)
        if rsts >= self._RST_THRESHOLD:
            return

        rst_seg = seg.make_reply(self._src_addr, src_addr, window=0, seq=-1, ack=True, rst=True)
        self._send_queue.put_nowait((rst_seg, src_addr))
        self._sent_rsts[key] = rsts + 1

    @abstractmethod
    def _handle_icmp_read(self) -> None:
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
                 loop: asyncio.AbstractEventLoop = None) -> None:
        super(IPv4TestMultiplexer, self).__init__(socket.AF_INET, socket.IPPROTO_ICMP,
                                                  src, send_limiter, loop)

        # Enable IP_HDRINCL to modify Identification field in traces
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self._send_next: Optional[Tuple[bytes, Tuple[str, int]]] = None

        if _IS_LINUX:
            # See linux/net/ipv4/raw.c
            allow = (1 << _ICMP_TIME_EXCEEDED)
            self._icmp_sock.setsockopt(socket.IPPROTO_RAW, _ICMP_FILTER,
                                       ~allow & 0xffff_ffff)

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

    def _handle_write(self) -> None:
        # Send segment dequeued last during previous invocation if present
        if self._send_next is not None:
            try:
                self._send_limiter.take()
                self._sock.sendto(*self._send_next)
            except (OutOfTokensError, BlockingIOError):
                return
            else:
                self._send_next = None

        try:
            while True:
                item = self._send_queue.get_nowait()
                dst = (str(item[1]), 0)
                data = bytearray(self._IP_HEAD)
                data[16:20] = item[1].packed
                data.extend(bytes(item[0]))

                if len(item) == 3:
                    # Set TTL
                    data[8] = item[2]

                    # Encode TTL into IHL field + options.
                    # The position of the EOOL option specifies the remainder (0-3).
                    pad_rows, eool_idx = divmod(item[2], 4)
                    pad_rows += 1  # pad_rows must be at least 1 to embed EOOL
                    data[0] = 0x40 | (pad_rows + 5)

                    opts = bytearray(itertools.repeat(0x01, pad_rows * 4))
                    opts[-4 + eool_idx:] = itertools.repeat(0x00, 4 - eool_idx)
                    data[20:20] = opts

                    # Encode TTL into ID field (bits 15-11, 9-5, and 4-0)
                    enc = item[2]
                    enc |= (enc << 11) | (enc << 5)
                    data[4:6] = enc.to_bytes(2, "big")

                self._send_limiter.take()
                self._sock.sendto(data, dst)
        except asyncio.QueueEmpty:
            pass
        except (OutOfTokensError, BlockingIOError):
            self._send_next = (data, dst)


class IPv6TestMultiplexer(BaseTestMultiplexer[IPv6Address]):
    def __init__(self, src: IPv6Address, send_limiter: TokenBucket,
                 loop: asyncio.AbstractEventLoop = None) -> None:
        super(IPv6TestMultiplexer, self).__init__(socket.AF_INET6, _IPPROTO_ICMPV6,
                                                  src, send_limiter, loop)

        self._send_next: Optional[Tuple[bytes, Tuple[str, int], List[Tuple[int, int, bytes]]]] = None  # noqa

        if _IS_LINUX:
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

    def _handle_write(self) -> None:
        # Send segment dequeued last during previous invocation if present
        if self._send_next is not None:
            try:
                msg = self._send_next
                self._send_limiter.take()
                if msg[2]:
                    self._sock.sendmsg((msg[0],), msg[2], address=msg[1])  # type: ignore
                else:
                    self._sock.sendto(msg[0], msg[1])
            except (OutOfTokensError, BlockingIOError):
                return
            else:
                self._send_next = None

        try:
            while True:
                item = self._send_queue.get_nowait()
                dst = (str(item[1]), 0)
                data = bytes(item[0])
                ancil: List[Tuple[int, int, bytes]] = []

                if item[2] is not None:
                    # Set hop limit
                    ancil.append((_IPPROTO_IPV6, socket.IPV6_HOPLIMIT,
                                  item[2].to_bytes(4, sys.byteorder)))

                    # Can't encode TTL into flow label because Linux
                    # requires a lot of internal setup to overwrite it,
                    # which is not available from Python

                if ancil:
                    self._sock.sendmsg((data,), ancil, address=dst)  # type: ignore
                else:
                    self._sock.sendto(data, dst)
        except asyncio.QueueEmpty:
            return
        except (OutOfTokensError, BlockingIOError):
            self._send_next = (data, dst, ancil)
