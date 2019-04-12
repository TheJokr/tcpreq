from abc import abstractmethod
from typing import Generic, ClassVar, Dict, Tuple, Optional
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
        self._send_queue: "asyncio.Queue[Tuple[Segment, IPAddressType]]" = asyncio.Queue(loop=loop)
        self._send_next: Optional[Tuple[bytes, Tuple[str, int]]] = None
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
                data = bytes(item[0])
                dst = (str(item[1]), 0)
                self._send_limiter.take()
                self._sock.sendto(data, dst)
        except asyncio.QueueEmpty:
            pass
        except (OutOfTokensError, BlockingIOError):
            self._send_next = (data, dst)


class IPv4TestMultiplexer(BaseTestMultiplexer[IPv4Address]):
    def __init__(self, src: IPv4Address, send_limiter: TokenBucket,
                 loop: asyncio.AbstractEventLoop = None) -> None:
        super(IPv4TestMultiplexer, self).__init__(socket.AF_INET, socket.IPPROTO_ICMP,
                                                  src, send_limiter, loop)

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


class IPv6TestMultiplexer(BaseTestMultiplexer[IPv6Address]):
    def __init__(self, src: IPv6Address, send_limiter: TokenBucket,
                 loop: asyncio.AbstractEventLoop = None) -> None:
        super(IPv6TestMultiplexer, self).__init__(socket.AF_INET6, _IPPROTO_ICMPV6,
                                                  src, send_limiter, loop)

        # Raw sockets with protocol set get an EINVAL here. This is caused
        # by the check for a non-zero inet_num socket field in
        # https://github.com/torvalds/linux/blob/v5.0/net/ipv6/ipv6_sockglue.c#L256:L259.
        # SOCK_RAW sockets use that field for storing the protocol number:
        # https://github.com/torvalds/linux/blob/v5.0/net/ipv6/af_inet6.c#L196:L197
        # sock.setsockopt(_IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

    def _handle_read(self) -> None:
        try:
            while True:
                # Raw IPv6 sockets don't include header
                data, src = self._sock.recvfrom(4096)  # TODO: increase if necessary
                self._handle_bytes(IPv6Address(src[0]), bytearray(data))
        except BlockingIOError:
            pass
