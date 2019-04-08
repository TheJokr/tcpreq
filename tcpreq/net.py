from typing import Generic, ClassVar, Dict, Tuple, Optional
from ipaddress import IPv4Address, IPv6Address
import socket
import asyncio

from .types import IPAddressType
from .tests import BaseTest
from .tcp import Segment

_AF_INET_MAP = {4: socket.AF_INET, 6: socket.AF_INET6}
# Workaround for missing attributes on Windows (IPv6 has protocol number 41)
_IPPROTO_IPV6: int = getattr(socket, "IPPROTO_IPV6", 41)


class TestMultiplexer(Generic[IPAddressType]):
    """Multiplex multiple TCP streams over a single raw IP socket."""
    _RST_THRESHOLD: ClassVar[int] = 3

    def __init__(self, src: IPAddressType, loop: asyncio.AbstractEventLoop = None) -> None:
        sock = socket.socket(_AF_INET_MAP[src.version], socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setblocking(False)
        if sock.family == socket.AF_INET6:
            # Raw sockets with protocol set get an EINVAL here. This is caused
            # by the check for a non-zero inet_num socket field in
            # https://github.com/torvalds/linux/blob/v5.0/net/ipv6/ipv6_sockglue.c#L256:L259
            # (probably to avoid changing the option on bound sockets).
            # SOCK_RAW sockets use that field for storing the protocol number though:
            # https://github.com/torvalds/linux/blob/v5.0/net/ipv6/af_inet6.c#L196:L197
            # sock.setsockopt(_IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            read_func = self._handle_read_v6
        else:
            read_func = self._handle_read_v4
        sock.bind((str(src), 0))

        if loop is None:
            loop = asyncio.get_event_loop()
        loop.add_reader(sock.fileno(), read_func)
        loop.add_writer(sock.fileno(), self._handle_write)

        self._sock = sock
        self._src_addr: IPAddressType = src
        self._recv_queue_map: Dict[Tuple[int, bytes, int], "asyncio.Queue[Segment]"] = {}
        self._send_queue: "asyncio.Queue[Tuple[Segment, IPAddressType]]" = asyncio.Queue(loop=loop)
        self._send_next: Optional[Tuple[bytes, Tuple[str, int]]] = None
        self._sent_rsts: Dict[Tuple[int, bytes, int], int] = {}
        self._loop = loop

    @staticmethod
    def _recv_queue_key(test: BaseTest[IPAddressType]) -> Tuple[int, bytes, int]:
        # Local address is verified in register_test and handled by OS
        return test.src[1], test.dst[0].packed, test.dst[1]

    def register_test(self, test: BaseTest[IPAddressType]) -> None:
        if test.send_queue is not None:
            raise ValueError("Test is already registered with a multiplexer")
        if test.src[0] != self._src_addr:
            raise ValueError("Test's source address doesn't match socket's source address")

        test.send_queue = self._send_queue
        self._recv_queue_map[self._recv_queue_key(test)] = test.recv_queue

    def unregister_test(self, test: BaseTest[IPAddressType]) -> None:
        if test.send_queue is not self._send_queue:
            raise ValueError("Test is not registered with this multiplexer")

        del self._recv_queue_map[self._recv_queue_key(test)]
        test.send_queue = None

    def _handle_read_v4(self: "TestMultiplexer[IPv4Address]") -> None:
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

                self._enqueue_segment(IPv4Address(src[0]), data[head_len:])
        except BlockingIOError:
            pass

    def _handle_read_v6(self: "TestMultiplexer[IPv6Address]") -> None:
        try:
            while True:
                # Raw IPv6 sockets don't include header
                data, src = self._sock.recvfrom(4096)  # TODO: increase if necessary
                self._enqueue_segment(IPv6Address(src[0]), bytearray(data))
        except BlockingIOError:
            pass

    def _enqueue_segment(self, src_addr: IPAddressType, data: bytearray) -> None:
        remote_src = src_addr.packed
        try:
            seg = Segment.from_bytes(remote_src, self._src_addr.packed, data)
        except ValueError:
            # Discard invalid segments silently
            return
        try:
            self._recv_queue_map[(seg.dst_port, remote_src, seg.src_port)].put_nowait(seg)
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

    def _handle_write(self) -> None:
        # Send segment dequeued last during previous invocation if present
        if self._send_next is not None:
            try:
                self._sock.sendto(*self._send_next)
            except BlockingIOError:
                return
            else:
                self._send_next = None

        try:
            while True:
                item = self._send_queue.get_nowait()
                data = bytes(item[0])
                dst = (str(item[1]), 0)
                self._sock.sendto(data, dst)
        except asyncio.QueueEmpty:
            pass
        except BlockingIOError:
            self._send_next = (data, dst)
