from typing import Generic, Dict, Tuple, Optional
from ipaddress import IPv4Address, IPv6Address
import socket
import asyncio

from .types import IPAddressType, AnyIPAddress
from .tests import BaseTest
from .tcp import Segment

_AF_INET_MAP = {4: socket.AF_INET, 6: socket.AF_INET6}
# Workaround for missing attributes on Windows (IPv6 has protocol number 41)
_IPPROTO_IPV6: int = getattr(socket, "IPPROTO_IPV6", 41)


class TestMultiplexer(Generic[IPAddressType]):
    """Multiplex multiple TCP streams over a single raw IP socket."""
    def __init__(self, src: IPAddressType, loop: asyncio.AbstractEventLoop = None) -> None:
        sock = socket.socket(_AF_INET_MAP[src.version], socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setblocking(False)
        if sock.family == socket.AF_INET6:
            sock.setsockopt(_IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
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

    def _handle_read_v4(self) -> None:
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

    def _handle_read_v6(self) -> None:
        try:
            while True:
                # Raw IPv6 sockets don't include header
                data, src = self._sock.recvfrom(4096)  # TODO: increase if necessary
                self._enqueue_segment(IPv6Address(src[0]), bytearray(data))
        except BlockingIOError:
            pass

    def _enqueue_segment(self, src_addr: AnyIPAddress, data: bytearray) -> None:
        remote_src = src_addr.packed
        try:
            seg = Segment.from_bytes(remote_src, self._src_addr.packed, data)
            self._recv_queue_map[(seg.dst_port, remote_src, seg.src_port)].put_nowait(seg)
        except (ValueError, KeyError):
            return

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
