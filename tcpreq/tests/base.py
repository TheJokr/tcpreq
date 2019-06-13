from abc import abstractmethod
from typing import Generic, ClassVar, Awaitable, List, Tuple, Union, Optional
import time
import math
import asyncio

from .result import TestResult, TEST_UNK, TEST_FAIL
from ..types import IPAddressType, ScanHost
from ..tcp import Segment


class BaseTest(Generic[IPAddressType]):
    """Abstract base class for all tests."""
    _HOP_LIMIT: ClassVar[int] = 20

    # Make sure _HOP_LIMIT fits into 5 bits (to save it in the IPv4 ID field 3 times).
    assert math.floor(math.log2(_HOP_LIMIT) + 1) <= 5
    # Make sure _HOP_LIMIT can be encoded into IHL+options (39 possible non-zero values).
    assert _HOP_LIMIT <= 39

    __slots__ = ("src", "dst", "recv_queue", "quote_queue", "send_queue", "_loop")

    def __init__(self, src: ScanHost[IPAddressType], dst: ScanHost[IPAddressType],
                 loop: asyncio.AbstractEventLoop = None) -> None:
        if loop is None:
            loop = asyncio.get_event_loop()

        self.src: ScanHost[IPAddressType] = src
        self.dst: ScanHost[IPAddressType] = dst
        self.recv_queue: "asyncio.Queue[bytearray]" = asyncio.Queue(loop=loop)
        self.quote_queue: List[Tuple[bytes, int, bytes]] = []
        self.send_queue: Optional["asyncio.Queue[Union[Tuple[Segment, IPAddressType],"
                                  "Tuple[Segment, IPAddressType, int]]]"] = None
        self._loop = loop

    def send(self, seg: Segment, ttl: int = None) -> Awaitable[None]:
        assert self.send_queue is not None, "Test is not registered with any multiplexer"
        if ttl is None:
            return self.send_queue.put((seg, self.dst.ip))

        assert 1 <= ttl <= self._HOP_LIMIT
        return self.send_queue.put((seg, self.dst.ip, ttl))

    async def receive(self, timeout: float) -> Segment:
        while timeout > 0:
            start = time.monotonic()
            data = await asyncio.wait_for(self.recv_queue.get(), timeout, loop=self._loop)
            timeout -= (time.monotonic() - start)

            try:
                return Segment.from_bytes(self.dst.ip.packed, self.src.ip.packed, data)
            except ValueError:
                # Discard invalid segments silently and retry
                pass

        raise asyncio.TimeoutError()

    async def _synchronize(self, sent_seq: int, timeout: float,
                           test_stage: int) -> Union[Segment, TestResult]:
        # Simultaneous open is not supported (targets are listening hosts)
        exp_ack = (sent_seq + 1) % 0x1_0000_0000
        try:
            syn_res = await self.receive(timeout=timeout)
        except asyncio.TimeoutError:
            return TestResult(self, TEST_UNK, test_stage, "Timeout during handshake")
        if syn_res.flags & 0x04 and syn_res.ack_seq == exp_ack:
            return TestResult(self, TEST_UNK, test_stage, "RST in reply to SYN during handshake")
        elif (syn_res.flags & 0x12) != 0x12:
            result = TestResult(self, TEST_FAIL, test_stage,
                                "Non-SYN-ACK in reply to SYN during handshake")
        elif syn_res.ack_seq != exp_ack:
            result = TestResult(self, TEST_FAIL, test_stage,
                                "Wrong SEQ acked in reply to SYN during handshake")
        else:
            return syn_res

        # Reset connection to be sure
        await self.send(syn_res.make_reset(self.src, self.dst))
        return result

    @abstractmethod
    async def run(self) -> TestResult:
        pass
