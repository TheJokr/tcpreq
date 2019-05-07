from abc import abstractmethod
from typing import Generic, ClassVar, Awaitable, List, Tuple, Union, Optional
import time
import math
import asyncio

from .result import TestResult
from ..types import IPAddressType
from ..tcp import Segment


class BaseTest(Generic[IPAddressType]):
    """Abstract base class for all tests."""
    _HOP_LIMIT: ClassVar[int] = 20

    # Make sure _HOP_LIMIT fits into 5 bits (to save it in the IPv4 ID field 3 times).
    assert math.floor(math.log2(_HOP_LIMIT) + 1) <= 5
    # Make sure _HOP_LIMIT can be encoded into IHL+options (39 possible non-zero values).
    assert _HOP_LIMIT <= 39

    __slots__ = ("src", "dst", "recv_queue", "quote_queue", "send_queue", "_loop")

    def __init__(self, src: Tuple[IPAddressType, int], dst: Tuple[IPAddressType, int],
                 loop: asyncio.AbstractEventLoop = None) -> None:
        if loop is None:
            loop = asyncio.get_event_loop()

        self.src: Tuple[IPAddressType, int] = src
        self.dst: Tuple[IPAddressType, int] = dst
        self.recv_queue: "asyncio.Queue[bytearray]" = asyncio.Queue(loop=loop)
        self.quote_queue: List[Tuple[bytes, int, bytes]] = []
        self.send_queue: Optional["asyncio.Queue[Union[Tuple[Segment, IPAddressType],"
                                  "Tuple[Segment, IPAddressType, int]]]"] = None
        self._loop = loop

    def send(self, seg: Segment, ttl: int = None) -> Awaitable[None]:
        assert self.send_queue is not None, "Test is not registered with any multiplexer"
        if ttl is None:
            return self.send_queue.put((seg, self.dst[0]))

        assert 1 <= ttl <= self._HOP_LIMIT
        return self.send_queue.put((seg, self.dst[0], ttl))

    async def receive(self, timeout: float) -> Segment:
        while timeout > 0:
            start = time.monotonic()
            data = await asyncio.wait_for(self.recv_queue.get(), timeout, loop=self._loop)
            timeout -= (time.monotonic() - start)

            try:
                return Segment.from_bytes(self.dst[0].packed, self.src[0].packed, data)
            except ValueError:
                # Discard invalid segments silently and retry
                pass

        raise asyncio.TimeoutError()

    @abstractmethod
    async def run(self) -> TestResult:
        pass
