from abc import abstractmethod
from typing import Generic, Awaitable, Tuple, Union, Optional
import asyncio

from .result import TestResult
from ..types import IPAddressType
from ..tcp import Segment


class BaseTest(Generic[IPAddressType]):
    """Abstract base class for all tests."""
    def __init__(self, src: Tuple[IPAddressType, int], dst: Tuple[IPAddressType, int],
                 loop: asyncio.AbstractEventLoop = None) -> None:
        if loop is None:
            loop = asyncio.get_event_loop()

        self.src: Tuple[IPAddressType, int] = src
        self.dst: Tuple[IPAddressType, int] = dst
        self.recv_queue: "asyncio.Queue[Segment]" = asyncio.Queue(loop=loop)
        self.send_queue: Optional["asyncio.Queue[Union[Tuple[Segment, IPAddressType],"
                                  "Tuple[Segment, IPAddressType, int]]]"] = None
        self._loop = loop

    def send(self, seg: Segment) -> Awaitable[None]:
        if self.send_queue is None:
            raise RuntimeError("Test is not registered with any multiplexer")
        return self.send_queue.put((seg, self.dst[0]))

    def receive(self, timeout: float) -> Awaitable[Segment]:
        return asyncio.wait_for(self.recv_queue.get(), timeout, loop=self._loop)

    @abstractmethod
    async def run(self) -> TestResult:
        pass
