from abc import abstractmethod
from typing import Generic, Tuple, Optional
import asyncio

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
        self.recv_queue: asyncio.Queue[Segment] = asyncio.Queue(loop=loop)
        self.send_queue: Optional[asyncio.Queue[Tuple[Segment, IPAddressType]]] = None
        self._loop = loop

    async def send(self, seg: Segment) -> None:
        if self.send_queue is None:
            raise RuntimeError("Test is not registered with any multiplexer")
        await self.send_queue.put((seg, self.dst[0]))

    @abstractmethod
    async def run(self) -> None:
        pass
