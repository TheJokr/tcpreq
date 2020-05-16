import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from ..types import IPAddressType
from ..tcp import Segment


class RSTACKTest(BaseTest[IPAddressType]):
    """Test response to resets with the ACK flag set."""
    # Assuming instant responses, i.e., no waiting
    MAX_PACKET_RATE = 3 / 10.0

    __slots__ = ()

    async def run(self) -> TestResult:
        # Establish connection
        cur_seq = random.randint(0, 0xffff_ffff)
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True))

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res

        # Try RST using RST-ACK segment
        rstack_seg = syn_res.make_reply(self.src, self.dst, window=0, seq=-1, ack=True, rst=True)
        await self.send(rstack_seg)

        await asyncio.sleep(10, loop=self._loop)
        self.recv_queue = asyncio.Queue(loop=self._loop)
        try:
            # TODO: change timeout?
            rstack_res = await self.receive(timeout=60)
        except asyncio.TimeoutError:
            return TestResult(self, TEST_PASS)
        if rstack_res.flags & 0x04 and rstack_res.seq == rstack_seg.ack_seq:
            return TestResult(self, TEST_PASS)

        # RST-ACK ignored; send non-ACK RST
        await self.send(syn_res.make_reset(self.src, self.dst))
        return TestResult(self, TEST_FAIL, 1, "RST-ACK ignored")
