import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from ..tcp import Segment


class RSTACKTest(BaseTest):
    """Test response to resets with the ACK flag set."""
    __slots__ = ()

    async def run(self) -> TestResult:
        cur_seq = random.randint(0, 0xffff_ffff)
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True))

        # TODO: change timeout?
        syn_res = await self.synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res

        rstack_seg = syn_res.make_reply(self.src[0], self.dst[0], window=0, seq=-1, ack=True, rst=True)
        await self.send(rstack_seg)

        try:
            # TODO: change timeout?
            rstack_res = await self.receive(timeout=60)
        except asyncio.TimeoutError:
            return TestResult(self, TEST_PASS)
        if rstack_res.flags & 0x04 and rstack_res.seq == rstack_seg.ack_seq:
            return TestResult(self, TEST_PASS)

        # RST-ACK ignored; send non-ACK RST
        await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
        return TestResult(self, TEST_FAIL, 1, "RST-ACK ignored")
