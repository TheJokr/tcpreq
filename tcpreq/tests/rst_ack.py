import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from ..tcp import Segment


class RSTACKTest(BaseTest):
    async def run(self) -> TestResult:
        cur_seq = random.randrange(0, 1 << 32)
        syn_seg = Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True)
        await self.send(syn_seg)
        del syn_seg

        result = None
        cur_seq = (cur_seq + 1) % 0x1_0000_0000
        try:
            # TODO: change timeout?
            syn_res = await self.receive(timeout=30)
        except asyncio.TimeoutError:
            return TestResult(TEST_UNK, 1, "Timeout during handshake")
        if syn_res.flags & 0x04 and syn_res.ack_seq == cur_seq:
            return TestResult(TEST_UNK, 1, "RST in reply to SYN during handshake")
        elif (syn_res.flags & 0x12) != 0x12:
            result = TestResult(TEST_FAIL, 1, "Non-SYN-ACK in reply to SYN during handshake")
        elif syn_res.ack_seq != cur_seq:
            result = TestResult(TEST_FAIL, 1, "Wrong SEQ acked in reply to SYN during handshake")

        if result is not None:
            # Reset connection to be sure
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return result

        rstack_seg = syn_res.make_reply(self.src[0], self.dst[0], window=0, seq=-1, ack=True, rst=True)
        await self.send(rstack_seg)

        try:
            # TODO: change timeout?
            rstack_res = await self.receive(timeout=60)
        except asyncio.TimeoutError:
            return TestResult(TEST_PASS)
        if rstack_res.flags & 0x04 and rstack_res.seq == rstack_seg.ack_seq:
            return TestResult(TEST_PASS)

        # RST-ACK ignored; send non-ACK RST
        await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
        return TestResult(TEST_FAIL, 1, "RST-ACK ignored")
