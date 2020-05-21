import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from ..types import IPAddressType
from ..tcp import Segment


class LivenessTest(BaseTest[IPAddressType]):
    """Test liveness by means of a standard three-way handshake."""
    # No explicit sleeps in this test, but the test loop
    # will always wait for 3 seconds between tests
    MAX_PACKET_RATE = 3 / 3.0
    FAIL_EARLY = True

    __slots__ = ()

    async def run(self) -> TestResult:
        # Try opening the connection up to 3 times
        cur_seq = random.randint(0, 0xffff_ffff)
        syn_seg = Segment(self.src, self.dst, seq=cur_seq, window=30720, syn=True)
        for _ in range(3):
            await self.send(syn_seg, ttl=self._HOP_LIMIT)

            # TODO: change timeout?
            syn_res = await self._synchronize(cur_seq, timeout=20, test_stage=0)
            if isinstance(syn_res, Segment):
                break
        else:
            # Skipped in case of break -> syn_res must be TestResult instance
            # Invert status code: self._synchronize returns UNK for unreachable
            # hosts and FAIL for non-conformat three-way handshakes
            assert isinstance(syn_res, TestResult)
            syn_res.status = TEST_FAIL if syn_res.status is TEST_UNK else TEST_PASS
            syn_res.stage = None
            return syn_res

        await self.send(syn_res.make_reply(self.src, self.dst, window=30720, ack=True))

        # Try closing the connection up to 3 times
        rst_seg = syn_res.make_reset(self.src, self.dst)
        for _ in range(3):
            await self.send(rst_seg)
            await asyncio.sleep(5, loop=self._loop)
            self.recv_queue = asyncio.Queue(loop=self._loop)

            try:
                await self.receive(timeout=10)
            except asyncio.TimeoutError:
                break
        else:
            return TestResult(self, TEST_FAIL, None, "RSTs ignored")

        return TestResult(self, TEST_PASS)
