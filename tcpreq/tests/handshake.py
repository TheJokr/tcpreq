import random

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from ..types import IPAddressType
from ..tcp import Segment


class HandshakeTest(BaseTest[IPAddressType]):
    """Test a target's responsiveness with a typical handshake."""
    __slots__ = ()

    async def run(self) -> TestResult:
        cur_seq = random.randint(0, 0xffff_ffff)
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=30720, syn=True))

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=60, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res

        await self.send(syn_res.make_reply(self.src, self.dst, window=30720, ack=True))
        await self.send(syn_res.make_reset(self.src, self.dst))
        return TestResult(self, TEST_PASS)
