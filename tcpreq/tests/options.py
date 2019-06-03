from typing import Awaitable, List, Optional
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..tcp import Segment, noop_option, end_of_options
from ..tcp.options import SizedOption


class OptionSupportTest(BaseTest):
    """Verify support for the two legacy options."""
    __slots__ = ()

    async def run(self) -> TestResult:
        # Test responsiveness without any options
        cur_seq = random.randint(0, 0xffff_ffff)
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True))

        # TODO: change timeout?
        syn_res = await self.synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res

        await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
        del syn_res

        self.recv_queue = asyncio.Queue(loop=self._loop)
        await asyncio.sleep(10, loop=self._loop)
        if not self.recv_queue.empty():
            # TODO: retransmit RST?
            return TestResult(self, TEST_UNK, 1, "RST ignored")

        # Test responsiveness with noop and eool options
        cur_seq = (cur_seq + 2048) % 0x1_0000_000
        opts = (noop_option, noop_option, end_of_options)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, syn=True, options=opts,  # type: ignore
                        **encode_ttl(ttl, win=True, ack=True, up=True, opts=False)),
                ttl=ttl
            ))
        del opts
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self.synchronize(cur_seq, timeout=30, test_stage=2)
        if isinstance(syn_res, TestResult):
            syn_res.status = TEST_FAIL
            syn_res.reason += " with options"  # type: ignore
            return syn_res

        await asyncio.sleep(10, loop=self._loop)
        result = TestResult(self, TEST_PASS)
        res_stat = 0
        hops = filter(None, (self._check_quote(*item) for item in self.quote_queue))
        for mbox_hop in hops:
            if mbox_hop == 0 and res_stat >= 1:
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (header options modified)"
            result = TestResult(self, TEST_UNK, 2, reason.format(mbox_hop))

            if mbox_hop > 0:
                break
            else:
                res_stat = 1
        del res_stat, hops

        await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
        return result

    def _check_quote(self, src_addr: bytes, ttl_guess: int, quote: bytes) -> Optional[int]:
        qlen = len(quote)
        if qlen < 20:
            # Header options not included in quote
            return None

        head_len = (quote[12] >> 2) & 0b00111100
        if qlen < head_len:
            # Header options not included in quote
            return None

        # TODO: allow modifications as long as noop and eool are included?
        if head_len == 24 and quote[20:24] == b"\x01\x01\x00\x00":
            return None

        return decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=True, ack=True, up=True, opts=False)


class UnknownOptionTest(BaseTest):
    """Test whether unknown options are ignored silently."""
    __slots__ = ()

    async def run(self) -> TestResult:
        # Option kind 158 is currently reserved
        # See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
        cur_seq = random.randint(0, 0xffff_ffff)
        opts = (SizedOption(158, b"\x58\xfa\x89"),)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, syn=True, options=opts,  # type: ignore
                        **encode_ttl(ttl, win=True, ack=True, up=True, opts=False)),
                ttl=ttl
            ))
        del opts
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self.synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res

        await asyncio.sleep(10, loop=self._loop)
        result = TestResult(self, TEST_PASS)
        res_stat = 0
        hops = filter(None, (self._check_quote(*item) for item in self.quote_queue))
        for mbox_hop in hops:
            if mbox_hop == 0 and res_stat >= 1:
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (header options modified)"
            result = TestResult(self, TEST_UNK, 2, reason.format(mbox_hop))

            if mbox_hop > 0:
                break
            else:
                res_stat = 1
        del res_stat, hops

        await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
        return result

    def _check_quote(self, src_addr: bytes, ttl_guess: int, quote: bytes) -> Optional[int]:
        qlen = len(quote)
        if qlen < 20:
            # Header options not included in quote
            return None

        head_len = (quote[12] >> 2) & 0b00111100
        if qlen < head_len:
            # Header options not included in quote
            return None

        # TODO: allow modifications as long as unknown option is included?
        if head_len == 28 and quote[20:28] == b"\x9e\x03\x58\xfa\x89\x00\x00\x00":
            return None

        return decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=True, ack=True, up=True, opts=False)
