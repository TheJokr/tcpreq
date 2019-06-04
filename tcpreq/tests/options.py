from typing import ClassVar, Awaitable, List, Optional
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..tcp import Segment, noop_option, end_of_options
from ..tcp.options import BaseOption, SizedOption, parse_options


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
            reason += " (header option(s) deleted)"
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

        opts = bytearray(quote[20:head_len])
        try:
            if {noop_option, end_of_options}.issubset(parse_options(opts)):
                return None
        except ValueError:
            pass

        return decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=True, ack=True, up=True, opts=False)


class UnknownOptionTest(BaseTest):
    """Test whether unknown options are ignored silently."""
    # Option kind 158 is currently reserved
    # See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
    _UNK_OPT: ClassVar[SizedOption] = SizedOption(158, b"\x58\xfa\x89")

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

        # Test whether unknown option is ignored
        # Option kind 158 is currently reserved
        # See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
        cur_seq = (cur_seq + 2048) % 0x1_0000_000
        opts = (self._UNK_OPT,)
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
            syn_res.reason += " with unknown option"  # type: ignore
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
            reason += " (unknown header option deleted)"
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

        opts = bytearray(quote[20:head_len])
        try:
            if self._UNK_OPT in parse_options(opts):
                return None
        except ValueError:
            pass

        return decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=True, ack=True, up=True, opts=False)


class IllegalLengthOptionTest(BaseTest):
    """Verify responsiveness after sending an option with illegal length."""
    # Option kind 2 is assigned to MSS
    # See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
    _ILLEGAL_OPT: ClassVar[BaseOption] = BaseOption(b"\x02\x00\x02\xf1")

    __slots__ = ()

    async def run(self) -> TestResult:
        cur_seq = random.randint(0, 0xffff_ffff)
        opts = (self._ILLEGAL_OPT,)
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

        cur_seq = (cur_seq + 1) % 0x1_0000_0000
        try:
            # TODO: change timeout?
            syn_res = await self.receive(timeout=30)
        except asyncio.TimeoutError:
            result = None
        else:
            if syn_res.flags & 0x04 and syn_res.ack_seq == cur_seq:
                result = TestResult(self, TEST_PASS)
            elif (syn_res.flags & 0x12) != 0x12:
                result = TestResult(self, TEST_FAIL, 1,
                                    "Non-SYN-ACK in reply to SYN during handshake")
            elif syn_res.ack_seq != cur_seq:
                result = TestResult(self, TEST_FAIL, 1,
                                    "Wrong SEQ acked in reply to SYN during handshake")
            else:
                result = TestResult(self, TEST_PASS)

        if result is not None and result.status is not TEST_PASS:
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return result

        await asyncio.sleep(10, loop=self._loop)
        res_stat = 0
        hops = filter(None, (self._check_quote(*item) for item in self.quote_queue))
        for mbox_hop in hops:
            if mbox_hop == 0 and res_stat >= 1:
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (illegal header option deleted)"
            result = TestResult(self, TEST_UNK, 1, reason.format(mbox_hop))

            if mbox_hop > 0:
                break
            else:
                res_stat = 1
        del res_stat, hops

        if result is not None:
            if result.status is TEST_PASS and not (syn_res.flags & 0x04):
                await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return result

        # No response to SYN with illegal option length and no modifications along the path
        # Test responsiveness to regular SYN
        # 0x1fffd == 2 * 0xffff - 1
        cur_seq = (cur_seq + 0x1fffd) % 0x1_0000_000
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True))

        cur_seq = (cur_seq + 1) % 0x1_0000_000
        try:
            # TODO: change timeout?
            syn_res = await self.receive(timeout=30)
        except asyncio.TimeoutError:
            # TODO: reclassify as TEST_UNK?
            return TestResult(self, TEST_FAIL, 2, "Timeout during handshake")
        if syn_res.flags & 0x04 and syn_res.ack_seq == cur_seq:
            return TestResult(self, TEST_PASS)
        elif (syn_res.flags & 0x12) != 0x12:
            result = TestResult(self, TEST_FAIL, 2, "Non-SYN-ACK in reply to SYN during handshake")
        elif syn_res.ack_seq != cur_seq:
            result = TestResult(self, TEST_FAIL, 2, "Wrong SEQ acked in reply to SYN during handshake")
        else:
            result = TestResult(self, TEST_PASS)

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

        opts = bytearray(quote[20:head_len])
        try:
            for _ in parse_options(opts):
                pass
        except ValueError:
            # parse_options should fail on parsing _ILLEGAL_OPT
            if opts[:4] == bytes(self._ILLEGAL_OPT):
                return None

        return decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=True, ack=True, up=True, opts=False)
