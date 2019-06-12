from typing import ClassVar, Awaitable, List, Optional
import random
import asyncio
from ipaddress import IPv4Address

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..tcp import Segment, MSSOption
from ..tcp.options import parse_options
from ..alp import PORT_MAP as ALP_MAP


class MSSSupportTest(BaseTest):
    """Verify support for the MSS option."""
    # See "Measuring the Evolution of Transport Protocols in the Internet"
    # for measurements on minimum accepted MSS values
    _MSS_OPT: ClassVar[MSSOption] = MSSOption(256)

    __slots__ = ()

    async def run(self) -> TestResult:
        if self.dst[1] not in ALP_MAP:
            return TestResult(self, TEST_UNK, 0, "Missing ALP module for port {}".format(self.dst[1]))

        cur_seq = random.randint(0, 0xffff_ffff)
        opts = (self._MSS_OPT,)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, window=0xffff, syn=True,  # type: ignore
                        options=opts, **encode_ttl(ttl, win=False, ack=True, up=True, opts=False)),
                ttl=ttl
            ))
        del opts
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res
        elif len(syn_res) > 276:
            result: Optional[TestResult] = TestResult(self, TEST_FAIL, 1, "Segment too large")
        else:
            result = None

        await asyncio.sleep(10, loop=self._loop)
        res_stat = 0
        hops = (i for i in (self._check_quote(*item) for item in self.quote_queue) if i is not None)
        for mbox_hop in hops:
            if mbox_hop == 0 and res_stat >= 1:
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (MSS modified or deleted)"
            result = TestResult(self, TEST_UNK, 1, reason.format(mbox_hop))

            if mbox_hop > 0:
                break
            else:
                res_stat = 1
        del res_stat, hops

        if result is not None:
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        # TODO: multiple flights?
        alp = ALP_MAP[self.dst[1]](self.src, self.dst)
        req = alp.pull_data(256)
        if req is None:
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return TestResult(self, TEST_UNK, 1, "No ALP data available")

        await self.send(syn_res.make_reply(self.src[0], self.dst[0], window=0xffff, ack=True, payload=req))
        del req

        # Check received segment sizes
        seg = syn_res
        result = TestResult(self, TEST_PASS)
        await asyncio.sleep(30, loop=self._loop)
        while True:
            try:
                seg = Segment.from_bytes(self.dst[0].packed, self.src[0].packed,
                                         self.recv_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
            except ValueError:
                # Silently ignore invalid segments
                pass
            else:
                if len(seg) > 276:
                    result = TestResult(self, TEST_FAIL, 1, "Segment too large")
                    break

        await self.send(seg.make_reset(self.src[0], self.dst[0]))
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

        found = False
        opts = bytearray(quote[20:head_len])
        try:
            for opt in parse_options(opts):
                if isinstance(opt, MSSOption):
                    if opt == MSSOption:
                        found = True
                    else:
                        break
        except ValueError:
            pass

        return (None if found else
                decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=False, ack=True, up=True, opts=False))


class MissingMSSTest(BaseTest):
    """Check fallback MSS value for validity."""
    __slots__ = ()

    async def run(self) -> TestResult:
        if self.dst[1] not in ALP_MAP:
            return TestResult(self, TEST_UNK, 0, "Missing ALP module for port {}".format(self.dst[1]))

        # Defaults defined in RFC 793bis
        if isinstance(self.dst[0], IPv4Address):
            seg_max_len = 536 + 20
        else:
            seg_max_len = 1220 + 20

        cur_seq = random.randint(0, 0xffff_ffff)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, window=0xffff, syn=True,  # type: ignore
                        **encode_ttl(ttl, win=False, ack=True, up=True, opts=True)),
                ttl=ttl
            ))
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res
        elif len(syn_res) > seg_max_len:
            result: Optional[TestResult] = TestResult(self, TEST_FAIL, 1, "Segment too large")
        else:
            result = None

        await asyncio.sleep(10, loop=self._loop)
        res_stat = 0
        hops = (i for i in (self._check_quote(*item) for item in self.quote_queue) if i is not None)
        for mbox_hop in hops:
            if mbox_hop == 0 and res_stat >= 1:
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (MSS inserted)"
            result = TestResult(self, TEST_UNK, 1, reason.format(mbox_hop))

            if mbox_hop > 0:
                break
            else:
                res_stat = 1
        del res_stat, hops

        if result is not None:
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        # TODO: multiple flights?
        alp = ALP_MAP[self.dst[1]](self.src, self.dst)
        req = alp.pull_data(seg_max_len)
        if req is None:
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return TestResult(self, TEST_UNK, 1, "No ALP data available")

        await self.send(syn_res.make_reply(self.src[0], self.dst[0], window=0xffff, ack=True, payload=req))
        del req

        # Check received segment sizes
        seg = syn_res
        result = TestResult(self, TEST_PASS)
        await asyncio.sleep(30, loop=self._loop)
        while True:
            try:
                seg = Segment.from_bytes(self.dst[0].packed, self.src[0].packed,
                                         self.recv_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
            except ValueError:
                # Silently ignore invalid segments
                pass
            else:
                if len(seg) > seg_max_len:
                    result = TestResult(self, TEST_FAIL, 1, "Segment too large")
                    break

        await self.send(seg.make_reset(self.src[0], self.dst[0]))
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
            if all(not isinstance(opt, MSSOption) for opt in parse_options(opts)):
                return None
        except ValueError:
            pass

        return decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=False, ack=True, up=True, opts=True)


# Derive from MSSSupportTest to avoid duplicating _check_quote
# TODO: Factor common part into base class for both MSSSupportTest and LateOptionTest
class LateOptionTest(MSSSupportTest):
    """Test response to MSS option delivered after the 3WH."""
    __slots__ = ()

    async def run(self) -> TestResult:
        if self.dst[1] not in ALP_MAP:
            return TestResult(self, TEST_UNK, 0, "Missing ALP module for port {}".format(self.dst[1]))

        cur_seq = random.randint(0, 0xffff_ffff)
        opts = (self._MSS_OPT,)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, window=0xffff, syn=True,  # type: ignore
                        options=opts, **encode_ttl(ttl, win=False, ack=True, up=True, opts=False)),
                ttl=ttl
            ))
        del opts
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res
        elif len(syn_res) > 276:
            result: Optional[TestResult] = TestResult(self, TEST_FAIL, 1, "Segment too large")
        else:
            result = None

        await asyncio.sleep(10, loop=self._loop)
        res_stat = 0
        hops = (i for i in (self._check_quote(*item) for item in self.quote_queue) if i is not None)
        for mbox_hop in hops:
            if mbox_hop == 0 and res_stat >= 1:
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (MSS modified or deleted)"
            result = TestResult(self, TEST_UNK, 1, reason.format(mbox_hop))

            if mbox_hop > 0:
                break
            else:
                res_stat = 1
        del res_stat, hops

        if result is not None:
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        # TODO: multiple flights?
        alp = ALP_MAP[self.dst[1]](self.src, self.dst)
        req = alp.pull_data(256)
        if req is None:
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return TestResult(self, TEST_UNK, 1, "No ALP data available")

        # Path interference check above should cover this too
        await self.send(syn_res.make_reply(self.src[0], self.dst[0], window=0xffff, ack=True,
                                           options=(MSSOption(512),), payload=req))
        del req

        # Check received segment sizes
        seg = syn_res
        result = TestResult(self, TEST_PASS)
        await asyncio.sleep(30, loop=self._loop)
        while True:
            try:
                seg = Segment.from_bytes(self.dst[0].packed, self.src[0].packed,
                                         self.recv_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
            except ValueError:
                # Silently ignore invalid segments
                pass
            else:
                # The only invalid way to respond to this late MSS is by processing it
                # This would lead to bigger segments being received
                if len(seg) > 276:
                    result = TestResult(self, TEST_FAIL, 1, "Segment too large")
                    break

        await self.send(seg.make_reset(self.src[0], self.dst[0]))
        return result
