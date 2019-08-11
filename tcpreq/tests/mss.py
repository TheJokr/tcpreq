from typing import ClassVar, Awaitable, List, Tuple, Optional
import random
import asyncio
from ipaddress import IPv4Address

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..types import IPAddressType
from ..tcp import Segment, MSSOption
from ..tcp.options import parse_options
from ..alp import ALP_MAP


class MSSSupportTest(BaseTest[IPAddressType]):
    """Verify support for the MSS option."""
    # See "Measuring the Evolution of Transport Protocols in the Internet"
    # for measurements on minimum accepted MSS values
    _SYN_OPTS: ClassVar[Tuple[MSSOption, ...]] = (MSSOption(256),)
    _REQ_OPTS: ClassVar[Tuple[MSSOption, ...]] = ()

    __slots__ = ()

    # Code shared between MSSSupportTest and LateOptionTest
    async def run(self) -> TestResult:
        if self.dst.port not in ALP_MAP:
            return TestResult(self, TEST_UNK, 0, "Missing ALP module for port {}".format(self.dst.port))

        cur_seq = random.randint(0, 0xffff_ffff)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, window=0xffff, syn=True,  # type: ignore
                        options=self._SYN_OPTS, **encode_ttl(ttl, win=False, ack=True, up=True, opts=False)),
                ttl=ttl
            ))
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult) and syn_res.status is TEST_UNK:
            # Retry synchronization without encoding/segment burst
            await self.send(Segment(self.src, self.dst, seq=cur_seq,
                                    window=0xffff, syn=True, options=self._SYN_OPTS))
            syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            syn_res.status = TEST_FAIL
            syn_res.reason += " with MSS option"  # type: ignore
            return syn_res

        await self.send(syn_res.make_reply(self.src, self.dst, window=0xffff, ack=True))
        await asyncio.sleep(10, loop=self._loop)

        result = None if len(syn_res) <= 276 else TestResult(self, TEST_FAIL, 1, "Segment too large")
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
            await self.send(syn_res.make_reset(self.src, self.dst))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        # TODO: multiple flights?
        alp = ALP_MAP[self.dst.port](self.src, self.dst)
        req = alp.pull_data(200)
        if req is None or len(req) > 1460:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return TestResult(self, TEST_UNK, 1, "ALP data unavailable")

        # Path interference check above should cover this too
        await self.send(syn_res.make_reply(self.src, self.dst, window=0xffff, ack=True,
                                           options=self._REQ_OPTS, payload=req))
        del req

        # Check received segment sizes
        seg = syn_res
        result = TestResult(self, TEST_PASS)
        await asyncio.sleep(30, loop=self._loop)
        while True:
            try:
                seg = Segment.from_bytes(self.dst.ip.packed, self.src.ip.packed,
                                         self.recv_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
            except ValueError:
                # Silently ignore invalid segments
                pass
            else:
                # The only invalid way to respond to the (optional) late MSS
                # is by processing it. This would lead to bigger segments being received
                if len(seg) > 276:
                    result = TestResult(self, TEST_FAIL, 1, "Segment too large")
                    break

        await self.send(seg.make_reset(self.src, self.dst))
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

        idx = 0
        max_idx = len(self._SYN_OPTS) - 1
        found = False
        opts = bytearray(quote[20:head_len])
        try:
            for opt in parse_options(opts):
                if isinstance(opt, MSSOption):
                    if not found and opt == self._SYN_OPTS[idx]:
                        if idx == max_idx:
                            found = True
                        else:
                            idx += 1
                    else:
                        found = False
                        break
        except ValueError:
            pass

        return (None if found else
                decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=False, ack=True, up=True, opts=False))


class MissingMSSTest(BaseTest[IPAddressType]):
    """Check fallback MSS value for validity."""
    __slots__ = ()

    async def run(self) -> TestResult:
        if self.dst.port not in ALP_MAP:
            return TestResult(self, TEST_UNK, 0, "Missing ALP module for port {}".format(self.dst.port))

        # Defaults defined in RFC 793bis
        if isinstance(self.dst.ip, IPv4Address):
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
        if isinstance(syn_res, TestResult) and syn_res.status is TEST_UNK:
            # Retry synchronization without encoding/segment burst
            await self.send(Segment(self.src, self.dst, seq=cur_seq, window=0xffff, syn=True))
            syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res

        await self.send(syn_res.make_reply(self.src, self.dst, window=0xffff, ack=True))
        await asyncio.sleep(10, loop=self._loop)

        result = (None if len(syn_res) <= seg_max_len else
                  TestResult(self, TEST_FAIL, 1, "Segment too large"))
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
            await self.send(syn_res.make_reset(self.src, self.dst))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        # TODO: multiple flights?
        alp = ALP_MAP[self.dst.port](self.src, self.dst)
        req = alp.pull_data(seg_max_len - 40)
        if req is None or len(req) > 1460:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return TestResult(self, TEST_UNK, 1, "ALP data unavailable")

        await self.send(syn_res.make_reply(self.src, self.dst, window=0xffff, ack=True, payload=req))
        del req

        # Check received segment sizes
        seg = syn_res
        result = TestResult(self, TEST_PASS)
        await asyncio.sleep(30, loop=self._loop)
        while True:
            try:
                seg = Segment.from_bytes(self.dst.ip.packed, self.src.ip.packed,
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

        await self.send(seg.make_reset(self.src, self.dst))
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
            if not any(isinstance(opt, MSSOption) for opt in parse_options(opts)):
                return None
        except ValueError:
            pass

        return decode_ttl(quote, ttl_guess, self._HOP_LIMIT, win=False, ack=True, up=True, opts=True)


# Derive from MSSSupportTest to avoid code duplication
class LateOptionTest(MSSSupportTest[IPAddressType]):
    """Test response to MSS option delivered after the 3WH."""
    _REQ_OPTS = (MSSOption(512),)

    __slots__ = ()
