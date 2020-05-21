from typing import ClassVar, Awaitable, List, Tuple, Optional
import random
import asyncio
from ipaddress import IPv4Address

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..types import IPAddressType, ICMPQuote
from ..tcp import Segment, MSSOption
from ..tcp.options import parse_options
from ..alp import ALP_MAP


class MSSSupportTest(BaseTest[IPAddressType]):
    """Verify support for the MSS option."""
    # Assuming instant responses, i.e., no waiting
    MAX_PACKET_RATE = (BaseTest._HOP_LIMIT + 4) / 10.0

    # See "Measuring the Evolution of Transport Protocols in the Internet"
    # for measurements on minimum accepted MSS values
    # Update: CVE-2019-11477/11478/11479 makes testing with MSS <500 bytes infeasible
    _SYN_OPTS: ClassVar[Tuple[MSSOption, ...]] = (MSSOption(515),)
    _REQ_OPTS: ClassVar[Tuple[MSSOption, ...]] = ()

    __slots__ = ()

    async def run(self) -> TestResult:
        if self.dst.port not in ALP_MAP:
            return TestResult(self, TEST_UNK, 0, f"Missing ALP module for port {self.dst.port}")

        # Establish connection with specific MSS option(s)
        cur_seq = random.randint(0, 0xffff_ffff)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, window=0xffff,
                        syn=True, options=self._SYN_OPTS,
                        **encode_ttl(ttl, win=False, ack=True, up=True, opts=False)),  # type: ignore
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

        # Finish 3WH, if applicable
        if isinstance(syn_res, TestResult):
            syn_res.status = TEST_FAIL
            syn_res.reason += " with MSS option"  # type: ignore
            return syn_res

        await self.send(syn_res.make_reply(self.src, self.dst, window=0xffff, ack=True))
        await asyncio.sleep(10, loop=self._loop)

        # Check for MSS violations and middlebox interference
        result = None if len(syn_res) <= 535 else TestResult(self, TEST_FAIL, 1, "Segment too large")
        result = self._detect_mboxes("MSS modified or deleted", win=False,
                                     ack=True, up=True, opts=False) or result
        if result is not None:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        # Generate ALP payload data to monitor size of received segments
        # TODO: multiple flights?
        alp = ALP_MAP[self.dst.port](self.src, self.dst)
        req = alp.pull_data(400)
        if req is None or len(req) > 1460:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return TestResult(self, TEST_UNK, 1, "ALP data unavailable")

        # Path interference check above should cover this too
        # May contain additional (late) MSS options
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
                # is by processing it. This would lead to bigger segments being received.
                if len(seg) > 535:
                    result = TestResult(self, TEST_FAIL, 1, "Segment too large")
                    break

        await self.send(seg.make_reset(self.src, self.dst))
        return result

    def _quote_diff(self, icmp: ICMPQuote[IPAddressType], *, data: bytes = None) \
            -> Optional[Tuple[str, str]]:
        qlen = len(icmp.quote)
        if qlen < 20:
            # Header options not included in quote
            return None

        head_len = (icmp.quote[12] >> 2) & 0b00111100
        if qlen < head_len:
            # Header options not included in quote
            return None

        # MSS options must exactly match the ones in the original SYN
        # Other kinds of options may be added/removed freely
        idx = 0
        max_idx = len(self._SYN_OPTS) - 1
        match = False
        opts = bytearray(icmp.quote[20:head_len])
        try:
            for opt in parse_options(opts):
                if isinstance(opt, MSSOption):
                    if not match and opt == self._SYN_OPTS[idx]:
                        if idx == max_idx:
                            match = True
                        else:
                            idx += 1
                    else:
                        return "", opt.hex()
        except ValueError:
            pass

        if match:
            return None
        return ",".join(opt.hex() for opt in self._SYN_OPTS[idx:]), ""


class MissingMSSTest(BaseTest[IPAddressType]):
    """Check fallback MSS value for validity."""
    # Conceptually the same as MSSSupportTest
    MAX_PACKET_RATE = (BaseTest._HOP_LIMIT + 4) / 10.0

    __slots__ = ()

    async def run(self) -> TestResult:
        if self.dst.port not in ALP_MAP:
            return TestResult(self, TEST_UNK, 0, f"Missing ALP module for port {self.dst.port}")

        # Defaults defined in RFC 793bis
        if isinstance(self.dst.ip, IPv4Address):
            seg_max_len = 536 + 20
        else:
            seg_max_len = 1220 + 20

        # Establish connection without MSS option(s)
        cur_seq = random.randint(0, 0xffff_ffff)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, window=0xffff, syn=True,
                        **encode_ttl(ttl, win=False, ack=True, up=True, opts=True)),  # type: ignore
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

        # Finish 3WH, if applicable
        if isinstance(syn_res, TestResult):
            return syn_res

        await self.send(syn_res.make_reply(self.src, self.dst, window=0xffff, ack=True))
        await asyncio.sleep(10, loop=self._loop)

        # Check for MSS violations and middlebox interference
        result = (None if len(syn_res) <= seg_max_len else
                  TestResult(self, TEST_FAIL, 1, "Segment too large"))
        result = self._detect_mboxes("MSS inserted", win=False, ack=True, up=True, opts=True) or result
        if result is not None:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        # Generate ALP payload data to monitor size of received segments
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

    def _quote_diff(self, icmp: ICMPQuote[IPAddressType], *, data: bytes = None) \
            -> Optional[Tuple[str, str]]:
        qlen = len(icmp.quote)
        if qlen < 20:
            # Header options not included in quote
            return None

        head_len = (icmp.quote[12] >> 2) & 0b00111100
        if qlen < head_len:
            # Header options not included in quote
            return None

        # MSS option may not be added
        opts = bytearray(icmp.quote[20:head_len])
        try:
            for opt in parse_options(opts):
                if isinstance(opt, MSSOption):
                    return "", opt.hex()
        except ValueError:
            return "", opts.hex()

        return None


# Derive from MSSSupportTest to avoid code duplication
class LateOptionTest(MSSSupportTest[IPAddressType]):
    """Test response to additional MSS option delivered after the 3WH."""
    _REQ_OPTS = (MSSOption(536),)

    __slots__ = ()


# Derive from MSSSupportTest to avoid code duplication
class MultiMSSTest(MSSSupportTest[IPAddressType]):
    """Check behavior when faced with multiple MSS options."""
    # Linux, OSX, Windows 10 all use the last value seen
    _SYN_OPTS = (MSSOption(550), MSSOption(505), MSSOption(515))

    __slots__ = ()
