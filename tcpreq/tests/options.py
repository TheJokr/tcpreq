from typing import ClassVar, Awaitable, List, Optional
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..types import IPAddressType, ICMPQuote
from ..tcp import Segment, noop_option, end_of_options
from ..tcp.options import BaseOption, SizedOption, parse_options


class OptionSupportTest(BaseTest[IPAddressType]):
    """Verify support for the two legacy options (End of option list, NOOP)."""
    __slots__ = ()

    async def run(self) -> TestResult:
        # Establish connection with options in SYN
        cur_seq = random.randint(0, 0xffff_ffff)
        opts = (noop_option, noop_option, end_of_options)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, syn=True, options=opts,  # type: ignore
                        **encode_ttl(ttl, win=True, ack=True, up=True, opts=False)),
                ttl=ttl
            ))
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult) and syn_res.status is TEST_UNK:
            # Retry synchronization without encoding/segment burst
            await self.send(Segment(self.src, self.dst, seq=cur_seq,
                                    window=4096, syn=True, options=opts))
            syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        del opts

        # Check whether connection was established and tear it down if necessary
        if isinstance(syn_res, TestResult):
            syn_res.status = TEST_FAIL
            syn_res.reason += " with options"  # type: ignore
            return syn_res

        await self.send(syn_res.make_reset(self.src, self.dst))
        await asyncio.sleep(10, loop=self._loop)

        # Connection was established successfully, check for middlebox interference
        return self._detect_mboxes("header option(s) deleted", win=True,
                                   ack=True, up=True, opts=False) or TestResult(self, TEST_PASS)

    def _quote_modified(self, icmp: ICMPQuote[IPAddressType], *, data: bytes = None) -> bool:
        qlen = len(icmp.quote)
        if qlen < 20:
            # Header options not included in quote
            return False

        head_len = (icmp.quote[12] >> 2) & 0b00111100
        if qlen < head_len:
            # Header options not included in quote
            return False

        opts = bytearray(icmp.quote[20:head_len])
        try:
            # Lenient check: allow addition of new options, e.g. MSS, and (de-)duplication of existing ones
            return not {noop_option, end_of_options}.issubset(parse_options(opts))
        except ValueError:
            return True


class UnknownOptionTest(BaseTest[IPAddressType]):
    """Test whether unknown options are ignored silently."""
    # Option kind 158 is currently reserved
    # See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
    _UNK_OPT: ClassVar[SizedOption] = SizedOption(158, b"\x58\xfa\x89")

    __slots__ = ()

    async def run(self) -> TestResult:
        # Establish connection with unknown option in SYN
        cur_seq = random.randint(0, 0xffff_ffff)
        opts = (self._UNK_OPT,)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, syn=True, options=opts,  # type: ignore
                        **encode_ttl(ttl, win=True, ack=True, up=True, opts=False)),
                ttl=ttl
            ))
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult) and syn_res.status is TEST_UNK:
            # Retry synchronization without encoding/segment burst
            await self.send(Segment(self.src, self.dst, seq=cur_seq,
                                    window=4096, syn=True, options=opts))
            syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        del opts

        # Check whether connection was established and tear it down if necessary
        if isinstance(syn_res, TestResult):
            syn_res.status = TEST_FAIL
            syn_res.reason += " with unknown option"  # type: ignore
            return syn_res

        await self.send(syn_res.make_reset(self.src, self.dst))
        await asyncio.sleep(10, loop=self._loop)

        # Connection was established successfully, check for middlebox interference
        return self._detect_mboxes("unknown header option deleted", win=True,
                                   ack=True, up=True, opts=False) or TestResult(self, TEST_PASS)

    def _quote_modified(self, icmp: ICMPQuote[IPAddressType], *, data: bytes = None) -> bool:
        qlen = len(icmp.quote)
        if qlen < 20:
            # Header options not included in quote
            return False

        head_len = (icmp.quote[12] >> 2) & 0b00111100
        if qlen < head_len:
            # Header options not included in quote
            return False

        opts = bytearray(icmp.quote[20:head_len])
        try:
            # Lenient check: only require presence of unknown option
            return self._UNK_OPT not in parse_options(opts)
        except ValueError:
            return True


class IllegalLengthOptionTest(BaseTest[IPAddressType]):
    """Verify responsiveness after sending an option with illegal length."""
    # Option kind 2 is assigned to MSS
    # See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
    _ILLEGAL_OPT: ClassVar[BaseOption] = BaseOption(b"\x02\x00\x02\xf1")

    __slots__ = ()

    async def run(self) -> TestResult:
        # Try to establish connection with illegal option in SYN
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
            # Ignoring the segment is acceptable, but must test reachability afterwards
            result = None
        else:
            is_rst = bool(syn_res.flags & 0x04)
            if is_rst and syn_res.ack_seq == cur_seq:
                result = TestResult(self, TEST_PASS)
            elif (syn_res.flags & 0x12) != 0x12:
                result = TestResult(self, TEST_FAIL, 1,
                                    "Non-SYN-ACK in reply to SYN during handshake")
            elif syn_res.ack_seq != cur_seq:
                result = TestResult(self, TEST_FAIL, 1,
                                    "Wrong SEQ acked in reply to SYN during handshake")
            else:
                result = TestResult(self, TEST_PASS)

            if not is_rst:
                # Tear connection down ourselves
                await self.send(syn_res.make_reset(self.src, self.dst))

        if result is not None and result.status is not TEST_PASS:
            return result

        # Check for middlebox interference before returning PASS result
        await asyncio.sleep(10, loop=self._loop)
        result = self._detect_mboxes("illegal header option deleted", win=True,
                                     ack=True, up=True, opts=False) or result
        if result is not None:
            return result

        # No response to SYN with illegal option length and no modifications along the path
        # Test responsiveness to regular SYN
        # 0x1fffd == 2 * 0xffff - 1
        cur_seq = (cur_seq + 0x1fffd) % 0x1_0000_000
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True))

        # Check whether connection was established and tear it down if necessary
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

        await self.send(syn_res.make_reset(self.src, self.dst))
        return result

    def _quote_modified(self, icmp: ICMPQuote[IPAddressType], *, data: bytes = None) -> bool:
        qlen = len(icmp.quote)
        if qlen < 20:
            # Header options not included in quote
            return False

        head_len = (icmp.quote[12] >> 2) & 0b00111100
        if qlen < head_len:
            # Header options not included in quote
            return False

        # Lenient check: only require presence of illegal option
        opts = bytearray(icmp.quote[20:head_len])
        try:
            for _ in parse_options(opts):
                pass
        except ValueError:
            # parse_options should fail on parsing _ILLEGAL_OPT
            return opts[:4] != bytes(self._ILLEGAL_OPT)

        return True
