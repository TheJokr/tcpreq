from typing import Awaitable, List, Tuple, Optional
import sys
import time
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..types import IPAddressType
from ..tcp import Segment, check_window
from ..tcp.checksum import calc_checksum


def _bytes_int_xor(lhs: bytes, rhs: int) -> bytes:
    return (int.from_bytes(lhs, sys.byteorder) ^ rhs).to_bytes(len(lhs), sys.byteorder)


# Make sure TCP TX checksum offloading is disabled
# E.g. ethtool -K <DEVNAME> tx off on Linux
class ChecksumTest(BaseTest[IPAddressType]):
    """Evaluate response to incorrect checksums in SYNs and after handshake."""
    __slots__ = ()

    # Test path for checksum modifiers
    async def _detect_interference(self) -> Optional[TestResult]:
        seq = random.randint(0, 0xffff_ffff)
        cs = random.randint(0, 0xffff).to_bytes(2, sys.byteorder)
        futs: List[Awaitable[None]] = []

        for ttl in range(1, self._HOP_LIMIT + 1):
            syn_seg = Segment(self.src, self.dst, seq=seq, syn=True, **encode_ttl(ttl))  # type: ignore

            seg_arr = bytearray(syn_seg._raw)
            if syn_seg.checksum == cs:
                # Set unused bit in enc_16 to 1 to change real checksum
                seg_arr[14] |= 0x04
                seg_arr[18] |= 0x04
            seg_arr[16:18] = cs
            syn_seg._raw = bytes(seg_arr)

            futs.append(self.send(syn_seg, ttl=ttl))
        del syn_seg, seg_arr
        await asyncio.wait(futs, loop=self._loop)
        del futs

        result = await self._check_syn_resp(seq, test_stage=0)
        if result is not None:
            result.status = TEST_UNK
            result.reason += " (middlebox interference?)"  # type: ignore

        await asyncio.sleep(10, loop=self._loop)
        res_stat = 0
        hops = filter(None, (self._check_quote(*item, checksum=cs) for item in self.quote_queue))
        for mbox_hop, verified in hops:
            if mbox_hop > 0:
                if not verified and res_stat >= 3:
                    continue
            elif res_stat >= 1 + verified:
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (checksum corrected)" if verified else " (checksum modified)"
            result = TestResult(self, TEST_UNK, 0, reason.format(mbox_hop))

            if mbox_hop > 0:
                if verified:
                    break
                else:
                    res_stat = 3
            else:
                res_stat = 1 + verified

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        return result

    def _check_quote(self, src_addr: bytes, ttl_guess: int, quote: bytes,
                     *, checksum: bytes) -> Optional[Tuple[int, bool]]:
        qlen = len(quote)
        if qlen < 18:
            # Checksum not included in quote
            return None

        cs = quote[16:18]
        if cs == checksum:
            return None

        # Checksum is modified, but could still be wrong (incremental update)
        cs_vrfy = False
        if qlen >= 20:
            head_len = (quote[12] >> 2) & 0b00111100
            if qlen >= head_len:
                # Verify checksum if full header is included
                seg = bytearray(quote)
                seg[16:18] = b"\x00\x00"
                cs_vrfy = (calc_checksum(src_addr, self.dst.ip.packed, seg) == cs)
                if not cs_vrfy:
                    # Checksum is still incorrect
                    return None

        return decode_ttl(quote, ttl_guess, self._HOP_LIMIT), cs_vrfy

    async def receive_vrfyres(self, timeout: float) -> Optional[Segment]:
        while timeout > 0:
            start = time.monotonic()
            data = await asyncio.wait_for(self.recv_queue.get(), timeout, loop=self._loop)
            timeout -= (time.monotonic() - start)

            try:
                seg = Segment.from_bytes(self.dst.ip.packed, self.src.ip.packed, data)
            except ValueError as e:
                if str(e) == "Checksum mismatch":
                    return None
            else:
                if seg.flags & 0x02:
                    self._isns.append((time.monotonic(), seg.seq))
                return seg

        raise asyncio.TimeoutError()

    async def run(self) -> TestResult:
        result = await self._detect_interference()
        if result is not None:
            return result

        # Send SYN with incorrect checksum
        cur_seq = random.randint(0, 0xffff_ffff)
        syn_seg = Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True)

        seg_arr = bytearray(syn_seg._raw)
        seg_arr[16:18] = _bytes_int_xor(seg_arr[16:18], random.randint(1, 0xffff))
        syn_seg._raw = bytes(seg_arr)
        del seg_arr

        await self.send(syn_seg)
        del syn_seg

        result = await self._check_syn_resp(cur_seq, test_stage=1)
        if result is not None:
            return result

        # Send SYN with zero checksum (special case, middleboxes?)
        cur_seq = (cur_seq + 2048) % 0x1_0000_000
        win = 1023
        while True:
            win += 1
            syn_seg = Segment(self.src, self.dst, seq=cur_seq, window=win, syn=True)

            if syn_seg.checksum != b"\x00\x00":
                seg_arr = bytearray(syn_seg._raw)
                seg_arr[16:18] = b"\x00\x00"
                syn_seg._raw = bytes(seg_arr)
                del seg_arr
                break

        await self.send(syn_seg)
        del syn_seg

        result = await self._check_syn_resp(cur_seq, test_stage=2)
        if result is not None:
            return result

        # Send ACK with invalid checksum after SYN exchange
        # Establish connection
        cur_seq = (cur_seq + 2 * win) % 0x1_0000_000
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=512, syn=True))

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=3)
        if isinstance(syn_res, TestResult):
            return syn_res

        ack_seg = syn_res.make_reply(self.src, self.dst, window=512, ack=True)

        seg_arr = bytearray(ack_seg._raw)
        seg_arr[16:18] = _bytes_int_xor(seg_arr[16:18], random.randint(1, 0xffff))
        ack_seg._raw = bytes(seg_arr)
        del seg_arr

        await self.send(ack_seg)

        result = None
        try:
            # TODO: change timeout?
            ack_res = await self.receive_vrfyres(timeout=30)
        except asyncio.TimeoutError:
            # Dropping the segment silently is acceptable
            result = TestResult(self, TEST_PASS)
            ack_res = syn_res  # For ack_res.make_reset below
        else:
            if ack_res is None:
                result = TestResult(self, TEST_FAIL, 3,
                                    "Incorrect checksum in reply to ACK with incorrect checksum")
                ack_res = syn_res  # For ack_res.make_reset below
            elif (ack_res.flags == syn_res.flags and ack_res.seq == syn_res.seq and
                    ack_res.ack_seq == syn_res.ack_seq):
                # Retransmission of SYN-ACK is acceptable (similar to timeout)
                result = TestResult(self, TEST_PASS)
            elif not (ack_res.flags & 0x04):
                result = TestResult(self, TEST_FAIL, 3,
                                    "Non-RST in reply to ACK with incorrect checksum")
            elif not check_window(ack_res.seq, ack_seg.ack_seq,
                                  (ack_seg.ack_seq + ack_seg.window) % 0x1_0000_0000):
                return TestResult(self, TEST_FAIL, 3,
                                  "Invalid RST in reply to ACK with incorrect checksum")
            else:
                return TestResult(self, TEST_PASS)

        # Reset connection to be sure
        await self.send(ack_res.make_reset(self.src, self.dst))
        return result

    async def _check_syn_resp(self, sent_seq: int, test_stage: int) -> Optional[TestResult]:
        try:
            # TODO: change timeout?
            res = await self.receive_vrfyres(timeout=60)
        except asyncio.TimeoutError:
            # Dropping the segment silently is acceptable
            pass
        else:
            if res is None:
                return TestResult(self, TEST_FAIL, test_stage,
                                  "Incorrect checksum in reply to SYN with incorrect checksum")

            exp_ack = (sent_seq + 1) % 0x1_0000_0000
            if not (res.flags & 0x04):
                # Reset connection to be sure
                await self.send(res.make_reset(self.src, self.dst))
                return TestResult(self, TEST_FAIL, test_stage,
                                  "Non-RST in reply to SYN with incorrect checksum")
            elif res.ack_seq != exp_ack:
                return TestResult(self, TEST_FAIL, test_stage,
                                  "Invalid RST in reply to SYN with incorrect checksum")

        return None
