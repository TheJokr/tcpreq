from typing import Awaitable, List, Tuple, Optional
import sys
import time
import operator
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..types import IPAddressType, ICMPQuote
from ..tcp import Segment, ChecksumError, check_window
from ..tcp.checksum import calc_checksum


# Make sure TCP RX/TX checksum offloading is disabled
# E.g. on Linux: ethtool -K <DEVNAME> rx off tx off
class IncorrectChecksumTest(BaseTest[IPAddressType]):
    """Evaluate response to incorrect checksums in initial SYNs and after handshake."""
    __slots__ = ()

    @staticmethod
    def _generate_cs() -> bytes:
        return random.randint(1, 0xffff).to_bytes(2, sys.byteorder)

    async def receive_vrfyres(self, timeout: float) -> Optional[Segment]:
        """Variant of BaseTest.receive that allows checksum errors."""
        while timeout > 0:
            start = time.monotonic()
            data = await asyncio.wait_for(self.recv_queue.get(), timeout, loop=self._loop)
            timeout -= (time.monotonic() - start)

            try:
                seg = Segment.from_bytes(self.dst.ip.packed, self.src.ip.packed, data)
            except ChecksumError:
                return None
            except ValueError:
                # Discard invalid segments silently and retry
                pass
            else:
                if seg.flags & 0x02:
                    # Collect ISNs for ISN predictability meta-test
                    self._isns.append((time.monotonic(), seg.seq))
                return seg

        raise asyncio.TimeoutError()

    async def run(self) -> TestResult:
        # Send SYN with incorrect checksum
        cur_seq = random.randint(0, 0xffff_ffff)
        cs = self._generate_cs()
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            syn_seg = Segment(self.src, self.dst, seq=cur_seq, syn=True, **encode_ttl(ttl))  # type: ignore

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

        # Check that no connection has been established
        result = None
        cur_seq = (cur_seq + 1) % 0x1_0000_0000
        try:
            # TODO: change timeout?
            res = await self.receive_vrfyres(timeout=60)
        except asyncio.TimeoutError:
            # Dropping the segment silently is acceptable
            pass
        else:
            if res is None:
                return TestResult(self, TEST_FAIL, 1,
                                  "Incorrect checksum in reply to SYN with incorrect checksum")
            elif not (res.flags & 0x04):
                # Reset connection to be sure
                await self.send(res.make_reset(self.src, self.dst))
                result = TestResult(self, TEST_FAIL, 1,
                                    "Non-RST in reply to SYN with incorrect checksum")
            elif res.ack_seq != cur_seq:
                result = TestResult(self, TEST_FAIL, 1,
                                    "Invalid RST in reply to SYN with incorrect checksum")

            del res

        # Check path for middlebox interference (e.g., checksum corrected)
        await asyncio.sleep(10, loop=self._loop)
        res_stat = 0
        for icmp in self.quote_queue:
            mbox_hop = decode_ttl(icmp.quote, icmp.hops, self._HOP_LIMIT)
            self._path.append((mbox_hop, icmp.icmp_src.compressed))

            # None if not corrected, false if not enough data to verify, true if corrected
            verified = self._checksum_corrected(icmp, checksum=cs)
            if verified is None:
                continue
            if mbox_hop > 0:
                if not verified and res_stat >= 3:
                    continue
            elif res_stat >= 1 + verified:
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (checksum corrected)" if verified else " (checksum modified)"
            result = TestResult(self, TEST_UNK, 1, reason.format(mbox_hop))

            if mbox_hop > 0:
                if verified:
                    break
                else:
                    res_stat = 3
            else:
                res_stat = 1 + verified
        del res_stat

        self._path.sort(key=operator.itemgetter(0))
        if result is not None:
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        # Establish new connection
        cur_seq = (cur_seq + 2047) % 0x1_0000_000
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=512, syn=True))

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=2)
        if isinstance(syn_res, TestResult):
            return syn_res

        # Send ACK with invalid checksum after SYN exchange
        cs = self._generate_cs()
        ack_seg = syn_res.make_reply(self.src, self.dst, window=512, ack=True)

        seg_arr = bytearray(ack_seg._raw)
        if ack_seg.checksum == cs:
            # Change real checksum by modifying the window value
            seg_arr[15] = 0xf0
        seg_arr[16:18] = cs
        ack_seg._raw = bytes(seg_arr)
        del seg_arr

        # Verify that invalid ACK doesn't finish 3WH
        # Expected: Retransmission or RST
        await self.send(ack_seg)
        try:
            # TODO: change timeout?
            ack_res = await self.receive_vrfyres(timeout=30)
        except asyncio.TimeoutError:
            result = TestResult(self, TEST_FAIL, 2, "ACK with incorrect checksum accepted")
            ack_res = syn_res  # For ack_res.make_reset below
        else:
            if ack_res is None:
                result = TestResult(self, TEST_FAIL, 2,
                                    "Incorrect checksum in reply to ACK with incorrect checksum")
                ack_res = syn_res  # For ack_res.make_reset below
            elif (ack_res.flags == syn_res.flags and ack_res.seq == syn_res.seq and
                    ack_res.ack_seq == syn_res.ack_seq):
                # Retransmission of SYN-ACK is acceptable (ACK ignored)
                result = TestResult(self, TEST_PASS)
            elif not (ack_res.flags & 0x04):
                result = TestResult(self, TEST_FAIL, 2,
                                    "Non-RST in reply to ACK with incorrect checksum")
            elif not check_window(ack_res.seq, ack_seg.ack_seq,
                                  (ack_seg.ack_seq + ack_seg.window) % 0x1_0000_0000):
                return TestResult(self, TEST_FAIL, 2,
                                  "Invalid RST in reply to ACK with incorrect checksum")
            else:
                return TestResult(self, TEST_PASS)

        # Reset connection to be sure
        await self.send(ack_res.make_reset(self.src, self.dst))
        return result

    def _checksum_corrected(self, icmp: ICMPQuote[IPAddressType],
                            *, checksum: bytes) -> Optional[bool]:
        qlen = len(icmp.quote)
        if qlen < 18:
            # Checksum not included in quote
            return None

        cs = icmp.quote[16:18]
        if cs == checksum:
            return None

        # Checksum is modified, but could still be wrong (incremental update)
        cs_vrfy = False
        if qlen >= 20:
            head_len = (icmp.quote[12] >> 2) & 0b00111100
            if qlen >= head_len:
                # Verify checksum if full header is included
                seg = bytearray(icmp.quote)
                seg[16:18] = b"\x00\x00"
                cs_vrfy = (calc_checksum(icmp.quote_src, self.dst.ip.packed, seg) == cs)
                if not cs_vrfy:
                    # Checksum is still incorrect
                    return None

        return cs_vrfy


# IncorrectChecksumTest specialization with zero checksum
class ZeroChecksumTest(IncorrectChecksumTest[IPAddressType]):
    """Evaluate response to zeroed checksums in initial SYNs and after handshake."""
    __slots__ = ()

    @staticmethod
    def _generate_cs() -> bytes:
        return b"\x00\x00"
