from typing import Optional
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from ..tcp import Segment
from ..tcp.checksum import calc_checksum


# Make sure TX TCP checksum offloading is disabled
# E.g. ethtool -K <DEVNAME> tx off on Linux
class ChecksumTest(BaseTest):
    """Evaluate response to incorrect checksums in SYNs and after handshake."""
    async def run(self) -> TestResult:
        # Send SYN with incorrect checksum
        # Try random checksums until one doesn't match
        cur_seq = random.randrange(0, 1 << 32)
        cs_wrong = False
        while not cs_wrong:
            cs = random.randrange(0, 1 << 16).to_bytes(2, "little")
            syn_seg = Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True, checksum=cs)

            seg_arr = bytearray(bytes(syn_seg))
            seg_arr[16:18] = b"\x00\x00"
            cs_wrong = (calc_checksum(self.src[0].packed, self.dst[0].packed, b'', seg_arr) != cs)
        await self.send(syn_seg)

        result = await self._check_syn_resp(cur_seq)
        if result is not None:
            return result

        # Send SYN with zero checksum (special case, middleboxes?)
        cur_seq = (cur_seq + 2048) % 0x1_0000_000
        cs = b"\x00\x00"
        win = 1023
        cs_wrong = False
        while not cs_wrong:
            win += 1
            syn_seg = Segment(self.src, self.dst, seq=cur_seq, window=win, syn=True, checksum=cs)

            seg_raw = bytes(syn_seg)
            cs_wrong = (calc_checksum(self.src[0].packed, self.dst[0].packed, b'', seg_raw) != cs)
        await self.send(syn_seg)

        result = await self._check_syn_resp(cur_seq)
        if result is not None:
            return result

        # Send ACK with invalid checksum after SYN exchange
        # Establish connection
        cur_seq = (cur_seq + 2 * win) % 0x1_0000_000
        syn_seg = Segment(self.src, self.dst, seq=cur_seq, window=512, syn=True)
        await self.send(syn_seg)

        # Simultaneous open is not supported (targets are listening hosts)
        result = None
        cur_seq = (cur_seq + 1) % 0x1_0000_0000
        try:
            # TODO: change timeout?
            res = await self.receive(timeout=30)
        except asyncio.TimeoutError:
            return TestResult(TEST_UNK, "Timeout during handshake")
        if res.flags & 0x04 and res.seq == 0 and res.ack_seq == cur_seq:
            return TestResult(TEST_FAIL, "RST in reply to SYN during handshake")
        elif not (res.flags & 0x12):
            result = TestResult(TEST_FAIL, "Non-SYN-ACK in reply to SYN during handshake")
        elif res.ack_seq != cur_seq:
            result = TestResult(TEST_FAIL, "Wrong SEQ acked in reply to SYN during handshake")

        if result is not None:
            # Reset connection to be sure
            await self.send(res.make_reply(self.src[0], self.dst[0], window=0,
                                           seq=-1, ack=True, rst=True))
            return result

        cs_wrong = False
        while not cs_wrong:
            cs = random.randrange(0, 1 << 16).to_bytes(2, "little")
            ack_seg = res.make_reply(self.src[0], self.dst[0], window=512, ack=True, checksum=cs)

            seg_arr = bytearray(bytes(syn_seg))
            seg_arr[16:18] = b"\x00\x00"
            cs_wrong = (calc_checksum(self.src[0].packed, self.dst[0].packed, b'', seg_arr) != cs)
        await self.send(ack_seg)

        result = None
        try:
            # TODO: change timeout?
            res = await self.receive(timeout=30)
        except asyncio.TimeoutError:
            # Dropping the segment silently is acceptable
            result = TestResult(TEST_PASS)
        else:
            if not (res.flags & 0x04):
                result = TestResult(TEST_FAIL, "Non-RST in reply to ACK with incorrect checksum")
            elif res.seq != ack_seg.ack_seq or res.ack_seq != ack_seg.seq:
                # As per RFC 793bis. TODO: Too restrictive?
                return TestResult(TEST_FAIL, "Invalid RST in reply to ACK with incorrect checksum")
            else:
                return TestResult(TEST_PASS)

        # Reset connection to be sure
        await self.send(res.make_reply(self.src[0], self.dst[0], window=0,
                                       seq=-1, ack=True, rst=True))
        return result

    async def _check_syn_resp(self, sent_seq: int) -> Optional[TestResult]:
        try:
            # TODO: change timeout?
            res = await self.receive(timeout=60)
        except asyncio.TimeoutError:
            # Dropping the segment silently is acceptable
            pass
        else:
            exp_ack = (sent_seq + 1) % 0x1_0000_0000
            if not (res.flags & 0x04):
                # Reset connection to be sure
                await self.send(res.make_reply(self.src[0], self.dst[0], window=0,
                                               seq=-1, ack=True, rst=True))
                return TestResult(TEST_FAIL, "Non-RST in reply to SYN with incorrect checksum")
            elif res.seq != 0 or res.ack_seq != exp_ack:
                # As per RFC 793bis. TODO: Too restrictive?
                return TestResult(TEST_FAIL, "Invalid RST in reply to SYN with incorrect checksum")

        return None
