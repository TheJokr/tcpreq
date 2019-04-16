from typing import Awaitable, List, Tuple, Counter as CounterType, Optional
import sys
from collections import deque, Counter
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from ..tcp import Segment, check_window, noop_option, end_of_options
from ..tcp.checksum import calc_checksum


# Make sure TX TCP checksum offloading is disabled
# E.g. ethtool -K <DEVNAME> tx off on Linux
class ChecksumTest(BaseTest):
    """Evaluate response to incorrect checksums in SYNs and after handshake."""
    async def _detect_interference(self) -> Optional[TestResult]:
        # Test path for checksum modifiers
        src_addr = self.src[0].packed
        dst_addr = self.dst[0].packed
        seq = random.randrange(0, 1 << 32)
        cs = random.randrange(0, 1 << 16).to_bytes(2, sys.byteorder)
        opts = deque((end_of_options,))
        futs: List[Awaitable[None]] = []

        for ttl in range(1, self._HOP_LIMIT + 1):
            # Encoding is similar to IPv4 header
            enc_16 = (ttl << 11) | (ttl << 5) | ttl
            enc_32 = (enc_16 << 16) | enc_16
            opts.appendleft(noop_option)
            syn_seg = Segment(self.src, self.dst, seq=seq, window=enc_16, ack_seq=enc_32,
                              syn=True, checksum=cs, up=enc_16, options=opts)

            seg_arr = bytearray(bytes(syn_seg))
            seg_arr[16:18] = b"\x00\x00"
            if calc_checksum(src_addr, dst_addr, b'', seg_arr) == cs:
                # Set unused bit in enc_16 to 1 to change real checksum
                enc_16 |= 0x0400
                syn_seg = Segment(self.src, self.dst, seq=seq, window=enc_16, ack_seq=enc_32,
                                  syn=True, checksum=cs, up=enc_16, options=opts)

            futs.append(self.send(syn_seg, ttl=ttl))
        del src_addr, dst_addr, opts, syn_seg, seg_arr
        await asyncio.wait(futs, loop=self._loop)
        del futs

        result = await self._check_syn_resp(seq, 0)
        if result is not None:
            result = TestResult(TEST_UNK, 0, result.reason + " (middlebox interference?)")  # type: ignore # noqa

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
            result = TestResult(TEST_UNK, 0, reason.format(mbox_hop))

            if mbox_hop > 0:
                if verified:
                    break
                else:
                    res_stat = 3
            elif verified:
                res_stat = 2
            else:
                res_stat = 1

        # Clear queues (might contain challenge ACKs due to multiple SYNs reaching the target)
        await asyncio.sleep(10)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        return result

    def _check_quote(self, ttl_guess: int, quote: bytes,
                     checksum: bytes) -> Optional[Tuple[int, bool]]:
        qlen = len(quote)
        if qlen < 18:
            # Checksum not included in quote
            return None

        cs = quote[16:18]
        if cs == checksum:
            return None

        # Checksum is modified, but could be wrong still (incremental update)
        ttl = 0
        ttl_count: CounterType[int] = Counter()
        ttl_guess = min(ttl_guess, self._HOP_LIMIT)

        ack = int.from_bytes(quote[8:12], "big")
        ttl_count.update((ack >> i) & 0x1f for i in (27, 21, 16, 11, 5, 0))

        win = int.from_bytes(quote[14:16], "big")
        ttl_count.update((win >> i) & 0x1f for i in (11, 5, 0))

        cs_vrfy = False
        if qlen >= 20:
            up = int.from_bytes(quote[18:20], "big")
            ttl_count.update((up >> i) & 0x1f for i in (11, 5, 0))

            div = (quote[12] >> 4)
            head_len = div * 4
            if qlen >= head_len:
                # Verify checksum if full header is included
                # TODO: NAT may modify src_addr
                seg = bytearray(quote)
                seg[16:18] = b"\x00\x00"
                cs_vrfy = (calc_checksum(self.src[0].packed, self.dst[0].packed, b'', seg) == cs)
                if not cs_vrfy:
                    # Checksum is still incorrect
                    return None

                # Try to recover TTL from DO+options (see IPv4TestMultiplexer._recover_ttl)
                if div > 5:
                    div -= 6
                    mod: Optional[int] = None
                    expected = 0x01
                    for idx, opt in enumerate(quote[20:head_len]):
                        if opt != expected:
                            if mod is None and opt == 0x00:
                                mod = idx % 4
                                expected = 0x00
                            else:
                                mod = None
                                break

                    if mod is not None:
                        ttl = 4 * div + mod

        if ttl == 0:
            # Get most likely TTL value from ttl_count. There are up to 12 entries.
            # At least 4 votes (33%) are required to be selected. This means
            # only the top 3 values can be eligible.
            candidates = list(filter(lambda c: c[0] <= self._HOP_LIMIT and c[1] >= 4,
                                     ttl_count.most_common(3)))
            clen = len(candidates)

            if clen == 1:
                # Trivial case
                ttl = candidates[0][0]
            elif clen == 2:
                diff = candidates[0][1] - candidates[1][1]
                if diff >= 2 or candidates[0][0] == ttl_guess:
                    ttl = candidates[0][0]
                elif candidates[1][0] == ttl_guess:
                    ttl = candidates[1][0]
                elif diff > 0:
                    ttl = candidates[0][0]
                # else: evidence inconclusive
            elif clen == 3:
                # Must be a tie (4 * 3 == 12). Use window as tie breaker.
                ttl_count.clear()
                ttl_count.update((win >> i) & 0x1f for i in (11, 5, 0))
                for v, _ in candidates:
                    if ttl_count[v] >= 2:
                        ttl = v
                        break
                # else: evidence inconclusive
            else:  # clen == 0
                # Fall back to lower layer guess
                ttl = ttl_guess

        return ttl, cs_vrfy

    async def run(self) -> TestResult:
        result = await self._detect_interference()
        if result is not None:
            return result

        # Send SYN with incorrect checksum
        # Try random checksums until one doesn't match
        cur_seq = random.randrange(0, 1 << 32)
        cs_wrong = False
        while not cs_wrong:
            cs = random.randrange(0, 1 << 16).to_bytes(2, sys.byteorder)
            syn_seg = Segment(self.src, self.dst, seq=cur_seq, window=1024, syn=True, checksum=cs)

            seg_arr = bytearray(bytes(syn_seg))
            seg_arr[16:18] = b"\x00\x00"
            cs_wrong = (calc_checksum(self.src[0].packed, self.dst[0].packed, b'', seg_arr) != cs)
        await self.send(syn_seg)

        result = await self._check_syn_resp(cur_seq, test_stage=1)
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

        result = await self._check_syn_resp(cur_seq, test_stage=2)
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
            syn_res = await self.receive(timeout=30)
        except asyncio.TimeoutError:
            return TestResult(TEST_UNK, 3, "Timeout during handshake")
        if syn_res.flags & 0x04 and syn_res.ack_seq == cur_seq:
            return TestResult(TEST_UNK, 3, "RST in reply to SYN during handshake")
        elif not (syn_res.flags & 0x12):
            result = TestResult(TEST_FAIL, 3, "Non-SYN-ACK in reply to SYN during handshake")
        elif syn_res.ack_seq != cur_seq:
            result = TestResult(TEST_FAIL, 3, "Wrong SEQ acked in reply to SYN during handshake")

        if result is not None:
            # Reset connection to be sure
            await self.send(syn_res.make_reset(self.src[0], self.dst[0]))
            return result

        cs_wrong = False
        while not cs_wrong:
            cs = random.randrange(0, 1 << 16).to_bytes(2, sys.byteorder)
            ack_seg = syn_res.make_reply(self.src[0], self.dst[0], window=512,
                                         ack=True, checksum=cs)

            seg_arr = bytearray(bytes(syn_seg))
            seg_arr[16:18] = b"\x00\x00"
            cs_wrong = (calc_checksum(self.src[0].packed, self.dst[0].packed, b'', seg_arr) != cs)
        await self.send(ack_seg)

        result = None
        try:
            # TODO: change timeout?
            ack_res = await self.receive(timeout=30)
        except asyncio.TimeoutError:
            # Dropping the segment silently is acceptable
            result = TestResult(TEST_PASS)
            ack_res = syn_res  # For ack_res.make_reply below
        else:
            # Retransmission of SYN-ACK is acceptable (similar to timeout)
            if ack_res == syn_res:
                result = TestResult(TEST_PASS)
            elif not (ack_res.flags & 0x04):
                result = TestResult(TEST_FAIL, 3, "Non-RST in reply to ACK with incorrect checksum")
            elif not check_window(ack_res.seq, ack_seg.ack_seq,
                                  (ack_seg.ack_seq + ack_seg.window) % 0x1_0000_0000):
                return TestResult(TEST_FAIL, 3,
                                  "Invalid RST in reply to ACK with incorrect checksum")
            else:
                return TestResult(TEST_PASS)

        # Reset connection to be sure
        await self.send(ack_res.make_reset(self.src[0], self.dst[0]))
        return result

    async def _check_syn_resp(self, sent_seq: int, test_stage: int) -> Optional[TestResult]:
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
                await self.send(res.make_reset(self.src[0], self.dst[0]))
                return TestResult(TEST_FAIL, test_stage,
                                  "Non-RST in reply to SYN with incorrect checksum")
            elif res.ack_seq != exp_ack:
                return TestResult(TEST_FAIL, test_stage,
                                  "Invalid RST in reply to SYN with incorrect checksum")

        return None
