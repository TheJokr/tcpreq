from typing import Awaitable, List, Tuple
import operator
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..types import IPAddressType, ICMPQuote
from ..tcp import Segment


class ReservedFlagsTest(BaseTest[IPAddressType]):
    """Test response to reserved flags being set."""
    __slots__ = ()

    async def run(self) -> TestResult:
        cur_seq = random.randint(0, 0xffff_ffff)
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(
                Segment(self.src, self.dst, seq=cur_seq, rsrvd=0b0100, syn=True, **encode_ttl(ttl)),  # type: ignore
                ttl=ttl
            ))
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult) and syn_res.status is TEST_UNK:
            # Retry synchronization without encoding/segment burst
            await self.send(Segment(self.src, self.dst, seq=cur_seq,
                                    window=4096, rsrvd=0b0100, syn=True))
            syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            syn_res.status = TEST_FAIL
            syn_res.reason += " with reserved flag"  # type: ignore
            return syn_res
        elif syn_res._raw[12] & 0b1110:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return TestResult(
                self, TEST_FAIL, 1,
                "Reserved flags not zeroed in reply to SYN during handshake with reserved flag"
            )

        await self.send(syn_res.make_reply(self.src, self.dst, window=1024, rsrvd=0b0100, ack=True))
        await asyncio.sleep(10, loop=self._loop)

        result = None
        res_stat = 0
        net_path: List[Tuple[int, str]] = []
        custom_res = {"path": net_path}
        for icmp in self.quote_queue:
            mbox_hop = decode_ttl(icmp.quote, icmp.hops, self._HOP_LIMIT)
            net_path.append((mbox_hop, icmp.icmp_src.compressed))

            if not self._quote_modified(icmp) or (mbox_hop == 0 and res_stat >= 1):
                continue

            reason = "Middlebox interference detected"
            reason += " at or before hop {0}" if mbox_hop > 0 else " at unknown hop"
            reason += " (reserved flags reset)"
            result = TestResult(self, TEST_UNK, 1, reason.format(mbox_hop), custom=custom_res)

            if mbox_hop > 0:
                break
            else:
                res_stat = 1
        del res_stat
        net_path.sort(key=operator.itemgetter(0))

        if result is not None:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        for rt in range(3):
            try:
                # TODO: change timeout?
                ack_res = await self.receive(timeout=30)
            except asyncio.TimeoutError:
                # No response is acceptable
                result = TestResult(self, TEST_PASS)
                ack_res = syn_res  # For ack_res.make_reset below
            else:
                if (ack_res.flags == syn_res.flags and ack_res.seq == syn_res.seq and
                        ack_res.ack_seq == syn_res.ack_seq):
                    if rt < 2:
                        # SYN-ACK shouldn't be retransmitted, retransmit ACK (up to two times)
                        await self.send(syn_res.make_reply(self.src, self.dst, window=1024,
                                                           rsrvd=0b0100, ack=True))
                    else:
                        # Sent ACK acknowledges SYN-ACK already
                        result = TestResult(self, TEST_FAIL, 1,
                                            "ACK with reserved flag ignored", custom=custom_res)
                elif ack_res.flags & 0x04:
                    return TestResult(self, TEST_FAIL, 1,
                                      "RST in reply to ACK with reserved flag", custom=custom_res)
                elif ack_res._raw[12] & 0b1110:
                    result = TestResult(
                        self, TEST_FAIL, 1,
                        "Reserved flags not zeroed in reply to ACK with reserved flag",
                        custom=custom_res
                    )
                else:
                    result = TestResult(self, TEST_PASS)

            if result is not None:
                break

        await self.send(ack_res.make_reset(self.src, self.dst))
        return result  # type: ignore

    @staticmethod
    def _quote_modified(icmp: ICMPQuote[IPAddressType]) -> bool:
        if len(icmp.quote) < 13:
            # Reserved flags not included in quote
            return False

        # 9th flag bit is used for an optional ECN extension
        if (icmp.quote[12] & 0b1110) == 0b0100:
            return False

        return True
