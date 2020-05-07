from typing import Awaitable, List, Tuple, Optional
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl
from ..types import IPAddressType, ICMPQuote
from ..tcp import Segment
from ..alp import ALP_MAP


class ReservedFlagsTest(BaseTest[IPAddressType]):
    """Test response to reserved flags being set during handshake and normal operation."""
    __slots__ = ()

    async def run(self) -> TestResult:
        # Establish connection with 3rd reserved flag set in SYN
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

        # Check whether connection was established normally
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

        # Test reserved flags in ACK
        await self.send(syn_res.make_reply(self.src, self.dst, window=1024, rsrvd=0b0100, ack=True))
        await asyncio.sleep(10, loop=self._loop)

        # Check for middlebox interference in reserved flags
        result = self._detect_mboxes("reserved flags reset")
        if result is not None:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return result

        # Clear queues (might contain additional items due to multiple SYNs reaching the target)
        self.quote_queue.clear()
        self.recv_queue = asyncio.Queue(loop=self._loop)

        req = b''
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
                    # ACK was ignored, try to mitigate known causes
                    if rt == 0 and self.dst.port in ALP_MAP:
                        # Add ALP request to subsequent ACKs to counter TCP_DEFER_ACCEPT
                        alp = ALP_MAP[self.dst.port](self.src, self.dst)
                        tmp = alp.pull_data(500)
                        if tmp is not None and len(tmp) <= 1460:
                            req = tmp

                    if rt < 2:
                        # SYN-ACK shouldn't be retransmitted, retransmit ACK (up to two times)
                        await self.send(syn_res.make_reply(self.src, self.dst, window=1024,
                                                           rsrvd=0b0100, ack=True, payload=req))
                    else:
                        # Sent ACK acknowledges SYN-ACK already, but due to TCP_DEFER_ACCEPT
                        # we can only make a conclusive decision if we used ALP data
                        if req:
                            result = TestResult(self, TEST_FAIL, 1, "ACK with reserved flag ignored")
                        else:
                            result = TestResult(self, TEST_UNK, 1,
                                                "Empty ACK with reserved flag ignored")
                elif ack_res.flags & 0x04:
                    return TestResult(self, TEST_FAIL, 1, "RST in reply to ACK with reserved flag")
                elif ack_res._raw[12] & 0b1110:
                    result = TestResult(self, TEST_FAIL, 1,
                                        "Reserved flags not zeroed in reply to ACK with reserved flag")
                else:
                    result = TestResult(self, TEST_PASS)

            if result is not None:
                break

        # Reset connection to be sure
        await self.send(ack_res.make_reset(self.src, self.dst))
        return result  # type: ignore

    def _quote_diff(self, icmp: ICMPQuote[IPAddressType], *, data: bytes = None) \
            -> Optional[Tuple[str, str]]:
        if len(icmp.quote) < 13:
            # Reserved flags not included in quote
            return None

        # 9th flag bit is used for an optional ECN extension
        # Other reserved flags must keep their values
        rsrvd = icmp.quote[12] & 0b1110
        if rsrvd != 0b0100:
            return "0b0100", f"{rsrvd:#06b}"

        return None
