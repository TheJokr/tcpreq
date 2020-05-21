from typing import ClassVar, Awaitable, List, Tuple, Optional
import random
import asyncio

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .ttl_coding import encode_ttl, decode_ttl
from ..types import IPAddressType, ICMPQuote
from ..tcp import Segment, MSSOption
from ..alp import ALP_MAP


class UrgentPointerTest(BaseTest[IPAddressType]):
    """Verify support for the TCP urgent mechanism."""
    # Assuming instant responses, i.e., no waiting
    MAX_PACKET_RATE = (BaseTest._HOP_LIMIT + 5) / 10.0

    _UDATA_LENGTH_HINT: ClassVar[int] = 500
    _MSS_OPT: ClassVar[MSSOption] = MSSOption(1460)
    assert 256 <= _UDATA_LENGTH_HINT <= 1400

    __slots__ = ()

    async def run(self) -> TestResult:
        if self.dst.port not in ALP_MAP:
            return TestResult(self, TEST_UNK, 0, f"Missing ALP module for port {self.dst.port}")

        # Establish the connection
        cur_seq = random.randint(0, 0xffff_ffff)
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=4096,
                                syn=True, options=(self._MSS_OPT,)))

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=30, test_stage=1)
        if isinstance(syn_res, TestResult):
            return syn_res
        await self.send(syn_res.make_reply(self.src, self.dst, window=4096, ack=True))

        # Generate _UDATA_LENGTH_HINT bytes of ALP payload data
        alp = ALP_MAP[self.dst.port](self.src, self.dst)
        req = alp.pull_data(self._UDATA_LENGTH_HINT)
        if req is None or len(req) > 1460:
            await self.send(syn_res.make_reset(self.src, self.dst))
            return TestResult(self, TEST_UNK, 1, "ALP data unavailable")

        # Send payload as urgent data split over multiple segments
        # First segment with increasing TTLs for middlebox detection, later ones just once
        req_len = len(req)
        chck_up = req_len.to_bytes(2, "big")
        chunk_size = req_len // 3
        chunks = [req[:chunk_size], req[chunk_size:chunk_size * 2], req[chunk_size * 2:]]

        cur_seq = (cur_seq + 1) % 0x1_0000_0000
        futs: List[Awaitable[None]] = []
        for ttl in range(1, self._HOP_LIMIT + 1):
            futs.append(self.send(syn_res.make_reply(
                self.src, self.dst, seq=cur_seq, window=4096, urg=True, ack=True, up=req_len,
                payload=chunks[0], **encode_ttl(ttl, win=False, ack=False, up=False, opts=True)  # type: ignore
            ), ttl=ttl))
        await asyncio.wait(futs, loop=self._loop)

        futs = []
        for idx in range(1, 3):
            cur_seq = (cur_seq + chunk_size) % 0x1_0000_0000
            req_len -= chunk_size
            futs.append(self.send(syn_res.make_reply(
                self.src, self.dst, seq=cur_seq, window=4096,
                urg=True, ack=True, up=req_len, payload=chunks[idx]
            ), ttl=self._HOP_LIMIT))
        await asyncio.wait(futs, loop=self._loop)
        del futs

        # Lenient check: make sure target responds with a non-RST
        cur_seq = (cur_seq + len(chunks[-1])) % 0x1_0000_0000
        try:
            # TODO: change timeout?
            ack_res = await self.receive(timeout=30)
        except asyncio.TimeoutError:
            await self.send(Segment(self.src, self.dst, seq=cur_seq, window=0, rst=True))
            return TestResult(self, TEST_FAIL, 1,
                              "Timeout after handshake and request with urgent pointer")

        if ack_res.flags & 0x04:
            result = TestResult(self, TEST_FAIL, 1, "RST in reply to request with urgent pointer")
        else:
            await self.send(Segment(self.src, self.dst, seq=cur_seq, window=0, rst=True))
            result = TestResult(self, TEST_PASS)
        await asyncio.sleep(10, loop=self._loop)

        # Urgent data supported, check for middlebox interference
        return self._detect_mboxes("URG/UP modified", check_data=chck_up, win=False,
                                   ack=False, up=False, opts=True) or result

    def _quote_diff(self, icmp: ICMPQuote[IPAddressType], *, data: bytes = None) \
            -> Optional[Tuple[str, str]]:
        if data is None or len(icmp.quote) < 20:
            # Urgent pointer not included in function call or in quote
            return None

        # URG flag and UP field may not be modified
        urg = icmp.quote[13] & 0x20
        up = icmp.quote[18:20]
        if not (urg and up == data):
            return f"0x20,{data.hex()}", f"{urg:#04x},{up.hex()}"

        return None
