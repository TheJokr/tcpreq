from abc import abstractmethod
from typing import Generic, ClassVar, Awaitable, Iterator, List, Tuple, Deque, Union, Optional
import time
import math
import operator
import random
import asyncio

from .result import TestResult, TestResultStatus, TEST_UNK, TEST_FAIL
from .ttl_coding import decode_ttl
from ..types import IPAddressType, ScanHost, OutgoingPacket, ICMPQuote
from ..tcp import Segment


class BaseTest(Generic[IPAddressType]):
    """Abstract base class for all tests."""
    # Hop limit for middlebox detection (tracebox)
    _HOP_LIMIT: ClassVar[int] = 30

    # Make sure _HOP_LIMIT fits into 5 bits (to save it in the IPv4 ID field 3 times).
    assert math.floor(math.log2(_HOP_LIMIT) + 1) <= 5
    # Make sure _HOP_LIMIT can be encoded into DO+options (39 possible non-zero values).
    assert 1 <= _HOP_LIMIT <= 39

    # MUST be overwritten in derived classes: theoretical maximum packet rate (per second)
    # Used to automatically chunk inputs based on packet rate limit
    MAX_PACKET_RATE: ClassVar[float]

    # MAY be overwritten in derived classes: whether to skip later tests after this one fails
    FAIL_EARLY: ClassVar[bool] = False

    __slots__ = ("src", "dst", "_path", "_isns", "recv_queue",
                 "quote_queue", "send_queue", "_loop")

    def __init__(self, src: ScanHost[IPAddressType], dst: ScanHost[IPAddressType],
                 *, loop: asyncio.AbstractEventLoop = None) -> None:
        if loop is None:
            loop = asyncio.get_event_loop()

        self.src: ScanHost[IPAddressType] = src
        self.dst: ScanHost[IPAddressType] = dst
        self._path: List[Tuple[int, str]] = []
        self._isns: List[Tuple[float, int]] = []
        self.recv_queue: "asyncio.Queue[bytearray]" = asyncio.Queue(loop=loop)
        self.quote_queue: List[ICMPQuote[IPAddressType]] = []
        self.send_queue: Optional[Deque[OutgoingPacket[IPAddressType]]] = None
        self._loop = loop

    def send(self, seg: Segment, *, ttl: int = None) -> Awaitable[None]:
        """Send a segment, optionally with an explicit TTL for middlebox detection."""
        assert self.send_queue is not None, "Test is not registered with any multiplexer"
        assert ttl is None or 1 <= ttl <= self._HOP_LIMIT

        fut = self._loop.create_future()
        self.send_queue.append(OutgoingPacket(seg, self.dst.ip, ttl, fut))
        return fut

    async def receive(self, timeout: float) -> Segment:
        """Asynchronously return the next received segment with a timeout."""
        while timeout > 0:
            start = time.monotonic()
            data = await asyncio.wait_for(self.recv_queue.get(), timeout, loop=self._loop)
            timeout -= (time.monotonic() - start)

            try:
                seg = Segment.from_bytes(self.dst.ip.packed, self.src.ip.packed, data)
            except ValueError:
                # Discard invalid segments silently and retry
                pass
            else:
                if seg.flags & 0x02:
                    # Collect ISNs for ISN predictability meta-test
                    self._isns.append((time.monotonic(), seg.seq))
                return seg

        raise asyncio.TimeoutError()

    async def _synchronize(self, sent_seq: int, timeout: float,
                           test_stage: int) -> Union[Segment, TestResult]:
        """Handle 3WH failures after the initial SYN has been sent."""
        # Simultaneous open is not supported (targets are listening hosts)
        exp_ack = (sent_seq + 1) % 0x1_0000_0000
        try:
            syn_res = await self.receive(timeout=timeout)
        except asyncio.TimeoutError:
            return TestResult(self, TEST_UNK, test_stage, "Timeout during handshake")
        if syn_res.flags & 0x04 and syn_res.ack_seq == exp_ack:
            return TestResult(self, TEST_UNK, test_stage, "RST in reply to SYN during handshake")
        elif (syn_res.flags & 0x12) != 0x12:
            result = TestResult(self, TEST_FAIL, test_stage,
                                "Non-SYN-ACK in reply to SYN during handshake")
        elif syn_res.ack_seq != exp_ack:
            result = TestResult(self, TEST_FAIL, test_stage,
                                "Wrong SEQ acked in reply to SYN during handshake")
        else:
            return syn_res

        # Reset connection to be sure
        await self.send(syn_res.make_reset(self.src, self.dst))
        return result

    # Verify reachability once per test (because src port changes)
    async def run_with_reachability(self) -> TestResult:
        cur_seq = random.randint(0, 0xffff_ffff)
        await self.send(Segment(self.src, self.dst, seq=cur_seq, window=30720, syn=True),
                        ttl=self._HOP_LIMIT)

        # TODO: change timeout?
        syn_res = await self._synchronize(cur_seq, timeout=60, test_stage=0)
        if isinstance(syn_res, TestResult):
            syn_res.status = TestResultStatus.DEAD
            syn_res.stage = None
            return syn_res

        await self.send(syn_res.make_reply(self.src, self.dst, window=30720, ack=True))

        # Try closing the connection up to 3 times
        for _ in range(3):
            await self.send(syn_res.make_reset(self.src, self.dst))
            await asyncio.sleep(5, loop=self._loop)
            self.recv_queue = asyncio.Queue(loop=self._loop)

            try:
                await self.receive(timeout=10)
            except asyncio.TimeoutError:
                break
        else:
            return TestResult(self, TestResultStatus.DEAD, None, "RST ignored")

        return await self.run()

    @abstractmethod
    async def run(self) -> TestResult:
        pass

    def _detect_mboxes(self, info: str, check_data: bytes = None, *, win: bool = True,
                       ack: bool = True, up: bool = True, opts: bool = True) -> Optional[TestResult]:
        """Check for middlebox interference using (overwritten) _quote_diff predicate."""
        info = f" ({info})"

        result = None
        mbox_hop = self._HOP_LIMIT + 1

        for icmp in self.quote_queue:
            hop = icmp.hop = decode_ttl(icmp.quote, icmp.hop, self._HOP_LIMIT,
                                        win=win, ack=ack, up=up, opts=opts)
            hop_unk = hop == 0

            # Diff check is only necessary if it could improve the result
            # I.e., if we don't have any result yet (result is None),
            # or if hop is closer than the mbox the current result is based on
            if (hop_unk and result is not None) or hop >= mbox_hop:
                continue

            diff = self._quote_diff(icmp, data=check_data)
            if diff is None:  # quote matches sent segment
                continue

            reason = "Middlebox interference detected"
            reason += " at unknown hop" if hop_unk else f" at or before hop {hop}"
            reason += info
            result = TestResult(self, TEST_UNK, 1, reason, custom={"diff": diff})

            if not hop_unk:
                mbox_hop = hop

        path_gen: Iterator[Tuple[int, str]] = ((icmp.hop, icmp.icmp_src.compressed)
                                               for icmp in self.quote_queue)
        if mbox_hop <= self._HOP_LIMIT:
            path_gen = filter(lambda x: 1 <= x[0] <= mbox_hop, path_gen)

        # Use extend instead of new list here so result is updated as well
        self._path.extend(path_gen)
        self._path.sort(key=operator.itemgetter(0))

        return result

    def _quote_diff(self, icmp: ICMPQuote[IPAddressType], *, data: bytes = None) \
            -> Optional[Tuple[str, str]]:
        """Determine whether the quoted segment has been modified along the path."""
        return None  # not modified
