from typing import ClassVar, Sequence, Tuple, Optional
import struct
import math

from .options import BaseOption, parse_options
from .checksum import calc_checksum
from ..types import IPAddressType, ScanHost


# Segments are immutable
class Segment(object):
    # src_port, dst_port, seq, ack_seq, data offset/reserved bits, flags, window, checksum, up
    _TCP_HEAD: ClassVar[struct.Struct] = struct.Struct(">HHIIBBHHH")
    assert _TCP_HEAD.size == 20

    __slots__ = ("_head_len", "_raw", "_options")

    # src, dst are (addr: IPAddressType, port: int) tuples. flags int takes precedence over bools.
    def __init__(self, src: ScanHost[IPAddressType], dst: ScanHost[IPAddressType], *,
                 seq: int, window: int, ack_seq: int = 0, rsrvd: int = 0, cwr: bool = False,
                 ece: bool = False, urg: bool = False, ack: bool = False, psh: bool = False,
                 rst: bool = False, syn: bool = False, fin: bool = False, flags: int = None,
                 up: int = 0, options: Sequence[BaseOption] = (), payload: bytes = b'') -> None:
        opt_len = sum(len(o) for o in options)
        head_rows = 5
        if opt_len:
            head_rows += math.ceil(opt_len / 4.0)

        doff_rsrvd = (head_rows << 4) | (rsrvd & 0x0f)
        if flags is None:
            flags = ((cwr << 7) | (ece << 6) | (urg << 5) | (ack << 4) |
                     (psh << 3) | (rst << 2) | (syn << 1) | fin)

        self._head_len = head_rows * 4
        head = bytearray(self._head_len)
        try:
            self._TCP_HEAD.pack_into(head, 0, src.port, dst.port, seq, ack_seq,
                                     doff_rsrvd, flags, window, 0, up)
        except struct.error as e:
            raise OverflowError(str(e)) from e
        if opt_len:
            head[20:20 + opt_len] = b''.join(map(bytes, options))

        # Checksum field is explicitly set to zero in _TCP_HEAD.pack_into call
        head[16:18] = calc_checksum(src.ip.packed, dst.ip.packed, head, payload)

        self._raw = bytes(head) + payload
        self._options = tuple(options)

    # Negative seq is used as fallback if ACK is not set (see below)
    def make_reply(self, src: ScanHost[IPAddressType], dst: ScanHost[IPAddressType], *, window: int,
                   seq: int = None, ack_seq: int = None, rsrvd: int = 0, cwr: bool = False,
                   ece: bool = False, urg: bool = False, ack: bool = False, psh: bool = False,
                   rst: bool = False, syn: bool = False, fin: bool = False, flags: int = None,
                   up: int = 0, options: Sequence[BaseOption] = (), payload: bytes = b'') -> "Segment":
        if seq is None or seq < 0:
            if self.flags & 0x10:
                seq = self.ack_seq
            elif seq is not None:
                seq = -(seq + 1)
            else:
                raise ValueError("SEQ not given and ACK not present on this segment")

        if ack_seq is None:
            syn_fin = self.flags & 0x03
            syn_fin = (syn_fin >> 1) + (syn_fin & 0x01)
            payload_len = len(self) - self._head_len
            ack_seq = (self.seq + payload_len + syn_fin) % 0x1_0000_0000  # == 2^32

        return Segment(src, dst, seq=seq, window=window, ack_seq=ack_seq, rsrvd=rsrvd, cwr=cwr,
                       ece=ece, urg=urg, ack=ack, psh=psh, rst=rst, syn=syn, fin=fin, flags=flags,
                       up=up, options=options, payload=payload)

    def make_reset(self, src: ScanHost[IPAddressType], dst: ScanHost[IPAddressType]) -> "Segment":
        # Per RFC 793bis, section 3.4, "Reset Generation", 1. and 2.
        has_ack = self.flags & 0x10
        if has_ack:
            seq = self.ack_seq
            ack_seq: Optional[int] = 0
        else:
            seq = 0
            ack_seq = None

        return self.make_reply(src, dst, seq=seq, window=0, ack_seq=ack_seq, ack=not has_ack, rst=True)

    @classmethod
    def from_bytes(cls, src_addr: bytes, dst_addr: bytes, data: bytearray) -> "Segment":
        dlen = len(data)
        if dlen < 20:
            raise ValueError("Data too short")

        head_len = (data[12] >> 2) & 0b00111100  # == (data[12] >> 4) * 4
        if dlen < head_len:
            raise ValueError("Illegal data offset")

        check_old = data[16:18]
        data[16:18] = b"\x00\x00"

        checksum = calc_checksum(src_addr, dst_addr, data)
        data[16:18] = check_old
        if checksum != check_old:
            raise ValueError("Checksum mismatch")

        opt_data = data[20:head_len]
        options = tuple(parse_options(opt_data))
        if any(b != 0 for b in opt_data):
            raise ValueError("Illegal end-of-header padding")

        res = cls.__new__(cls)  # type: Segment
        res._head_len = head_len
        res._raw = bytes(data)
        res._options = options
        return res

    def __len__(self) -> int:
        return len(self._raw)

    def __bytes__(self) -> bytes:
        return self._raw

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Segment):
            return NotImplemented
        return self._raw == other._raw

    def __hash__(self) -> int:
        return self._raw.__hash__()

    @property
    def src_port(self) -> int:
        return int.from_bytes(self._raw[0:2], "big")

    @property
    def dst_port(self) -> int:
        return int.from_bytes(self._raw[2:4], "big")

    @property
    def seq(self) -> int:
        return int.from_bytes(self._raw[4:8], "big")

    @property
    def ack_seq(self) -> int:
        return int.from_bytes(self._raw[8:12], "big")

    @property
    def flags(self) -> int:
        return self._raw[13]

    @property
    def window(self) -> int:
        return int.from_bytes(self._raw[14:16], "big")

    @property
    def checksum(self) -> bytes:
        return self._raw[16:18]

    @property
    def up(self) -> int:
        return int.from_bytes(self._raw[18:20], "big")

    @property
    def options(self) -> Tuple[BaseOption, ...]:
        return self._options

    @property
    def payload(self) -> bytes:
        return self._raw[self._head_len:]
