from typing import Sized, SupportsBytes, ClassVar, Sequence, Tuple
import struct
import math

from .options import BaseOption, parse_options
from .checksum import calc_checksum
from ..types import IPAddressType


# Segments are immutable
class Segment(Sized, SupportsBytes):
    # src_port, dst_port, seq, ack_seq, data offset/reserved bits, flags, window, checksum, up
    _TCP_HEAD: ClassVar[struct.Struct] = struct.Struct(">HHIIBBHHH")
    assert _TCP_HEAD.size == 20

    # src, dst are (addr: IPAddressType, port: int) tuples. flags int takes precedence over bools.
    def __init__(self, src: Tuple[IPAddressType, int], dst: Tuple[IPAddressType, int],
                 seq: int, window: int, ack_seq: int = 0, cwr: bool = False, ece: bool = False,
                 urg: bool = False, ack: bool = False, psh: bool = False, rst: bool = False,
                 syn: bool = False, fin: bool = False, flags: int = None, checksum: bytes = None,
                 up: int = 0, options: Sequence[BaseOption] = (), payload: bytes = b'') -> None:
        opt_len = sum(len(o) for o in options)
        head_rows = 5
        if opt_len:
            head_rows += math.ceil(opt_len / 4.0)

        doff_rsrvd = (head_rows << 4)  # data offset + reserved bits (zeros)
        if flags is None:
            flags = ((cwr << 7) | (ece << 6) | (urg << 5) | (ack << 4) |
                     (psh << 3) | (rst << 2) | (syn << 1) | fin)

        self._head_len = head_rows * 4
        head = bytearray(self._head_len)
        try:
            self._TCP_HEAD.pack_into(head, 0, src[1], dst[1], seq, ack_seq,
                                     doff_rsrvd, flags, window, 0, up)
        except struct.error as e:
            raise OverflowError(str(e)) from e
        if opt_len:
            head[20:20 + opt_len] = b''.join(map(bytes, options))

        if checksum is None:
            # Checksum field is explicitly set to zero in _TCP_HEAD.pack_into call
            checksum = calc_checksum(src[0].packed, dst[0].packed, head, payload)
        head[16:18] = checksum

        self._raw = bytes(head) + payload
        self._options = tuple(options)

    # Negative seq is used as fallback if ACK is not set (see below)
    def make_reply(self, src_addr: IPAddressType, dst_addr: IPAddressType, window: int,
                   seq: int = None, ack_seq: int = None, cwr: bool = False, ece: bool = False,
                   urg: bool = False, ack: bool = False, psh: bool = False, rst: bool = False,
                   syn: bool = False, fin: bool = False, flags: int = None, checksum: bytes = None,
                   up: int = 0, options: Sequence[BaseOption] = (),
                   payload: bytes = b'') -> "Segment":
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

        src = (src_addr, self.dst_port)
        dst = (dst_addr, self.src_port)
        return Segment(src, dst, seq, window, ack_seq, cwr, ece, urg, ack,
                       psh, rst, syn, fin, flags, checksum, up, options, payload)

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

        # calc_checksum doesn't differentiate between TCP header and payload
        checksum = calc_checksum(src_addr, dst_addr, b'', data)
        data[16:18] = check_old
        if checksum != check_old:
            raise ValueError("Checksum mismatch")

        # parse_options consumes used data so it must be copied here
        opt_data = bytearray(data[20:head_len])
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
