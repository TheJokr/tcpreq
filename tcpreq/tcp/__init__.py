from .segment import Segment, ChecksumError
from .options import end_of_options, noop as noop_option, MSSOption


def check_window(seq: int, left: int, right: int) -> bool:
    """Check whether seq is contained in [left, right) (modulo 2^32)."""
    assert all(0 <= i < 0x1_0000_0000 for i in (seq, left, right)), "Arguments must be within [0, 2^32)"
    if left <= right:
        return left <= seq < right
    else:
        return left <= seq or seq < right
