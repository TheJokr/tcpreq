from .segment import Segment
from .options import end_of_options, noop as noop_option, MSSOption


# seq, left, right are assumed to be less than 2^32
def check_window(seq: int, left: int, right: int) -> bool:
    """Check whether seq is contained in [left, right) (modulo 2^32)."""
    if left <= right:
        return left <= seq < right
    else:
        return left <= seq or seq < right
