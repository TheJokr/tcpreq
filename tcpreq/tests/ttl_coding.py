from typing import Sequence, Dict, Counter as CounterType, Union
from collections import Counter

from ..tcp import noop_option, end_of_options
from ..tcp.options import BaseOption


def encode_ttl(ttl: int, *, win: bool = True, ack: bool = True, up: bool = True,
               opts: bool = True) -> Dict[str, Union[int, Sequence[BaseOption]]]:
    kwargs: Dict[str, Union[int, Sequence[BaseOption]]] = {}

    # Encoding is similar to IPv4 header
    enc_16 = (ttl << 11) | (ttl << 5) | ttl
    if win:
        kwargs["window"] = enc_16
    if ack:
        kwargs["ack_seq"] = (enc_16 << 16) | enc_16
    if up:
        kwargs["up"] = enc_16
    if opts:
        kwargs["options"] = (noop_option,) * ttl + (end_of_options,)

    return kwargs


def decode_ttl(quote: bytes, ttl_guess: int, hop_limit: int, *, win: bool = True,
               ack: bool = True, up: bool = True, opts: bool = True) -> int:
    qlen = len(quote)
    ttl_guess = min(ttl_guess, hop_limit)
    if qlen < 12:
        return ttl_guess

    if opts and qlen >= 24:
        div = quote[12] >> 4
        head_len = div << 2

        # Try to recover TTL from DO+options (see IPv4TestMultiplexer._recover_ttl)
        if div > 5 and qlen >= head_len:
            div -= 6
            mod = None
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
                return 4 * div + mod

    ttl_count: CounterType[int] = Counter()
    if ack:
        ack_val = int.from_bytes(quote[8:12], "big")
        ttl_count.update((ack_val >> i) & 0x1f for i in (27, 21, 16, 11, 5, 0))

    if win and qlen >= 16:
        win_val = int.from_bytes(quote[14:16], "big")
        ttl_count.update((win_val >> i) & 0x1f for i in (11, 5, 0))

    if up and qlen >= 20:
        up_val = int.from_bytes(quote[18:20], "big")
        ttl_count.update((up_val >> i) & 0x1f for i in (11, 5, 0))

    # Get most likely TTL value from ttl_count. There are up to 12 entries.
    # At least 33% of all votes are required to be selected.
    # This means only the top 3 values can be eligible.
    thresh = ack * 2 + win + up
    candidates = list(filter(lambda c: c[0] <= hop_limit and c[1] >= thresh,
                             ttl_count.most_common(3)))
    clen = len(candidates)

    if clen == 1:
        # Trivial case
        return candidates[0][0]
    elif clen == 2:
        diff = candidates[0][1] - candidates[1][1]
        if diff >= 2 or candidates[0][0] == ttl_guess:
            return candidates[0][0]
        elif candidates[1][0] == ttl_guess:
            return candidates[1][0]
        elif diff > 0:
            return candidates[0][0]
    elif clen == 0:  # clen == 0
        # Fall back to lower layer guess
        return ttl_guess

    # Must be a 2- or 3-way tie
    return 0
