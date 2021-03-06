import time
import math


class OutOfTokensError(Exception):
    pass


# Every refill_interval seconds, refill_amount tokens are added to the bucket
# up to a maximum of cap. A send operation removes tokens from the bucket.
# The default (1 token per call) corresponds to a packet-based limiter.
# See https://en.wikipedia.org/wiki/Token_bucket
class TokenBucket(object):
    __slots__ = ("_tokens", "_cap", "_increment", "_interval", "_last_update")

    def __init__(self, refill_amount: int, refill_interval: float, cap: int) -> None:
        self._tokens = self._cap = cap
        self._increment = refill_amount
        self._interval = refill_interval
        self._last_update = time.monotonic()

    def _update_bucket(self) -> None:
        intervals = math.floor((time.monotonic() - self._last_update) / self._interval)
        if intervals == 0:
            return

        self._tokens = min(self._cap, self._tokens + intervals * self._increment)
        self._last_update += intervals * self._interval

    def take(self, tokens: int = 1) -> None:
        self._update_bucket()
        if self._tokens < tokens:
            raise OutOfTokensError()

        self._tokens -= tokens
