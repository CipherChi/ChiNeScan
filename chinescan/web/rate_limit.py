"""Small process-local sliding-window request limiter."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from math import ceil


class InProcessRateLimiter:
    def __init__(
        self,
        limits: dict[str, tuple[int, int]],
        *,
        max_buckets: int = 4096,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits
        self.max_buckets = max_buckets
        self.clock = clock
        self._buckets: dict[tuple[str, str], deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, category: str, client: str) -> int:
        limit, window = self.limits[category]
        now = self.clock()
        key = (category, client)
        with self._lock:
            self._prune(now)
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self.max_buckets:
                    self._buckets.pop(next(iter(self._buckets)))
                bucket = deque()
                self._buckets[key] = bucket
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if len(bucket) >= limit:
                return max(1, ceil(window - (now - bucket[0])))
            bucket.append(now)
            return 0

    def _prune(self, now: float) -> None:
        for key, bucket in tuple(self._buckets.items()):
            _limit, window = self.limits[key[0]]
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if not bucket:
                del self._buckets[key]
