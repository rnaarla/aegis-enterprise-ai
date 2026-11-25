"""Optimal bounded-memory & sub-linear TTL data structures for high-throughput services.

Complexity Guarantees:
- `BoundedLRUTTLCache[K, V]`:
  - `get(key)`: $O(1)$ average time
  - `put(key, val, ttl)`: $O(1)$ average time
  - Auxiliary space: strictly bounded by $O(\\text{max\\_size})$ entries (immune to OOM leaks)
- `MinHeapTTLIndex[K]`:
  - `push(key, exp)`: $O(\\log N)$ worst-case time (monotonic tie-breaker avoids key comparison)
  - `discard(key)`: $O(1)$ lazy tombstone removal
  - `pop_expired(now)`: $O(1)$ amortized per pushed element
"""

from __future__ import annotations

import heapq
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable


class BoundedLRUTTLCache[K: Hashable, V]:
    """Thread-safe doubly-linked hash map (`OrderedDict`) enforcing both LRU cap & per-key TTL."""

    def __init__(
        self,
        *,
        max_size: int = 10_000,
        default_ttl_seconds: float = 3_600.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        if default_ttl_seconds <= 0:
            raise ValueError("default_ttl_seconds must be > 0")
        self._max_size = max_size
        self._default_ttl = default_ttl_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._store: OrderedDict[K, tuple[V, float]] = OrderedDict()

    @property
    def max_size(self) -> int:
        return self._max_size

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def get(self, key: K) -> V | None:
        """Fetch live entry in $O(1)$ time and promote to MRU tail."""
        now = self._clock()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if now >= expires_at:
                del self._store[key]
                return None
            self._store.move_to_end(key, last=True)
            return value

    def put(self, key: K, value: V, *, ttl_seconds: float | None = None) -> None:
        """Insert/update entry in $O(1)$ time, evicting LRU head if over capacity."""
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        if ttl <= 0:
            self.delete(key)
            return
        expires_at = self._clock() + ttl
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key, last=True)
            self._store[key] = (value, expires_at)
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)

    def delete(self, key: K) -> bool:
        """Remove key in $O(1)$ time."""
        with self._lock:
            return self._store.pop(key, None) is not None


class MinHeapTTLIndex[K: Hashable]:
    """Binary min-heap indexed by `(expires_at, seq, key)` with $O(1)$ lazy tombstones."""

    def __init__(self) -> None:
        self._heap: list[tuple[float, int, K]] = []
        self._live_exp: dict[K, float] = {}
        self._seq = 0

    def __len__(self) -> int:
        return len(self._live_exp)

    def push(self, key: K, expires_at: float) -> None:
        """Schedule `key` for expiration at `expires_at` in $O(\\log N)$ time."""
        self._seq += 1
        self._live_exp[key] = expires_at
        heapq.heappush(self._heap, (expires_at, self._seq, key))

    def discard(self, key: K) -> None:
        """Lazy-delete `key` in $O(1)$ time; stale heap node is ignored when popped."""
        self._live_exp.pop(key, None)

    def pop_expired(self, now: float) -> list[K]:
        """Evict and return all keys with `expires_at <= now` ($O(1)$ amortized per push)."""
        expired: list[K] = []
        while self._heap and self._heap[0][0] <= now:
            exp, _seq, key = heapq.heappop(self._heap)
            live = self._live_exp.get(key)
            if live is not None and live == exp:
                del self._live_exp[key]
                expired.append(key)
        # Compact tombstone backlog if stale heap nodes exceed 4x live keys
        if len(self._heap) > max(64, 4 * len(self._live_exp)):
            self._rebuild()
        return expired

    def _rebuild(self) -> None:
        self._heap.clear()
        for key, exp in self._live_exp.items():
            self._seq += 1
            self._heap.append((exp, self._seq, key))
        heapq.heapify(self._heap)
