"""Adaptive AIMD (`Gradient2` / TCP-Vegas style) Concurrency Limiter for Legacy Systems.

Protects fragile single-instance enterprise systems (e.g., SAP ECC/S4HANA ABAP dialog work
processes, legacy SOAP gateways) from bursty AI agent storms by dynamically adjusting the
in-flight concurrency limit based on observed RTT queueing gradient (`min_rtt / ewma_rtt`):
- Queue-free (`gradient >= 0.90`): Additive increase (`limit += 1`, up to `max_limit`).
- Queue buildup (`gradient < 0.90`) or explicit overload fault: Multiplicative backoff
  (`limit = max(min_limit, limit * backoff_ratio)`).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass


class BackpressureShedError(RuntimeError):
    """Raised immediately (`O(1)`) when in-flight calls reach the adaptive AIMD concurrency ceiling."""

    def __init__(self, limiter_name: str, current_limit: int, inflight: int) -> None:
        super().__init__(
            f"AIMD limiter {limiter_name!r} shed load (inflight={inflight}, limit={current_limit})"
        )
        self.limiter_name = limiter_name
        self.current_limit = current_limit
        self.inflight = inflight


@dataclass(frozen=True)
class AIMDSnapshot:
    name: str
    current_limit: int
    inflight: int
    min_rtt_seconds: float
    ewma_rtt_seconds: float
    gradient: float
    shed_total: int


class AIMDConcurrencyLimiter:
    """Thread-safe `O(1)` latency-gradient adaptive concurrency limiter."""

    def __init__(
        self,
        name: str,
        *,
        initial_limit: int = 16,
        min_limit: int = 2,
        max_limit: int = 64,
        backoff_ratio: float = 0.75,
        ewma_alpha: float = 0.25,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if min_limit < 1 or initial_limit < min_limit or max_limit < initial_limit:
            raise ValueError("Require 1 <= min_limit <= initial_limit <= max_limit")
        if not (0.5 <= backoff_ratio < 1.0):
            raise ValueError("backoff_ratio must be in [0.5, 1.0)")
        self.name = name
        self._limit = float(initial_limit)
        self._min_limit = float(min_limit)
        self._max_limit = float(max_limit)
        self._backoff = backoff_ratio
        self._alpha = ewma_alpha
        self._clock = clock
        self._lock = threading.Lock()
        self._inflight = 0
        self._min_rtt: float | None = None
        self._ewma_rtt: float | None = None
        self._last_gradient = 1.0
        self._shed_total = 0

    @property
    def current_limit(self) -> int:
        with self._lock:
            return int(self._limit)

    def snapshot(self) -> AIMDSnapshot:
        with self._lock:
            return AIMDSnapshot(
                name=self.name,
                current_limit=int(self._limit),
                inflight=self._inflight,
                min_rtt_seconds=round(self._min_rtt or 0.0, 6),
                ewma_rtt_seconds=round(self._ewma_rtt or 0.0, 6),
                gradient=round(self._last_gradient, 4),
                shed_total=self._shed_total,
            )

    @contextmanager
    def acquire(self) -> Iterator[int]:
        """Acquire an in-flight permit or fail-fast (`O(1)`) with `BackpressureShedError`."""
        with self._lock:
            eff_limit = int(self._limit)
            if self._inflight >= eff_limit:
                self._shed_total += 1
                raise BackpressureShedError(self.name, eff_limit, self._inflight)
            self._inflight += 1
            was_saturated = self._inflight >= max(1, eff_limit // 2)

        t0 = self._clock()
        overload_fault = False
        try:
            yield eff_limit
        except (TimeoutError, ConnectionError, OSError):
            overload_fault = True
            raise
        finally:
            rtt = max(0.00005, self._clock() - t0)
            with self._lock:
                self._inflight = max(0, self._inflight - 1)
                if overload_fault:
                    self._limit = max(self._min_limit, self._limit * self._backoff)
                    self._last_gradient = 0.5
                else:
                    if self._min_rtt is None or rtt < self._min_rtt:
                        self._min_rtt = rtt
                    else:
                        # Gentle upward drift (`0.1%`) so stale historical min_rtt adapts to baseline shifts
                        self._min_rtt = self._min_rtt * 1.001
                    self._ewma_rtt = (
                        rtt
                        if self._ewma_rtt is None
                        else (self._alpha * rtt + (1.0 - self._alpha) * self._ewma_rtt)
                    )
                    gradient = min(1.0, self._min_rtt / max(0.00005, self._ewma_rtt))
                    self._last_gradient = gradient
                    if gradient < 0.85:
                        self._limit = max(
                            self._min_limit,
                            self._limit * max(self._backoff, gradient),
                        )
                    elif gradient >= 0.90 and was_saturated:
                        # Additive increase (+1 per full window, i.e., +1/limit per request)
                        self._limit = min(self._max_limit, self._limit + (1.0 / max(1.0, self._limit)))
