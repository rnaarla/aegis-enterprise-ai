"""SRE Resilience Primitives: $O(1)$ Circuit Breaker & Full-Jitter Exponential Backoff."""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from enum import StrEnum


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitOpenError(RuntimeError):
    """Raised immediately ($O(1)$ fail-fast) when a downstream circuit breaker is OPEN."""

    def __init__(self, name: str, retry_after_seconds: float) -> None:
        super().__init__(f"Circuit {name!r} is OPEN; retry after {retry_after_seconds:.2f}s")
        self.circuit_name = name
        self.retry_after_seconds = retry_after_seconds


class TransientDependencyError(RuntimeError):
    """Wrapper signaling a retryable transient upstream fault (e.g. HTTP 502/503/504/timeout)."""


class CircuitBreaker:
    """Thread-safe $O(1)$-state Circuit Breaker (`CLOSED -> OPEN -> HALF_OPEN -> CLOSED`).

    Prevents cascading thread/connection pool exhaustion when legacy SOAP ERPs or GPU nodes
    degrade under load.
    """

    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int = 5,
        recovery_timeout_seconds: float = 15.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_timeout_seconds <= 0:
            raise ValueError("recovery_timeout_seconds must be > 0")
        self.name = name
        self._threshold = failure_threshold
        self._recovery_timeout = recovery_timeout_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at = 0.0
        self._half_open_probe_inflight = False

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if (
                self._state == CircuitState.OPEN
                and (self._clock() - self._opened_at) >= self._recovery_timeout
            ):
                return CircuitState.HALF_OPEN
            return self._state

    def call[T](
        self,
        fn: Callable[[], T],
        *,
        trip_on: tuple[type[BaseException], ...] = (TransientDependencyError, OSError),
    ) -> T:
        """Execute `fn` guarded by the circuit breaker state machine."""
        now = self._clock()
        is_probe = False
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = now - self._opened_at
                if elapsed < self._recovery_timeout:
                    raise CircuitOpenError(self.name, self._recovery_timeout - elapsed)
                self._state = CircuitState.HALF_OPEN
                self._half_open_probe_inflight = False

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_probe_inflight:
                    raise CircuitOpenError(self.name, self._recovery_timeout)
                self._half_open_probe_inflight = True
                is_probe = True

        try:
            result = fn()
        except trip_on:
            with self._lock:
                self._consecutive_failures += 1
                if is_probe or self._consecutive_failures >= self._threshold:
                    self._state = CircuitState.OPEN
                    self._opened_at = self._clock()
                    self._half_open_probe_inflight = False
            raise
        except BaseException:
            if is_probe:
                with self._lock:
                    self._half_open_probe_inflight = False
            raise
        else:
            with self._lock:
                self._state = CircuitState.CLOSED
                self._consecutive_failures = 0
                self._half_open_probe_inflight = False
            return result


def execute_with_full_jitter_retry[T](
    fn: Callable[[], T],
    *,
    max_attempts: int = 3,
    base_delay_seconds: float = 0.02,
    max_delay_seconds: float = 0.5,
    retryable_exceptions: tuple[type[BaseException], ...] = (TransientDependencyError, OSError),
    sleep_fn: Callable[[float], None] = time.sleep,
) -> T:
    """Retry idempotent calls using AWS Full-Jitter backoff (`Uniform(0, min(cap, base * 2^i))`)."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    rng = random.SystemRandom()
    last_exc: BaseException | None = None

    for attempt in range(max_attempts):
        try:
            return fn()
        except retryable_exceptions as exc:
            last_exc = exc
            if attempt + 1 >= max_attempts:
                raise
            cap = min(max_delay_seconds, base_delay_seconds * (2**attempt))
            sleep_fn(rng.uniform(0.0, cap))

    assert last_exc is not None
    raise last_exc
