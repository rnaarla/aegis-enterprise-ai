"""Thread-safe LIFO PostgreSQL connection pool with automatic broken-connection eviction."""

from __future__ import annotations

import queue
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import pq


class PostgresPoolExhaustedError(TimeoutError):
    """Raised when all pooled PostgreSQL connections are leased past `acquire_timeout`."""


class BoundedPostgresPool:
    """Lightweight LIFO connection pool keeping hot backend processes warm in OS cache.

    Guarantees:
    - Bounded concurrency: never opens more than `max_connections` backends.
    - Clean state: rolls back any uncommitted/aborted transaction before returning to pool,
      resetting `SET LOCAL` role and GUC bindings automatically.
    - Broken-socket resilience: discards closed/broken connections and dials fresh replacements.
    """

    def __init__(
        self,
        dsn: str,
        *,
        max_connections: int = 16,
        acquire_timeout_seconds: float = 5.0,
        statement_timeout_ms: int = 2_000,
    ) -> None:
        if max_connections < 1:
            raise ValueError("max_connections must be >= 1")
        self._dsn = dsn
        self._max = max_connections
        self._timeout = acquire_timeout_seconds
        self.statement_timeout_ms = statement_timeout_ms
        self._idle: queue.LifoQueue[psycopg.Connection[Any]] = queue.LifoQueue(
            maxsize=max_connections
        )
        self._slots = threading.BoundedSemaphore(max_connections)
        self._closed = False

    @property
    def dsn(self) -> str:
        return self._dsn

    @contextmanager
    def connection(self) -> Iterator[psycopg.Connection[Any]]:
        if self._closed:
            raise RuntimeError("BoundedPostgresPool is closed")
        acquired = self._slots.acquire(timeout=self._timeout)
        if not acquired:
            raise PostgresPoolExhaustedError(
                f"Timed out waiting {self._timeout}s for PostgreSQL pool slot (max={self._max})"
            )

        conn: psycopg.Connection[Any] | None = None
        try:
            while True:
                try:
                    candidate = self._idle.get_nowait()
                except queue.Empty:
                    conn = psycopg.connect(self._dsn)
                    break
                if not candidate.closed and not candidate.broken:
                    conn = candidate
                    break
                candidate.close()

            yield conn
        except Exception:
            if conn is not None and not conn.closed and not conn.broken:
                conn.rollback()
            raise
        finally:
            if conn is not None:
                if self._closed or conn.closed or conn.broken:
                    conn.close()
                else:
                    if conn.info.transaction_status != pq.TransactionStatus.IDLE:
                        conn.rollback()
                    self._idle.put_nowait(conn)
            self._slots.release()

    def close(self) -> None:
        self._closed = True
        while True:
            try:
                conn = self._idle.get_nowait()
                conn.close()
            except queue.Empty:
                break
