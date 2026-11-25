"""Sub-linear $O(\\log N)$ / $O(k)$ JTI, session, and agent kill-switch revocation stores."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from aegis_core.dsa import BoundedLRUTTLCache, MinHeapTTLIndex


class InMemoryRevocationStore:
    """Thread-safe revocation store using a Min-Heap TTL queue + inverted hash indexes.

    Complexity Improvements over naive dict scanning:
    - `register_issued_token`: $O(\\log N)$ heap push + $O(1)$ amortized expiry eviction
      (replaces $O(N)$ full-table scan per login -> eliminates $O(N^2)$ scaling bottleneck).
    - `revoke_all_for_subject` / `revoke_all_for_agent`: $O(k)$ where $k$ is strictly the
      target principal/agent's active tokens (replaces $O(N_{\\text{cluster}})$ scan).
    - `is_revoked`: $O(1)$ hash lookup across bounded LRU-TTL revocation caches.
    """

    def __init__(
        self,
        *,
        max_revoked_cache_size: int = 100_000,
        epoch_clock: Callable[[], float] = time.time,
    ) -> None:
        self._clock = epoch_clock
        self._lock = threading.RLock()
        self._active_tokens: dict[str, tuple[str, str, int]] = {}
        self._expiry_heap: MinHeapTTLIndex[str] = MinHeapTTLIndex()
        self._by_subject: dict[str, set[str]] = {}
        self._by_agent: dict[str, set[str]] = {}

        self._revoked_jtis: BoundedLRUTTLCache[str, str] = BoundedLRUTTLCache(
            max_size=max_revoked_cache_size,
            default_ttl_seconds=600.0,
            clock=epoch_clock,
        )
        self._revoked_subjects: BoundedLRUTTLCache[str, str] = BoundedLRUTTLCache(
            max_size=max_revoked_cache_size,
            default_ttl_seconds=3_600.0,
            clock=epoch_clock,
        )
        self._revoked_agents: BoundedLRUTTLCache[str, str] = BoundedLRUTTLCache(
            max_size=4_096,
            default_ttl_seconds=86_400.0,
            clock=epoch_clock,
        )

    def _evict_expired_locked(self, now: float) -> None:
        for expired_jti in self._expiry_heap.pop_expired(now):
            meta = self._active_tokens.pop(expired_jti, None)
            if meta is not None:
                sub, ag_id, _ = meta
                self._discard_index_locked(self._by_subject, sub, expired_jti)
                self._discard_index_locked(self._by_agent, ag_id, expired_jti)

    @staticmethod
    def _discard_index_locked(index: dict[str, set[str]], bucket_key: str, jti: str) -> None:
        bucket = index.get(bucket_key)
        if bucket is not None:
            bucket.discard(jti)
            if not bucket:
                del index[bucket_key]

    def register_issued_token(
        self,
        jti: str,
        human_subject: str,
        agent_id: str,
        exp_epoch: int,
    ) -> None:
        now = self._clock()
        with self._lock:
            self._evict_expired_locked(now)
            if float(exp_epoch) <= now:
                return
            self._active_tokens[jti] = (human_subject, agent_id, exp_epoch)
            self._expiry_heap.push(jti, float(exp_epoch))
            self._by_subject.setdefault(human_subject, set()).add(jti)
            self._by_agent.setdefault(agent_id, set()).add(jti)

    def revoke_jti(self, jti: str, exp_epoch: int, reason: str) -> None:
        now = self._clock()
        ttl = float(exp_epoch) - now
        with self._lock:
            meta = self._active_tokens.pop(jti, None)
            self._expiry_heap.discard(jti)
            if meta is not None:
                sub, ag_id, _ = meta
                self._discard_index_locked(self._by_subject, sub, jti)
                self._discard_index_locked(self._by_agent, ag_id, jti)
            if ttl > 0:
                self._revoked_jtis.put(jti, reason, ttl_seconds=ttl)

    def revoke_all_for_subject(self, human_subject: str, reason: str) -> int:
        now = self._clock()
        with self._lock:
            self._evict_expired_locked(now)
            self._revoked_subjects.put(human_subject, reason, ttl_seconds=3_600.0)
            jtis = self._by_subject.pop(human_subject, set())
            count = 0
            for jti in jtis:
                meta = self._active_tokens.pop(jti, None)
                self._expiry_heap.discard(jti)
                if meta is not None:
                    _sub, ag_id, exp = meta
                    self._discard_index_locked(self._by_agent, ag_id, jti)
                    rem_ttl = float(exp) - now
                    if rem_ttl > 0:
                        self._revoked_jtis.put(jti, reason, ttl_seconds=rem_ttl)
                        count += 1
            return count

    def revoke_all_for_agent(self, agent_id: str, reason: str) -> int:
        now = self._clock()
        with self._lock:
            self._evict_expired_locked(now)
            self._revoked_agents.put(agent_id, reason, ttl_seconds=86_400.0)
            jtis = self._by_agent.pop(agent_id, set())
            count = 0
            for jti in jtis:
                meta = self._active_tokens.pop(jti, None)
                self._expiry_heap.discard(jti)
                if meta is not None:
                    sub, _ag_id, exp = meta
                    self._discard_index_locked(self._by_subject, sub, jti)
                    rem_ttl = float(exp) - now
                    if rem_ttl > 0:
                        self._revoked_jtis.put(jti, reason, ttl_seconds=rem_ttl)
                        count += 1
            return count

    def is_revoked(self, jti: str, human_subject: str, agent_id: str) -> tuple[bool, str | None]:
        with self._lock:
            ag_reason = self._revoked_agents.get(agent_id)
            if ag_reason is not None:
                return True, f"agent_killswitch:{ag_reason}"
            sub_reason = self._revoked_subjects.get(human_subject)
            if sub_reason is not None:
                return True, f"subject_revoked:{sub_reason}"
            jti_reason = self._revoked_jtis.get(jti)
            if jti_reason is not None:
                return True, f"jti_revoked:{jti_reason}"
        return False, None


class RedisRevocationStore:
    """Production multi-replica Redis/Valkey revocation store using single-RTT pipelines."""

    def __init__(self, redis_client: Any, key_prefix: str = "aegis:rev") -> None:
        self._redis = redis_client
        self._p = key_prefix

    def register_issued_token(
        self,
        jti: str,
        human_subject: str,
        agent_id: str,
        exp_epoch: int,
    ) -> None:
        ttl = max(1, exp_epoch - int(time.time()))
        pipe = self._redis.pipeline()
        pipe.setex(f"{self._p}:meta:{jti}", ttl, f"{human_subject}|{agent_id}|{exp_epoch}")
        pipe.sadd(f"{self._p}:sub_idx:{human_subject}", jti)
        pipe.expire(f"{self._p}:sub_idx:{human_subject}", 600)
        pipe.sadd(f"{self._p}:agent_idx:{agent_id}", jti)
        pipe.expire(f"{self._p}:agent_idx:{agent_id}", 600)
        pipe.execute()

    def revoke_jti(self, jti: str, exp_epoch: int, reason: str) -> None:
        ttl = max(60, exp_epoch - int(time.time()))
        self._redis.setex(f"{self._p}:jti:{jti}", ttl, reason)

    def revoke_all_for_subject(self, human_subject: str, reason: str) -> int:
        jtis = self._redis.smembers(f"{self._p}:sub_idx:{human_subject}")
        pipe = self._redis.pipeline()
        pipe.setex(f"{self._p}:sub_block:{human_subject}", 3_600, reason)
        count = 0
        for raw_jti in jtis:
            jti = raw_jti.decode("utf-8") if isinstance(raw_jti, bytes) else str(raw_jti)
            pipe.setex(f"{self._p}:jti:{jti}", 600, reason)
            count += 1
        pipe.execute()
        return count

    def revoke_all_for_agent(self, agent_id: str, reason: str) -> int:
        jtis = self._redis.smembers(f"{self._p}:agent_idx:{agent_id}")
        pipe = self._redis.pipeline()
        pipe.setex(f"{self._p}:agent_block:{agent_id}", 86_400, reason)
        count = 0
        for raw_jti in jtis:
            jti = raw_jti.decode("utf-8") if isinstance(raw_jti, bytes) else str(raw_jti)
            pipe.setex(f"{self._p}:jti:{jti}", 600, reason)
            count += 1
        pipe.execute()
        return count

    def is_revoked(self, jti: str, human_subject: str, agent_id: str) -> tuple[bool, str | None]:
        pipe = self._redis.pipeline()
        pipe.get(f"{self._p}:agent_block:{agent_id}")
        pipe.get(f"{self._p}:sub_block:{human_subject}")
        pipe.get(f"{self._p}:jti:{jti}")
        agent_reason, sub_reason, jti_reason = pipe.execute()
        if agent_reason is not None:
            r = (
                agent_reason.decode("utf-8")
                if isinstance(agent_reason, bytes)
                else str(agent_reason)
            )
            return True, f"agent_killswitch:{r}"
        if sub_reason is not None:
            r = sub_reason.decode("utf-8") if isinstance(sub_reason, bytes) else str(sub_reason)
            return True, f"subject_revoked:{r}"
        if jti_reason is not None:
            r = jti_reason.decode("utf-8") if isinstance(jti_reason, bytes) else str(jti_reason)
            return True, f"jti_revoked:{r}"
        return False, None
