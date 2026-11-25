"""Per-tenant SHA-256 hash-chained audit ledger with $O(1)$-RAM streaming verification.

Scalability & Compliance Improvements:
1. Per-Tenant Hash Chains: Each `tenant_id` maintains an independent monotonic chain
   (`sequence_id = 1, 2, ...` from `GENESIS_PREV_HASH`), allowing a bank's external
   auditor to verify its complete chain without seeing other tenants' hashes.
2. Zero Cross-Tenant Contention: `PostgresAuditLedger.append` uses transactional advisory
   locks (`pg_advisory_xact_lock(hashtext(tenant_id))`) instead of `LOCK TABLE ... EXCLUSIVE`,
   enabling lock-free parallel writes across distinct tenants over a `BoundedPostgresPool`.
3. $O(T_{\\text{tenants}})$ Streaming Verification: `verify_integrity` streams rows in fixed
   chunks (`fetchmany(256)`) rather than loading millions of rows via `fetchall()`.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Literal

from aegis_core.db_pool import BoundedPostgresPool
from aegis_core.models import AuditEventType, AuditRecord

GENESIS_PREV_HASH = "0" * 64


def compute_audit_entry_hash(
    *,
    sequence_id: int,
    occurred_at_iso: str,
    tenant_id: str,
    event_type: AuditEventType,
    human_subject: str,
    actor_id: str,
    jti: str | None,
    decision: Literal["ALLOW", "DENY", "REVOKE"],
    detail: dict[str, str | int | float | bool | list[str]],
    prev_hash: str,
) -> str:
    """Deterministically compute `SHA256(prev_hash || canonical_json(record))`."""
    canonical_payload = {
        "sequence_id": sequence_id,
        "occurred_at": occurred_at_iso,
        "tenant_id": tenant_id,
        "event_type": event_type.value,
        "human_subject": human_subject,
        "actor_id": actor_id,
        "jti": jti,
        "decision": decision,
        "detail": detail,
        "prev_hash": prev_hash,
    }
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(serialized).hexdigest()


def verify_records_chain(records: Iterable[AuditRecord]) -> tuple[bool, str]:
    """Stream-verify per-tenant monotonic sequences and SHA-256 chains in $O(|\\text{tenants}|)$ space."""
    # Maps tenant_id -> (expected_next_seq, expected_prev_hash)
    tenant_heads: dict[str, tuple[int, str]] = {}
    total_verified = 0

    for rec in records:
        expected_seq, expected_prev = tenant_heads.get(rec.tenant_id, (1, GENESIS_PREV_HASH))
        if rec.sequence_id != expected_seq:
            return (
                False,
                (
                    f"Sequence gap detected for tenant {rec.tenant_id!r} at record "
                    f"{rec.sequence_id} (expected {expected_seq})"
                ),
            )
        if rec.prev_hash != expected_prev:
            return (
                False,
                f"Broken prev_hash link for tenant {rec.tenant_id!r} at sequence_id={rec.sequence_id}",
            )
        recomputed = compute_audit_entry_hash(
            sequence_id=rec.sequence_id,
            occurred_at_iso=rec.occurred_at.isoformat(),
            tenant_id=rec.tenant_id,
            event_type=rec.event_type,
            human_subject=rec.human_subject,
            actor_id=rec.actor_id,
            jti=rec.jti,
            decision=rec.decision,
            detail=rec.detail,
            prev_hash=rec.prev_hash,
        )
        if recomputed != rec.entry_hash:
            return (
                False,
                f"Payload hash mismatch for tenant {rec.tenant_id!r} at sequence_id={rec.sequence_id}",
            )
        tenant_heads[rec.tenant_id] = (expected_seq + 1, rec.entry_hash)
        total_verified += 1

    return True, f"Verified {total_verified} hash-chained audit records intact"


def _row_to_audit_record(row: tuple[Any, ...]) -> AuditRecord:
    raw_detail: Any = row[8]
    parsed_detail: dict[str, str | int | float | bool | list[str]] = (
        raw_detail if isinstance(raw_detail, dict) else json.loads(str(raw_detail))
    )
    decision_str = str(row[7])
    decision_lit: Literal["ALLOW", "DENY", "REVOKE"] = (
        "ALLOW" if decision_str == "ALLOW" else ("DENY" if decision_str == "DENY" else "REVOKE")
    )
    return AuditRecord(
        sequence_id=int(row[0]),
        occurred_at=datetime.fromisoformat(str(row[1])),
        tenant_id=str(row[2]),
        event_type=AuditEventType(str(row[3])),
        human_subject=str(row[4]),
        actor_id=str(row[5]),
        jti=str(row[6]) if row[6] is not None else None,
        decision=decision_lit,
        detail=parsed_detail,
        prev_hash=str(row[9]),
        entry_hash=str(row[10]),
    )


class InMemoryAuditLedger:
    """Thread-safe per-tenant hash-chained audit ledger ($O(1)$ append)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: list[AuditRecord] = []
        self._tenant_heads: dict[str, tuple[int, str]] = {}

    def append(
        self,
        *,
        tenant_id: str,
        event_type: AuditEventType,
        human_subject: str,
        actor_id: str,
        jti: str | None,
        decision: Literal["ALLOW", "DENY", "REVOKE"],
        detail: dict[str, str | int | float | bool | list[str]],
    ) -> AuditRecord:
        with self._lock:
            seq, prev_hash = self._tenant_heads.get(tenant_id, (1, GENESIS_PREV_HASH))
            now = datetime.now(tz=UTC)
            entry_hash = compute_audit_entry_hash(
                sequence_id=seq,
                occurred_at_iso=now.isoformat(),
                tenant_id=tenant_id,
                event_type=event_type,
                human_subject=human_subject,
                actor_id=actor_id,
                jti=jti,
                decision=decision,
                detail=detail,
                prev_hash=prev_hash,
            )
            record = AuditRecord(
                sequence_id=seq,
                occurred_at=now,
                tenant_id=tenant_id,
                event_type=event_type,
                human_subject=human_subject,
                actor_id=actor_id,
                jti=jti,
                decision=decision,
                detail=detail,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            self._records.append(record)
            self._tenant_heads[tenant_id] = (seq + 1, entry_hash)
            return record

    def list_records(self, tenant_id: str | None = None) -> list[AuditRecord]:
        with self._lock:
            if tenant_id is None:
                return list(self._records)
            return [r for r in self._records if r.tenant_id == tenant_id]

    def verify_integrity(self) -> tuple[bool, str]:
        with self._lock:
            snapshot = list(self._records)
        return verify_records_chain(snapshot)


class PostgresAuditLedger:
    """Pooled PostgreSQL ledger using per-tenant advisory locks & streaming cursor verification."""

    def __init__(self, dsn: str, *, pool: BoundedPostgresPool | None = None) -> None:
        self._dsn = dsn
        self._pool = pool if pool is not None else BoundedPostgresPool(dsn, max_connections=16)

    def append(
        self,
        *,
        tenant_id: str,
        event_type: AuditEventType,
        human_subject: str,
        actor_id: str,
        jti: str | None,
        decision: Literal["ALLOW", "DENY", "REVOKE"],
        detail: dict[str, str | int | float | bool | list[str]],
    ) -> AuditRecord:
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            # Per-tenant transactional advisory lock: distinct tenants write in full parallel!
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (tenant_id,))
            cur.execute(
                """
                SELECT sequence_id, entry_hash
                FROM audit_ledger
                WHERE tenant_id = %s
                ORDER BY sequence_id DESC
                LIMIT 1
                """,
                (tenant_id,),
            )
            last_row = cur.fetchone()
            if last_row is None:
                seq = 1
                prev_hash = GENESIS_PREV_HASH
            else:
                seq = int(last_row[0]) + 1
                prev_hash = str(last_row[1])

            now = datetime.now(tz=UTC)
            now_iso = now.isoformat()
            entry_hash = compute_audit_entry_hash(
                sequence_id=seq,
                occurred_at_iso=now_iso,
                tenant_id=tenant_id,
                event_type=event_type,
                human_subject=human_subject,
                actor_id=actor_id,
                jti=jti,
                decision=decision,
                detail=detail,
                prev_hash=prev_hash,
            )
            cur.execute(
                """
                INSERT INTO audit_ledger (
                    sequence_id, occurred_at_iso, tenant_id, event_type,
                    human_subject, actor_id, jti, decision, detail_json,
                    prev_hash, entry_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                """,
                (
                    seq,
                    now_iso,
                    tenant_id,
                    event_type.value,
                    human_subject,
                    actor_id,
                    jti,
                    decision,
                    json.dumps(detail, sort_keys=True),
                    prev_hash,
                    entry_hash,
                ),
            )
            return AuditRecord(
                sequence_id=seq,
                occurred_at=now,
                tenant_id=tenant_id,
                event_type=event_type,
                human_subject=human_subject,
                actor_id=actor_id,
                jti=jti,
                decision=decision,
                detail=detail,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )

    def list_records(self, tenant_id: str | None = None) -> list[AuditRecord]:
        with self._pool.connection() as conn, conn.cursor() as cur:
            if tenant_id is None:
                cur.execute(
                    """
                    SELECT sequence_id, occurred_at_iso, tenant_id, event_type,
                           human_subject, actor_id, jti, decision, detail_json,
                           prev_hash, entry_hash
                    FROM audit_ledger
                    ORDER BY tenant_id ASC, sequence_id ASC
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT sequence_id, occurred_at_iso, tenant_id, event_type,
                           human_subject, actor_id, jti, decision, detail_json,
                           prev_hash, entry_hash
                    FROM audit_ledger
                    WHERE tenant_id = %s
                    ORDER BY sequence_id ASC
                    """,
                    (tenant_id,),
                )
            rows = cur.fetchall()
        return [_row_to_audit_record(r) for r in rows]

    def verify_integrity(self, batch_size: int = 256) -> tuple[bool, str]:
        """Stream-verify entire DB ledger in fixed `batch_size` chunks ($O(1)$ per-tenant RAM)."""
        with self._pool.connection() as conn, conn.transaction(), conn.cursor(
            name="aegis_audit_stream_cursor"
        ) as cur:
            cur.itersize = batch_size
            cur.execute(
                """
                SELECT sequence_id, occurred_at_iso, tenant_id, event_type,
                       human_subject, actor_id, jti, decision, detail_json,
                       prev_hash, entry_hash
                FROM audit_ledger
                ORDER BY tenant_id ASC, sequence_id ASC
                """
            )

            def _record_generator() -> Iterable[AuditRecord]:
                while True:
                    batch = cur.fetchmany(batch_size)
                    if not batch:
                        break
                    for row in batch:
                        yield _row_to_audit_record(row)

            return verify_records_chain(_record_generator())
