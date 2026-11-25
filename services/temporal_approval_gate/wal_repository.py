"""Crash-durable SQLite WAL Repository for pending & decided approval workflows."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ApprovalGateRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    vendor_id: str = Field(min_length=3, max_length=32)
    company_code: str = Field(default="1000", min_length=2, max_length=16)
    description: str = Field(min_length=3, max_length=256)
    amount_usd: float = Field(gt=0.0)


class ApprovalWorkflowRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    workflow_id: str
    tenant_id: str
    requester_sub: str
    vendor_id: str
    company_code: str
    description: str
    amount_usd: float
    snapshot_vendor_etag: str
    payload_sha256: str
    status: Literal[
        "AWAITING_APPROVAL",
        "APPROVED_EXECUTED",
        "REJECTED",
        "ABORTED_TOCTOU_DRIFT",
        "FAILED_SAP_ERROR",
    ]
    slack_block_kit_json: dict[str, Any]
    approver_sub: str | None = None
    sap_po_number: str | None = None
    failure_reason: str | None = None


class WalApprovalRepository:
    """Repository encapsulating `PRAGMA synchronous=FULL` WAL checkpoints for crash survival."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_wal()

    def _init_wal(self) -> None:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS durable_approval_workflows (
                    workflow_id          TEXT PRIMARY KEY,
                    tenant_id            TEXT NOT NULL,
                    requester_sub        TEXT NOT NULL,
                    vendor_id            TEXT NOT NULL,
                    company_code         TEXT NOT NULL,
                    description          TEXT NOT NULL,
                    amount_usd           REAL NOT NULL,
                    snapshot_vendor_etag TEXT NOT NULL,
                    payload_sha256       TEXT NOT NULL,
                    status               TEXT NOT NULL,
                    slack_card_json      TEXT NOT NULL,
                    approver_sub         TEXT,
                    sap_po_number        TEXT,
                    failure_reason       TEXT
                )
                """
            )
            conn.commit()

    def insert_pending(
        self,
        *,
        workflow_id: str,
        tenant_id: str,
        requester_sub: str,
        vendor_id: str,
        company_code: str,
        description: str,
        amount_usd: float,
        snapshot_etag: str,
        payload_hash: str,
        slack_card: dict[str, Any],
    ) -> None:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO durable_approval_workflows (
                    workflow_id, tenant_id, requester_sub, vendor_id, company_code,
                    description, amount_usd, snapshot_vendor_etag, payload_sha256,
                    status, slack_card_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    workflow_id,
                    tenant_id,
                    requester_sub,
                    vendor_id,
                    company_code,
                    description,
                    round(amount_usd, 2),
                    snapshot_etag,
                    payload_hash,
                    "AWAITING_APPROVAL",
                    json.dumps(slack_card, sort_keys=True),
                ),
            )
            conn.commit()

    def get(self, workflow_id: str) -> ApprovalWorkflowRecord:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                """
                SELECT workflow_id, tenant_id, requester_sub, vendor_id, company_code,
                       description, amount_usd, snapshot_vendor_etag, payload_sha256,
                       status, slack_card_json, approver_sub, sap_po_number, failure_reason
                FROM durable_approval_workflows
                WHERE workflow_id = ?
                """,
                (workflow_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown approval workflow_id: {workflow_id!r}")

        status_val: Any = str(row[9])
        return ApprovalWorkflowRecord(
            workflow_id=str(row[0]),
            tenant_id=str(row[1]),
            requester_sub=str(row[2]),
            vendor_id=str(row[3]),
            company_code=str(row[4]),
            description=str(row[5]),
            amount_usd=float(row[6]),
            snapshot_vendor_etag=str(row[7]),
            payload_sha256=str(row[8]),
            status=status_val,
            slack_block_kit_json=json.loads(str(row[10])),
            approver_sub=str(row[11]) if row[11] is not None else None,
            sap_po_number=str(row[12]) if row[12] is not None else None,
            failure_reason=str(row[13]) if row[13] is not None else None,
        )

    def update_resolution(
        self,
        workflow_id: str,
        *,
        status: str,
        approver_sub: str,
        sap_po_number: str | None,
        failure_reason: str | None,
    ) -> None:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                UPDATE durable_approval_workflows
                SET status = ?, approver_sub = ?, sap_po_number = ?, failure_reason = ?
                WHERE workflow_id = ?
                """,
                (status, approver_sub, sap_po_number, failure_reason, workflow_id),
            )
            conn.commit()
