"""Zero-Trust RAG Orchestrator binding Project 1 RFC 8693 tokens to Project 4 RLS queries."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis_core.crypto import TokenVerificationError
from aegis_core.models import (
    AuditEventType,
    RetrievalQuery,
    RetrievalResponse,
    SecurityReceipt,
)
from aegis_core.ports import AuditLedgerPort, RetrievalStorePort
from aegis_core.telemetry import AegisTelemetry
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker


class RetrievalAuthorizationError(Exception):
    """Raised when a RAG call fails token verification, revocation check, or scope check."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class SecureRAGEngine:
    """Enforces cryptographic JWT validation, revocation checks, RLS binding, and audit receipts."""

    def __init__(
        self,
        *,
        broker: SSODelegationBroker,
        store: RetrievalStorePort,
        audit_ledger: AuditLedgerPort,
        telemetry: AegisTelemetry | None = None,
    ) -> None:
        self._broker = broker
        self._store = store
        self._audit = audit_ledger
        self._telemetry = telemetry or AegisTelemetry("aegis-secure-rag")

    def retrieve(
        self,
        *,
        bearer_token: str,
        request: RetrievalQuery,
        now_epoch: int | None = None,
    ) -> RetrievalResponse:
        """Verify RFC 8693 token, execute kernel-RLS hybrid search, and emit SecurityReceipt."""
        try:
            claims = self._broker.verify_and_check_revocation(
                bearer_token,
                required_scope="rag:read",
                now_epoch=now_epoch,
            )
        except TokenVerificationError as exc:
            self._audit.append(
                tenant_id="unverified",
                event_type=AuditEventType.RAG_RETRIEVAL_DENIED,
                human_subject="unverified",
                actor_id="unverified",
                jti=None,
                decision="DENY",
                detail={"reason": str(exc)},
            )
            raise RetrievalAuthorizationError(str(exc), status_code=401) from exc
        except DelegationPolicyError as exc:
            self._audit.append(
                tenant_id="unverified",
                event_type=AuditEventType.RAG_RETRIEVAL_DENIED,
                human_subject="unverified",
                actor_id="unverified",
                jti=None,
                decision="DENY",
                detail={"reason": exc.description},
            )
            raise RetrievalAuthorizationError(exc.description, status_code=exc.status_code) from exc

        with self._telemetry.span(
            "gen_ai.retrieval",
            {
                "aegis.tenant_id": claims.tenant_id,
                "aegis.sub": claims.sub,
                "aegis.actor_id": claims.act.sub,
                "aegis.clearance": int(claims.clearance),
                "aegis.jti": claims.jti,
                "gen_ai.retrieval.top_k": request.top_k,
            },
        ) as span:
            chunks, db_role, rls_forced = self._store.retrieve_authorized(
                claims=claims,
                query=request.query,
                top_k=request.top_k,
            )
            span.set_attribute("gen_ai.retrieval.returned_chunks", len(chunks))
            span.set_attribute("aegis.db_role", db_role)
            span.set_attribute("aegis.rls_forced", rls_forced)

            audit_rec = self._audit.append(
                tenant_id=claims.tenant_id,
                event_type=AuditEventType.RAG_RETRIEVAL_EXECUTED,
                human_subject=claims.sub,
                actor_id=claims.act.sub,
                jti=claims.jti,
                decision="ALLOW",
                detail={
                    "returned_chunk_ids": [c.chunk_id for c in chunks],
                    "returned_count": len(chunks),
                    "effective_clearance": int(claims.clearance),
                    "db_role": db_role,
                    "rls_forced": rls_forced,
                },
            )

            receipt = SecurityReceipt(
                jti=claims.jti,
                human_subject=claims.sub,
                actor_spiffe_id=claims.act.sub,
                tenant_id=claims.tenant_id,
                effective_clearance=claims.clearance,
                db_execution_role=db_role,
                rls_forced=rls_forced,
                audit_entry_hash=audit_rec.entry_hash,
                evaluated_at=datetime.now(tz=UTC),
            )
            return RetrievalResponse(
                query=request.query,
                results=chunks,
                security_receipt=receipt,
            )
