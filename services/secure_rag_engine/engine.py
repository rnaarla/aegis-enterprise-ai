"""Zero-Trust RAG Orchestrator with Cross-Encoder Reranking, Timing Padding & Grounding."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from aegis_core.crypto import TokenVerificationError
from aegis_core.models import (
    AuditEventType,
    RetrievalQuery,
    RetrievalResponse,
    ScoredChunk,
    SecurityReceipt,
)
from aegis_core.ports import AuditLedgerPort, RetrievalStorePort
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry
from aegis_core.telemetry import AegisTelemetry
from secure_rag_engine.reranker_grounding import (
    CitationVerificationResult,
    LocalCrossEncoderReranker,
    verify_answer_citations,
)
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker


class RetrievalAuthorizationError(Exception):
    """Raised when a RAG call fails token verification, revocation check, or scope check."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class SecureRAGEngine:
    """Enforces JWT validation, revocation, transitive RLS, cross-encoder reranking & grounding."""

    def __init__(
        self,
        *,
        broker: SSODelegationBroker,
        store: RetrievalStorePort,
        audit_ledger: AuditLedgerPort,
        telemetry: AegisTelemetry | None = None,
        reranker: LocalCrossEncoderReranker | None = None,
        constant_floor_ms: float = 0.0,
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self._broker = broker
        self._store = store
        self._audit = audit_ledger
        self._telemetry = telemetry or AegisTelemetry("aegis-secure-rag")
        self._reranker = reranker or LocalCrossEncoderReranker()
        self._floor_ms = max(0.0, constant_floor_ms)
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY

    def retrieve(
        self,
        *,
        bearer_token: str,
        request: RetrievalQuery,
        now_epoch: int | None = None,
    ) -> RetrievalResponse:
        """Verify RFC 8693 token, execute kernel-RLS hybrid search + rerank, and emit receipt."""
        t0 = time.perf_counter()
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

        # Enforce RFC 9396 RAR `rag_corpus` source-system filtering if bound to token
        rar_allowed_sources: set[str] | None = None
        for detail in claims.authorization_details:
            if detail.type == "rag_corpus" and detail.allowed_sources:
                rar_allowed_sources = set(detail.allowed_sources)

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
            fetch_k = min(25, request.top_k * 2) if request.enable_reranker else request.top_k
            chunks, db_role, rls_forced = self._store.retrieve_authorized(
                claims=claims,
                query=request.query,
                top_k=fetch_k,
            )
            if rar_allowed_sources is not None:
                chunks = [c for c in chunks if c.source_system in rar_allowed_sources]
            if request.enable_reranker and chunks:
                chunks = self._reranker.rerank(request.query, chunks, top_k=request.top_k)
            else:
                chunks = chunks[: request.top_k]

            span.set_attribute("gen_ai.retrieval.returned_chunks", len(chunks))
            span.set_attribute("aegis.db_role", db_role)
            span.set_attribute("aegis.rls_forced", rls_forced)
            self._sli.inc_counter(
                "aegis_rag_retrievals_total",
                1.0,
                {"rls_forced": str(rls_forced).lower()},
            )

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

            if self._floor_ms > 0.0:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if elapsed_ms < self._floor_ms:
                    time.sleep((self._floor_ms - elapsed_ms) / 1000.0)

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

    def verify_citations(
        self,
        *,
        answer_text: str,
        authorized_chunks: list[ScoredChunk],
    ) -> CitationVerificationResult:
        res = verify_answer_citations(
            answer_text=answer_text, authorized_chunks=authorized_chunks
        )
        self._sli.inc_counter(
            "aegis_rag_citation_checks_total",
            1.0,
            {"grounded": str(res.grounded).lower()},
        )
        return res
