"""Real PostgreSQL 18 kernel `FORCE ROW LEVEL SECURITY` & immutable audit integration tests."""

from __future__ import annotations

import psycopg
import pytest
from enterprise_twin.corpus_seed.meridian_corpus import build_meridian_corpus
from enterprise_twin.idp_seed.meridian_idp import (
    MeridianAgentRegistry,
    MeridianIdentityProvider,
)

from aegis_core.audit import PostgresAuditLedger
from aegis_core.models import RetrievalQuery, TokenExchangeRequest
from secure_rag_engine.embeddings import DeterministicFinancialEmbedder
from secure_rag_engine.engine import RetrievalAuthorizationError, SecureRAGEngine
from secure_rag_engine.store import PostgresRLSRetrievalStore
from sso_delegation_broker.broker import SSODelegationBroker
from sso_delegation_broker.revocation import InMemoryRevocationStore

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def live_rls_stack(
    pg_rls_dsn: str,
) -> tuple[
    SSODelegationBroker, SecureRAGEngine, MeridianIdentityProvider, PostgresAuditLedger, str
]:
    embedder = DeterministicFinancialEmbedder(dim=64)
    store = PostgresRLSRetrievalStore(dsn=pg_rls_dsn, embedder=embedder)
    store.apply_migrations()

    chunks, tuples = build_meridian_corpus()
    store.ingest_chunks(chunks, tuples)

    audit = PostgresAuditLedger(dsn=pg_rls_dsn)
    idp = MeridianIdentityProvider()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
    )
    engine = SecureRAGEngine(broker=broker, store=store, audit_ledger=audit)
    return broker, engine, idp, audit, pg_rls_dsn


def test_md_retrieves_ma_docs_but_never_cross_tenant_canary(
    live_rls_stack: tuple[
        SSODelegationBroker, SecureRAGEngine, MeridianIdentityProvider, PostgresAuditLedger, str
    ],
) -> None:
    broker, engine, idp, _, _ = live_rls_stack
    tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    )
    res = engine.retrieve(
        bearer_token=tok.access_token,
        request=RetrievalQuery(
            query="Project Chronos Helios valuation EBITDA apex canary",
            top_k=20,
        ),
    )
    doc_ids = {c.document_id for c in res.results}
    assert "doc-chronos-valuation" in doc_ids
    assert "doc-chronos-spa-draft" in doc_ids
    assert "doc-cobol-nostro-ledger" in doc_ids
    # Cross-tenant PUBLIC canary MUST be blocked by RESTRICTIVE tenant RLS policy
    assert "doc-rival-tenant-secret" not in doc_ids
    assert res.security_receipt.db_execution_role == "aegis_app_runtime"
    assert res.security_receipt.rls_forced is True


def test_junior_analyst_physically_cannot_retrieve_executive_chunks(
    live_rls_stack: tuple[
        SSODelegationBroker, SecureRAGEngine, MeridianIdentityProvider, PostgresAuditLedger, str
    ],
) -> None:
    broker, engine, idp, _, _ = live_rls_stack
    tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("marcus.chen"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-research-assistant",
            requested_scopes=["rag:read"],
        )
    )
    res = engine.retrieve(
        bearer_token=tok.access_token,
        request=RetrievalQuery(
            query="Project Chronos Helios valuation breakup fee Nostro Fedwire SAP PO",
            top_k=25,
        ),
    )
    doc_ids = {c.document_id for c in res.results}
    assert doc_ids == {"doc-q3-macro-research", "doc-travel-expense-policy"}


def test_ethical_wall_blocks_cleared_deal_group_member_at_db_kernel(
    live_rls_stack: tuple[
        SSODelegationBroker, SecureRAGEngine, MeridianIdentityProvider, PostgresAuditLedger, str
    ],
) -> None:
    broker, engine, idp, _, _ = live_rls_stack
    # Julian Ross is in `deal-chronos` AND has `TOP_SECRET_MA` (40) clearance,
    # but has an explicit `ethical_wall_deny` tuple on Project Chronos documents.
    tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("julian.ross"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    )
    res = engine.retrieve(
        bearer_token=tok.access_token,
        request=RetrievalQuery(query="Project Chronos Helios valuation SPA Nostro", top_k=25),
    )
    doc_ids = {c.document_id for c in res.results}
    assert "doc-chronos-valuation" not in doc_ids
    assert "doc-chronos-spa-draft" not in doc_ids
    # Non-conflicted RESTRICTED Nostro ledger remains accessible via `md-ma` group
    assert "doc-cobol-nostro-ledger" in doc_ids


def test_agent_max_clearance_prevents_overprivileged_bot_leakage(
    live_rls_stack: tuple[
        SSODelegationBroker, SecureRAGEngine, MeridianIdentityProvider, PostgresAuditLedger, str
    ],
) -> None:
    broker, engine, idp, _, _ = live_rls_stack
    # MD Elena Vance (TOP_SECRET_MA=40) uses meridian-procurement-agent (max_clearance=CONFIDENTIAL=20)
    tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read"],
        )
    )
    res = engine.retrieve(
        bearer_token=tok.access_token,
        request=RetrievalQuery(query="Project Chronos valuation SAP procurement policy", top_k=25),
    )
    doc_ids = {c.document_id for c in res.results}
    assert "doc-sap-vendor-master" in doc_ids
    assert "doc-chronos-valuation" not in doc_ids
    assert "doc-cobol-nostro-ledger" not in doc_ids


def test_revoked_jti_blocked_and_postgres_audit_ledger_is_kernel_immutable(
    live_rls_stack: tuple[
        SSODelegationBroker, SecureRAGEngine, MeridianIdentityProvider, PostgresAuditLedger, str
    ],
) -> None:
    broker, engine, idp, audit, dsn = live_rls_stack
    tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_saml2_assertion_for_persona("priya.nair"),
            subject_token_type="urn:ietf:params:oauth:token-type:saml2",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read"],
        )
    )
    broker.revoke_token_by_jti(
        jti=tok.jti,
        tenant_id="meridian-fin",
        human_subject="priya.nair",
        actor_id="meridian-procurement-agent",
        reason="session_terminated",
    )
    with pytest.raises(RetrievalAuthorizationError, match="revoked"):
        engine.retrieve(
            bearer_token=tok.access_token,
            request=RetrievalQuery(query="SAP purchase order threshold", top_k=5),
        )

    # Attempt UPDATE, DELETE, and TRUNCATE directly on PostgreSQL audit_ledger
    for malicious_sql in (
        "UPDATE audit_ledger SET decision = 'ALLOW' WHERE sequence_id = 1",
        "DELETE FROM audit_ledger WHERE sequence_id = 1",
        "TRUNCATE TABLE audit_ledger",
    ):
        with psycopg.connect(dsn) as conn, conn.cursor() as cur, pytest.raises(psycopg.Error):
            cur.execute(malicious_sql)

    intact, summary = audit.verify_integrity()
    assert intact is True
    assert "Verified" in summary
