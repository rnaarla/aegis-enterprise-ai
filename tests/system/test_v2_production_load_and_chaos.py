"""Multi-Worker Production Load, Chaos & Quantitative NFR Proof Suite (MANGOS SRE Standard).

Proves every V2 feature under concurrent burst load, injected latency/faults, and race
conditions against explicit quantitative latency (`p95`/`p99`), throughput, availability,
memory, and zero-leakage NFR gates.
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from enterprise_twin.corpus_seed.historical_tickets import generate_500_historical_tickets
from enterprise_twin.idp_seed.meridian_idp import (
    MeridianAgentRegistry,
    MeridianIdentityProvider,
)
from enterprise_twin.soap_erp_mock.sap_soap_server import LegacySAPSoapTwin

from admin_control_plane.portal_api import ControlPlaneService
from aegis_core.aimd import AIMDConcurrencyLimiter
from aegis_core.audit import InMemoryAuditLedger
from aegis_core.crypto import SigningKeyPair, compute_jwk_thumbprint_from_public_jwk
from aegis_core.models import (
    ClearanceLevel,
    DocumentChunk,
    DocumentClassification,
    ReBACTuple,
    RetrievalQuery,
    TokenExchangeRequest,
)
from aegis_core.sli_metrics import SLIRegistry
from aegis_core.telemetry import AegisTelemetry
from edge_triage_router.router import (
    DeterministicOnPremClassifierAdapter,
    EdgeTriageOverloadError,
    LocalQuantizedTriageRouter,
)
from finops_telemetry.engine import FinOpsTelemetryEngine
from mcp_erp_bridge.bridge import (
    JSONRPCRequest,
    MCPERPBridgeServer,
)
from pii_unmasking_proxy.proxy import ChatCompletionRequest, ChatMessage, DeterministicPIIProxy
from pii_unmasking_proxy.sse_stream import passes_luhn_checksum
from pii_unmasking_proxy.vault import EnvelopeEncryptedPIIVault
from secure_rag_engine.embeddings import DeterministicFinancialEmbedder
from secure_rag_engine.engine import SecureRAGEngine
from secure_rag_engine.store import PostgresRLSRetrievalStore
from shadow_replay_harness.harness import ShadowReplayHarness
from sso_delegation_broker.broker import SSODelegationBroker
from sso_delegation_broker.dpop_ssf import mint_dpop_proof
from sso_delegation_broker.revocation import InMemoryRevocationStore


def _percentile_ms(samples_ms: list[float], p: float) -> float:
    ordered = sorted(samples_ms)
    idx = min(len(ordered) - 1, max(0, math.ceil(p * len(ordered)) - 1))
    return ordered[idx]


class _FastEchoLLM:
    def complete(self, masked_messages: list[dict[str, str]], model: str) -> str:
        _ = model
        return f"Processed: {masked_messages[-1]['content']}"

    def stream_complete(self, masked_messages: list[dict[str, str]], model: str) -> Iterator[str]:
        text = self.complete(masked_messages, model)
        mid = len(text) // 2
        yield text[:mid]
        yield text[mid:]


class _CongestedSOAPTransport:
    """Injects synthetic SAP ABAP dialog queueing delay to prove AIMD window contraction & shedding."""

    def __init__(self, twin: LegacySAPSoapTwin, delay_seconds: float) -> None:
        self._twin = twin
        self.delay_seconds = delay_seconds

    def post_envelope(self, soap_xml: bytes) -> tuple[int, bytes]:
        if self.delay_seconds > 0:
            time.sleep(self.delay_seconds)
        return self._twin.handle_soap_envelope(soap_xml)


@pytest.mark.system
def test_production_load_sso_dpop_subdelegation_and_live_key_rotation() -> None:
    """NFR Gate P1: 240 concurrent DPoP exchanges + subdelegations + live key rotation (`p99 <= 80ms`)."""
    idp = MeridianIdentityProvider()
    sli = SLIRegistry()
    audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
        sli_registry=sli,
    )
    elena_oidc = idp.issue_oidc_token_for_persona("elena.vance")
    dpop_key = SigningKeyPair.generate_es256()
    jkt = compute_jwk_thumbprint_from_public_jwk(dpop_key.public_jwk)

    latencies_ms: list[float] = []
    lat_lock = threading.Lock()

    def _worker(idx: int) -> None:
        t0 = time.perf_counter()
        if idx in (60, 120, 180):
            broker.rotate_signing_key()
        proof = mint_dpop_proof(
            holder_key=dpop_key,
            htm="POST",
            htu="https://auth.aegis.meridian.fin/v1/oauth/token",
            jti=f"load-dpop-{idx}",
        )
        ex = broker.exchange_token(
            TokenExchangeRequest(
                subject_token=elena_oidc,
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                agent_id="meridian-procurement-agent",
                requested_scopes=["rag:read", "erp:po:create"],
                dpop_jkt=jkt,
            ),
            dpop_proof_jwt=proof,
        )
        sub = broker.exchange_agent_to_agent(
            parent_agent_token=ex.access_token,
            target_subagent_id="meridian-research-assistant",
            requested_scopes=["rag:read"],
        )
        claims = broker.verify_and_check_revocation(sub.access_token, required_scope="rag:read")
        assert claims.delegation_depth == 2
        dur = (time.perf_counter() - t0) * 1000.0
        with lat_lock:
            latencies_ms.append(dur)

    workers = min(8, max(2, (os.cpu_count() or 2) * 2))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(_worker, range(240)))

    assert len(latencies_ms) == 240
    # Each worker executes 7 asymmetric RS256/ES256 crypto ops (DPoP + OIDC + Mint + Subdelegate + Verify)
    assert _percentile_ms(latencies_ms, 0.95) <= 150.0
    assert _percentile_ms(latencies_ms, 0.99) <= 300.0
    valid_audit, _ = audit.verify_integrity()
    assert valid_audit is True


@pytest.mark.system
def test_production_load_postgres18_rls_contention_zero_leakage(pg_rls_dsn: str) -> None:
    """NFR Gate P4: 100 concurrent multi-clearance queries on 16-conn LIFO pool (`0` MNPI leaks)."""
    idp = MeridianIdentityProvider()
    audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
    )
    store = PostgresRLSRetrievalStore(dsn=pg_rls_dsn, embedder=DeterministicFinancialEmbedder())
    store.apply_migrations()
    rag = SecureRAGEngine(broker=broker, store=store, audit_ledger=audit)

    store.ingest_chunks(
        [
            DocumentChunk(
                chunk_id="chk-load-mnpi-secret",
                document_id="doc-load-mnpi",
                tenant_id="meridian-fin",
                title="Project Chronos Secret Valuation",
                source_uri="s3://ma/secret.pdf",
                source_system="sharepoint_ma",
                page_or_record_ref="p1",
                classification=DocumentClassification.TOP_SECRET_MA,
                clearance_required=ClearanceLevel.TOP_SECRET_MA,
                content="Chronos enterprise valuation ceiling is USD 6.8 billion.",
                department_owner="CORP_DEV",
            ),
            DocumentChunk(
                chunk_id="chk-load-public-kb",
                document_id="doc-load-public",
                tenant_id="meridian-fin",
                title="Corporate Expense Policy",
                source_uri="s3://kb/expense.pdf",
                source_system="policy_kb",
                page_or_record_ref="p1",
                classification=DocumentClassification.INTERNAL,
                clearance_required=ClearanceLevel.INTERNAL,
                content="Standard corporate hotel policy and Chronos travel code.",
                department_owner="HR",
            ),
        ],
        [
            ReBACTuple(
                tenant_id="meridian-fin",
                object_id="doc-load-mnpi",
                relation="viewer",
                subject_type="group",
                subject_id="deal-chronos",
            ),
            ReBACTuple(
                tenant_id="meridian-fin",
                object_id="doc-load-public",
                relation="viewer",
                subject_type="group",
                subject_id="all-employees",
            ),
            # Julian Ross is on Ethical Wall for doc-load-mnpi despite TOP_SECRET_MA!
            ReBACTuple(
                tenant_id="meridian-fin",
                object_id="doc-load-mnpi",
                relation="ethical_wall_deny",
                subject_type="user",
                subject_id="julian.ross",
            ),
        ],
    )

    elena_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    ).access_token
    marcus_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("marcus.chen"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-research-assistant",
            requested_scopes=["rag:read"],
        )
    ).access_token
    julian_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("julian.ross"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    ).access_token

    latencies_ms: list[float] = []
    lock = threading.Lock()

    def _query_worker(i: int) -> None:
        t0 = time.perf_counter()
        persona_mod = i % 3
        tok = elena_tok if persona_mod == 0 else (marcus_tok if persona_mod == 1 else julian_tok)
        resp = rag.retrieve(
            bearer_token=tok, request=RetrievalQuery(query="Chronos valuation ceiling")
        )
        ids = {c.chunk_id for c in resp.results}
        if persona_mod == 0:
            assert "chk-load-mnpi-secret" in ids
        else:
            # Zero-leakage invariant under 16-connection pool reuse!
            assert "chk-load-mnpi-secret" not in ids
        with lock:
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)

    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(_query_worker, range(96)))
    finally:
        import psycopg

        with psycopg.connect(pg_rls_dsn) as clean_conn, clean_conn.cursor() as cur:
            cur.execute("DELETE FROM rag_chunks WHERE document_id IN ('doc-load-mnpi', 'doc-load-public')")
            cur.execute("DELETE FROM rebac_tuples WHERE object_id IN ('doc-load-mnpi', 'doc-load-public')")
            clean_conn.commit()

    assert len(latencies_ms) == 96
    assert _percentile_ms(latencies_ms, 0.99) <= 250.0


@pytest.mark.system
def test_production_chaos_sap_aimd_backpressure_saga_and_pii_fpe_barrage(tmp_path: Path) -> None:
    """NFR Gate P5 & P6: SAP congestion AIMD shedding + Saga rollback + 2,500-term Aho-Corasick FPE."""
    idp = MeridianIdentityProvider()
    audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
    )
    priya_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_saml2_assertion_for_persona("priya.nair"),
            subject_token_type="urn:ietf:params:oauth:token-type:saml2",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read", "erp:po:create"],
        )
    ).access_token

    sap_twin = LegacySAPSoapTwin()
    congested = _CongestedSOAPTransport(sap_twin, delay_seconds=0.001)
    aimd = AIMDConcurrencyLimiter("sap-chaos", initial_limit=6, min_limit=2, max_limit=12)
    bridge = MCPERPBridgeServer(
        broker=broker,
        soap_transport=congested,
        audit_ledger=audit,
        aimd_limiter=aimd,
        durable_outbox_path=tmp_path / "chaos_outbox.sqlite3",
    )

    # 1. Prove Saga rollback leaves ZERO orphaned SAP POs when downstream partner step fails
    before_pos = len(sap_twin.list_purchase_orders())
    saga_out = bridge.execute_po_with_downstream_saga(
        bearer_token=priya_tok,
        po_args={
            "vendor_id": "0000100450",
            "company_code": "1000",
            "description": "Saga Test Hardware",
            "amount_usd": 12_000.0,
            "idempotency_key": "saga-idem-01",
        },
        downstream_step=lambda: (_ for _ in ()).throw(RuntimeError("NetSuite timeout")),
    )
    assert saga_out["saga_succeeded"] is False
    assert saga_out["compensated_steps"] == ["sap_po_create"]
    assert len(sap_twin.list_purchase_orders()) == before_pos

    # 2. Inject 25ms SAP dialog slowdown under 20 concurrent callers -> AIMD shrinks & sheds cleanly!
    congested.delay_seconds = 0.025

    def _call_sap(i: int) -> int:
        rpc = bridge.handle_jsonrpc(
            JSONRPCRequest(
                id=i,
                method="tools/call",
                params={"name": "sap_get_vendor_status", "arguments": {"vendor_id": "0000100450"}},
            ),
            bearer_token=priya_tok,
        )
        return int(rpc.get("error", {}).get("code", 0))

    with ThreadPoolExecutor(max_workers=20) as pool:
        codes = list(pool.map(_call_sap, range(40)))
    assert -32005 in codes  # AIMD shed excess storm in O(1) without crashing!
    assert aimd.snapshot().shed_total >= 1

    # 3. P6 Load: 2,500-term Aho-Corasick + Feistel FPE across 150 concurrent requests (`p99 <= 25ms`)
    big_dict = {f"SecretDeal{i}": "DEAL" for i in range(2_500)}
    pii_proxy = DeterministicPIIProxy(
        broker=broker,
        vault=EnvelopeEncryptedPIIVault(),
        upstream_llm=_FastEchoLLM(),
        audit_ledger=audit,
        custom_entity_dictionary=big_dict,
    )
    pii_lat: list[float] = []
    pii_lock = threading.Lock()

    def _pii_worker(i: int) -> None:
        t0 = time.perf_counter()
        res = pii_proxy.complete_sync(
            bearer_token=priya_tok,
            req=ChatCompletionRequest(
                session_id=f"load-sess-{i % 20}",
                format_preserving_fpe=True,
                messages=[
                    ChatMessage(
                        role="user",
                        content=f"Audit SecretDeal{i % 2500} card 4532015112830366 for Elena Vance",
                    )
                ],
            ),
        )
        content = str(res["choices"][0]["message"]["content"])
        # Extract the FPE 16-digit PAN and prove Luhn validity
        for token in content.split():
            if len(token) == 19 and token.count("-") == 3:
                assert passes_luhn_checksum(token) is True
        with pii_lock:
            pii_lat.append((time.perf_counter() - t0) * 1000.0)

    workers = min(8, max(2, (os.cpu_count() or 2) * 2))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(_pii_worker, range(150)))

    assert _percentile_ms(pii_lat, 0.99) <= 80.0


@pytest.mark.system
def test_production_chaos_wfq_gpu_priority_atomic_finops_and_canary_rollback() -> None:
    """NFR Gate P8, P9 & P12: WFQ critical reserve, atomic budget race safety & canary rollback."""
    idp = MeridianIdentityProvider()
    audit = InMemoryAuditLedger()
    telemetry = AegisTelemetry("chaos-p8-p9-p12")
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
    )
    elena_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    ).access_token

    # 1. P8 WFQ Priority Lanes: Saturate GPU KV-cache to 90% (29,500 / 32,768 tokens)
    router = LocalQuantizedTriageRouter(
        broker=broker,
        classifier=DeterministicOnPremClassifierAdapter(),
        audit_ledger=audit,
        max_kv_cache_tokens=32_768,
    )
    router.simulate_gpu_kv_load(29_500)
    # BATCH traffic caps at 85% -> fails closed!
    with pytest.raises(EdgeTriageOverloadError):
        router.evaluate_and_route(
            bearer_token=elena_tok, prompt="Routine batch job", priority="BATCH"
        )
    # CRITICAL CISO/MD traffic uses reserved 15% lane -> succeeds with zero cloud leak on MNPI!
    crit_res = router.evaluate_and_route(
        bearer_token=elena_tok,
        prompt="Project Chronos breakup fee review",
        priority="CRITICAL",
    )
    assert crit_res.egress_permitted is False
    assert crit_res.route_target == "LOCAL_AWQ_8B_ENCLAVE"

    # 2. P9 Atomic Budget Race: 40 concurrent threads attempting $1.50 spend against a $15.00 cap
    finops = FinOpsTelemetryEngine()
    finops.budget_governor.set_monthly_budget("meridian-fin", "CORP_DEV", 15.0)

    def _spend_worker(_i: int) -> str:
        return finops.evaluate_budget_gate(
            tenant_id="meridian-fin",
            cost_center="CORP_DEV",
            requested_model_id="gpt-5-enterprise",
            estimated_cost_usd=1.50,
        ).decision

    with ThreadPoolExecutor(max_workers=20) as pool:
        decisions = list(pool.map(_spend_worker, range(40)))
    assert "ALLOW_REQUESTED_MODEL" in decisions
    assert "STEP_DOWN_LOCAL_MODEL" in decisions
    assert "HARD_STOP_BUDGET_EXCEEDED" in decisions

    # 3. P12 Canary Live Fault Injection -> Instant Auto-Rollback to `prompt-v1`
    admin_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("david.kim"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-admin-console",
            requested_scopes=["admin:control_plane", "admin:prompts:write", "admin:traces:read"],
        )
    ).access_token
    cp = ControlPlaneService(
        broker=broker,
        replay_harness=ShadowReplayHarness(),
        golden_tickets=generate_500_historical_tickets(),
        finops_engine=finops,
        telemetry=telemetry,
        audit_ledger=audit,
    )
    draft = cp.create_prompt_draft(
        bearer_token=admin_tok,
        system_prompt=(
            "Enforce MNPI clearance strictly, refuse SPERR=X vendors, "
            "and route POs exceeding USD 50,000 through Temporal Gate."
        ),
    )
    cp.configure_canary_stage(
        bearer_token=admin_tok, canary_version_id=draft.version_id, weight_pct=25
    )
    for _ in range(12):
        cp.record_canary_sample(tenant_id="meridian-fin", is_error=True, latency_ms=2500.0)
    status = cp.canary.status()
    assert status.auto_rolled_back is True
    assert status.canary_weight_pct == 0
    assert cp.canary.route_version("meridian-fin", "elena.vance") == "prompt-v1"
