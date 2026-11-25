"""32-Thread Concurrency Stress, Circuit Breaker State Machine & Portal UI Integration Suite."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx
import pytest
from enterprise_twin.corpus_seed.historical_tickets import generate_500_historical_tickets
from enterprise_twin.idp_seed.meridian_idp import (
    MeridianAgentRegistry,
    MeridianIdentityProvider,
)
from enterprise_twin.soap_erp_mock.sap_soap_server import LegacySAPSoapTwin
from httpx import ASGITransport, AsyncClient

from admin_control_plane.portal_api import (
    ControlPlaneService,
    create_admin_control_plane_app,
)
from aegis_core.audit import PostgresAuditLedger
from aegis_core.db_pool import BoundedPostgresPool
from aegis_core.models import AuditEventType, TokenExchangeRequest
from aegis_core.resilience import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    TransientDependencyError,
)
from aegis_core.telemetry import AegisTelemetry
from edge_triage_router.router import (
    DataTemperature,
    TriageClassification,
    VLLMGuidedJSONClassifierAdapter,
)
from finops_telemetry.engine import FinOpsTelemetryEngine, GenAITelemetryEvent
from mcp_erp_bridge.soap_client import HttpSOAPTransport, build_wsse_soap_envelope
from secure_rag_engine.embeddings import DeterministicFinancialEmbedder
from secure_rag_engine.store import PostgresRLSRetrievalStore
from shadow_replay_harness.harness import ShadowReplayHarness
from sso_delegation_broker.broker import SSODelegationBroker
from sso_delegation_broker.revocation import InMemoryRevocationStore

pytestmark = pytest.mark.integration


def test_32_thread_multitenant_postgres_audit_ledger_parallel_contention(
    pg_rls_dsn: str,
) -> None:
    """Hammer `PostgresAuditLedger` across 32 threads & 8 tenants over a 10-slot LIFO pool."""
    pool = BoundedPostgresPool(pg_rls_dsn, max_connections=10, acquire_timeout_seconds=10.0)
    store = PostgresRLSRetrievalStore(
        dsn=pg_rls_dsn,
        embedder=DeterministicFinancialEmbedder(dim=32),
        pool=pool,
    )
    store.apply_migrations()
    ledger = PostgresAuditLedger(dsn=pg_rls_dsn, pool=pool)

    tenants = [f"bank-stress-{i}" for i in range(8)]
    writes_per_tenant = 15

    def _worker(task_tuple: tuple[str, int]) -> str:
        t_id, idx = task_tuple
        rec = ledger.append(
            tenant_id=t_id,
            event_type=AuditEventType.TOKEN_EXCHANGED,
            human_subject=f"user-{idx}",
            actor_id="spiffe://meridian.fin/agent/meridian-ma-copilot",
            jti=f"jti-{t_id}-{idx}",
            decision="ALLOW",
            detail={"worker_idx": idx},
        )
        return rec.entry_hash

    tasks = [(t, i) for t in tenants for i in range(writes_per_tenant)]
    with ThreadPoolExecutor(max_workers=32) as executor:
        hashes = list(executor.map(_worker, tasks))

    assert len(set(hashes)) == len(tasks)
    for t in tenants:
        t_recs = ledger.list_records(tenant_id=t)
        assert [r.sequence_id for r in t_recs] == list(range(1, writes_per_tenant + 1))

    # Stream-verify with small cursor batch_size=13 to exercise multi-fetch server cursor
    valid, msg = ledger.verify_integrity(batch_size=13)
    assert valid is True
    assert "intact" in msg
    pool.close()


def test_32_thread_finops_and_revocation_race_safety() -> None:
    finops = FinOpsTelemetryEngine()
    rev_store = InMemoryRevocationStore()

    def _stress_op(idx: int) -> None:
        jti = f"race-jti-{idx}"
        rev_store.register_issued_token(
            jti=jti,
            human_subject=f"sub-{idx % 6}",
            agent_id="agent-x",
            exp_epoch=9_999_999_999,
        )
        if idx % 17 == 0:
            rev_store.revoke_all_for_subject(f"sub-{idx % 6}", "concurrent_logout")
        else:
            _ = rev_store.is_revoked(jti, f"sub-{idx % 6}", "agent-x")

        finops.record_event(
            GenAITelemetryEvent(
                event_id=f"race-ev-{idx:04d}",
                trace_id=f"race-tr-{idx:04d}",
                tenant_id="meridian-fin",
                cost_center="CORP_DEV",
                workflow_type="ma_diligence_memo",
                human_subject="elena.vance",
                actor_spiffe_id="spiffe://meridian.fin/agent/bot",
                model_id="qwen2.5-8b-awq-local",
                uncached_input_tokens=500,
                output_tokens=100,
                outcome="VERIFIED_RESOLVED",
            )
        )

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(_stress_op, range(200)))

    reports = finops.department_roi_reports("meridian-fin")
    assert len(reports) == 1
    assert reports[0].total_events == 200


def test_circuit_breaker_and_jittered_retry_recovery_and_trip() -> None:
    fake_clock = 100.0
    breaker = CircuitBreaker(
        "sap-test",
        failure_threshold=2,
        recovery_timeout_seconds=10.0,
        clock=lambda: fake_clock,
    )
    sap_twin = LegacySAPSoapTwin()
    call_counter = 0

    def _flaky_soap_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_counter
        call_counter += 1
        # First 2 attempts return HTTP 503 Service Unavailable, 3rd succeeds!
        if call_counter <= 2:
            return httpx.Response(503, content=b"SAP Gateway Busy")
        code, xml = sap_twin.handle_soap_envelope(request.content)
        return httpx.Response(code, content=xml)

    client = HttpSOAPTransport(
        "http://sap.internal/bapi",
        transport=httpx.MockTransport(_flaky_soap_handler),
        circuit_breaker=breaker,
        max_attempts=3,
    )
    env = build_wsse_soap_envelope(
        "BAPI_VENDOR_GETDETAIL",
        {"LIFNR": "0000100450"},
        wsse_username="SVC_AEGIS_RFC",
        wsse_credential="sap_rfc_twin_credential",
    )
    status, _ = client.post_envelope(env)
    assert status == 200
    assert call_counter == 3
    assert breaker.state == CircuitState.CLOSED

    # Now force persistent outage -> circuit trips to OPEN -> fails fast -> recovers via HALF_OPEN
    vllm_healthy = False

    def _vllm_outage_handler(_req: httpx.Request) -> httpx.Response:
        if not vllm_healthy:
            return httpx.Response(503, content=b"CUDA OOM")
        body = TriageClassification(
            temperature=DataTemperature.COLD_PUBLIC_CLOUD_SAFE,
            detected_signals=[],
            confidence=0.99,
            local_triage_summary="Healthy probe",
        ).model_dump_json()
        return httpx.Response(200, json={"choices": [{"message": {"content": body}}]})

    vllm_breaker = CircuitBreaker(
        "vllm-gpu",
        failure_threshold=2,
        recovery_timeout_seconds=30.0,
        clock=lambda: fake_clock,
    )
    vllm = VLLMGuidedJSONClassifierAdapter(
        transport=httpx.MockTransport(_vllm_outage_handler),
        circuit_breaker=vllm_breaker,
        max_attempts=1,
    )

    def _state_of(cb: CircuitBreaker) -> CircuitState:
        return cb.state

    with pytest.raises(TransientDependencyError):
        vllm.classify_prompt("hello")
    assert _state_of(vllm_breaker) == CircuitState.CLOSED

    with pytest.raises(TransientDependencyError):
        vllm.classify_prompt("hello")
    assert _state_of(vllm_breaker) == CircuitState.OPEN

    # While OPEN, immediately raises CircuitOpenError without hitting network
    with pytest.raises(CircuitOpenError):
        vllm.classify_prompt("hello")

    # Advance fake clock past 30s recovery window -> HALF_OPEN -> probe succeeds -> CLOSED!
    fake_clock += 31.0
    assert _state_of(vllm_breaker) == CircuitState.HALF_OPEN
    vllm_healthy = True
    recovered = vllm.classify_prompt("hello")
    assert recovered.temperature == DataTemperature.COLD_PUBLIC_CLOUD_SAFE
    assert _state_of(vllm_breaker) == CircuitState.CLOSED


async def test_portal_browser_ui_correlation_headers_and_readyz() -> None:
    telemetry = AegisTelemetry("ui-test")
    idp = MeridianIdentityProvider()
    audit = PostgresAuditLedger.__new__(PostgresAuditLedger)  # unused in GET /ui
    _ = audit
    from aegis_core.audit import InMemoryAuditLedger

    mem_audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=mem_audit,
        telemetry=telemetry,
    )
    cp = ControlPlaneService(
        broker=broker,
        replay_harness=ShadowReplayHarness(),
        golden_tickets=generate_500_historical_tickets(12),
        finops_engine=FinOpsTelemetryEngine(),
        telemetry=telemetry,
        audit_ledger=mem_audit,
    )
    app = create_admin_control_plane_app(cp)

    admin_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("david.kim"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-admin-console",
            requested_scopes=["admin:control_plane", "admin:prompts:write", "admin:traces:read"],
        )
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://cp") as client:
        ui_r = await client.get("/ui", headers={"X-Request-ID": "req-custom-99"})
        assert ui_r.status_code == 200
        assert "Aegis Enterprise AI" in ui_r.text
        assert ui_r.headers["X-Request-ID"] == "req-custom-99"
        assert ui_r.headers["traceparent"].startswith("00-")

        ready_r = await client.get("/readyz")
        assert ready_r.status_code == 200
        assert ready_r.json()["status"] == "ready"

        fin_r: Any = await client.get(
            "/v1/admin/finops",
            headers={"Authorization": f"Bearer {admin_tok.access_token}"},
        )
        assert fin_r.status_code == 200
        assert isinstance(json.loads(fin_r.text), list)
