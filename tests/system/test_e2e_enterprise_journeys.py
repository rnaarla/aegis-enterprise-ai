"""Tier 3 System Suite: Full cross-service HTTP + PostgreSQL 18 + SAP SOAP + Temporal journeys."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from enterprise_twin.corpus_seed.historical_tickets import generate_500_historical_tickets
from enterprise_twin.corpus_seed.meridian_corpus import build_meridian_corpus
from enterprise_twin.demo_runner.run_ciso_pov import _execute_ciso_pov
from enterprise_twin.demo_runner.run_full_12_module_pov import run_all_12_projects_live
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
from aegis_core.telemetry import AegisTelemetry
from edge_triage_router.router import (
    DeterministicOnPremClassifierAdapter,
    LocalQuantizedTriageRouter,
    create_edge_triage_app,
)
from finops_telemetry.engine import FinOpsTelemetryEngine, create_finops_app
from mcp_erp_bridge.bridge import (
    DirectInProcessSOAPTransport,
    MCPERPBridgeServer,
)
from pii_unmasking_proxy.proxy import DeterministicPIIProxy, create_pii_proxy_app
from pii_unmasking_proxy.vault import EnvelopeEncryptedPIIVault
from secure_rag_engine.app import create_rag_app
from secure_rag_engine.embeddings import DeterministicFinancialEmbedder
from secure_rag_engine.engine import SecureRAGEngine
from secure_rag_engine.store import PostgresRLSRetrievalStore
from shadow_replay_harness.harness import ShadowReplayHarness
from sso_delegation_broker.app import create_broker_app
from sso_delegation_broker.broker import SSODelegationBroker
from sso_delegation_broker.revocation import InMemoryRevocationStore
from temporal_approval_gate.gate import (
    DurableApprovalGate,
    create_approval_gate_app,
    sign_slack_webhook_payload,
)

pytestmark = pytest.mark.system


class _SystemCloudLLM:
    def complete(self, masked_messages: list[dict[str, str]], model: str) -> str:
        return f"[{model}] Ready: {masked_messages[-1]['content']}"

    def stream_complete(self, masked_messages: list[dict[str, str]], model: str) -> Iterator[str]:
        _ = (masked_messages, model)
        yield from ["Drafted PO for ", "<PER", "SON_001> (SSN <SS", "N_001>)"]


async def test_system_ciso_6_scenario_pov_runner(pg_rls_dsn: str) -> None:
    await _execute_ciso_pov(pg_rls_dsn)


def test_system_full_12_module_master_pov_runner() -> None:
    run_all_12_projects_live()


async def test_system_6_hop_enterprise_http_journey(pg_rls_dsn: str, tmp_path: Path) -> None:
    """Execute a complete 6-service HTTP transaction from SAML login to SAP PO & OTel audit."""
    telemetry = AegisTelemetry("aegis-system-e2e")
    audit = PostgresAuditLedger(dsn=pg_rls_dsn)
    store = PostgresRLSRetrievalStore(
        dsn=pg_rls_dsn, embedder=DeterministicFinancialEmbedder(dim=64)
    )
    store.apply_migrations()
    chunks, tuples = build_meridian_corpus()
    store.ingest_chunks(chunks, tuples)

    idp = MeridianIdentityProvider()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
        telemetry=telemetry,
    )
    sap_twin = LegacySAPSoapTwin()
    mcp_srv = MCPERPBridgeServer(
        broker=broker,
        soap_transport=DirectInProcessSOAPTransport(sap_twin),
        audit_ledger=audit,
        telemetry=telemetry,
    )
    finops = FinOpsTelemetryEngine()
    gate = DurableApprovalGate(
        db_path=tmp_path / "sys_wal.sqlite",
        broker=broker,
        mcp_bridge=mcp_srv,
        audit_ledger=audit,
    )

    broker_app = create_broker_app(broker, audit)
    triage_app = create_edge_triage_app(
        LocalQuantizedTriageRouter(
            broker=broker,
            classifier=DeterministicOnPremClassifierAdapter(),
            audit_ledger=audit,
        )
    )
    pii_app = create_pii_proxy_app(
        DeterministicPIIProxy(
            broker=broker,
            vault=EnvelopeEncryptedPIIVault(),
            upstream_llm=_SystemCloudLLM(),
            audit_ledger=audit,
        )
    )
    rag_app = create_rag_app(
        SecureRAGEngine(broker=broker, store=store, audit_ledger=audit, telemetry=telemetry)
    )
    gate_app = create_approval_gate_app(gate)
    finops_app = create_finops_app(finops)
    cp_app = create_admin_control_plane_app(
        ControlPlaneService(
            broker=broker,
            replay_harness=ShadowReplayHarness(),
            golden_tickets=generate_500_historical_tickets(40),
            finops_engine=finops,
            telemetry=telemetry,
            audit_ledger=audit,
        )
    )

    async with (
        AsyncClient(transport=ASGITransport(app=broker_app), base_url="http://broker") as b_cli,
        AsyncClient(transport=ASGITransport(app=triage_app), base_url="http://triage") as t_cli,
        AsyncClient(transport=ASGITransport(app=pii_app), base_url="http://pii") as p_cli,
        AsyncClient(transport=ASGITransport(app=rag_app), base_url="http://rag") as r_cli,
        AsyncClient(transport=ASGITransport(app=gate_app), base_url="http://gate") as g_cli,
        AsyncClient(transport=ASGITransport(app=finops_app), base_url="http://fin") as f_cli,
        AsyncClient(transport=ASGITransport(app=cp_app), base_url="http://cp") as c_cli,
    ):
        # Hop 1: VP Procurement Priya exchanges SAML 2.0 assertion for 5m ES256 agent JWT
        tok_r = await b_cli.post(
            "/v1/oauth/token",
            json={
                "subject_token": idp.issue_saml2_assertion_for_persona("priya.nair"),
                "subject_token_type": "urn:ietf:params:oauth:token-type:saml2",
                "agent_id": "meridian-procurement-agent",
                "requested_scopes": ["rag:read", "erp:po:create", "erp:po:approve"],
            },
        )
        assert tok_r.status_code == 200
        p_hdr = {"Authorization": f"Bearer {tok_r.json()['access_token']}"}

        # Hop 2: Local AWQ 8B Triage classifies prompt containing SSN -> WARM_PII_MASK_REQUIRED
        user_prompt = "Onboard Elena Vance (SSN 123-45-6789) and check SAP PO threshold"
        tri_r = await t_cli.post("/v1/triage", headers=p_hdr, json={"prompt": user_prompt})
        assert tri_r.json()["route_target"] == "PII_MASKING_PROXY_TO_CLOUD"

        # Hop 3: Stream response through Deterministic PII SSE Proxy
        sse_r = await p_cli.post(
            "/v1/chat/completions",
            headers=p_hdr,
            json={
                "session_id": "sys-sess-1",
                "messages": [{"role": "user", "content": user_prompt}],
                "stream": True,
            },
        )
        assert "123-45-6789" in sse_r.text and "<SSN_001>" not in sse_r.text

        # Hop 4: Retrieve procurement policy from PostgreSQL 18 FORCE RLS RAG
        rag_r = await r_cli.post(
            "/v1/retrieve",
            headers=p_hdr,
            json={"query": "SAP Purchase Order USD 50,000 threshold Temporal", "top_k": 3},
        )
        assert any(c["document_id"] == "doc-sap-vendor-master" for c in rag_r.json()["results"])

        # Hop 5: Submit $68,000 PO -> Temporal Gate pauses -> MD approves via HMAC Slack webhook
        po_r = await g_cli.post(
            "/v1/approvals/po",
            headers=p_hdr,
            json={
                "vendor_id": "0000100450",
                "description": "Enterprise Cloud Security Platform",
                "amount_usd": 68_000.0,
            },
        )
        wf_id = po_r.json()["workflow_id"]
        slack_bytes = json.dumps(
            {
                "workflow_id": wf_id,
                "action": "approve",
                "approver_subject_token": idp.issue_oidc_token_for_persona("elena.vance"),
                "comment": "Approved by MD",
            }
        ).encode("utf-8")
        ts = int(time.time())
        sig = sign_slack_webhook_payload(
            signing_secret=gate.slack_signing_secret, timestamp=ts, raw_body=slack_bytes
        )
        exec_r = await g_cli.post(
            "/v1/webhooks/slack/interactive",
            content=slack_bytes,
            headers={"X-Slack-Request-Timestamp": str(ts), "X-Slack-Signature": sig},
        )
        assert exec_r.json()["status"] == "APPROVED_EXECUTED"
        assert exec_r.json()["sap_po_number"] == "4500019201"

        # Hop 6: Record FinOps telemetry + IT Admin inspects OTel traces & verifies SHA-256 ledger
        await f_cli.post(
            "/v1/finops/events",
            json={
                "event_id": "ev-sys-68k",
                "trace_id": "tr-sys-68k",
                "tenant_id": "meridian-fin",
                "cost_center": "FINANCE_OPS",
                "workflow_type": "sap_po_triage",
                "human_subject": "priya.nair",
                "actor_spiffe_id": "spiffe://meridian.fin/agent/meridian-procurement-agent",
                "model_id": "gpt-5-enterprise",
                "uncached_input_tokens": 1500,
                "cached_input_tokens": 8000,
                "output_tokens": 350,
                "outcome": "VERIFIED_RESOLVED",
            },
        )

        admin_tok_r = await b_cli.post(
            "/v1/oauth/token",
            json={
                "subject_token": idp.issue_oidc_token_for_persona("david.kim"),
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "agent_id": "meridian-admin-console",
                "requested_scopes": ["admin:control_plane", "admin:traces:read"],
            },
        )
        a_hdr = {"Authorization": f"Bearer {admin_tok_r.json()['access_token']}"}
        traces_r = await c_cli.get("/v1/admin/traces", headers=a_hdr)
        assert traces_r.status_code == 200 and len(traces_r.json()) >= 4

        audit_r = await b_cli.get("/v1/audit/verify")
        assert audit_r.json()["valid"] is True
