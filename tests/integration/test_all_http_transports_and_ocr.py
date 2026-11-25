"""Tier 2 Integration Suite: All FastAPI HTTP transports, Temporal timeouts, and Tesseract OCR."""

from __future__ import annotations

import json
import shutil
import struct
import time
import zlib
from pathlib import Path

import pytest
from enterprise_twin.corpus_seed.historical_tickets import generate_500_historical_tickets
from enterprise_twin.corpus_seed.meridian_corpus import build_meridian_corpus
from enterprise_twin.idp_seed.meridian_idp import (
    MeridianAgentRegistry,
    MeridianIdentityProvider,
)
from enterprise_twin.soap_erp_mock.sap_soap_server import LegacySAPSoapTwin
from httpx import ASGITransport, AsyncClient
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from admin_control_plane.portal_api import (
    ControlPlaneService,
    create_admin_control_plane_app,
)
from aegis_core.audit import InMemoryAuditLedger, PostgresAuditLedger
from aegis_core.models import TokenExchangeRequest
from aegis_core.telemetry import AegisTelemetry
from edge_triage_router.router import (
    DeterministicOnPremClassifierAdapter,
    LocalQuantizedTriageRouter,
    create_edge_triage_app,
)
from finops_telemetry.engine import FinOpsTelemetryEngine, create_finops_app
from legacy_ingestor.pdf_layout_ocr import extract_layout_aware_pdf_chunks
from mcp_erp_bridge.bridge import (
    DirectInProcessSOAPTransport,
    MCPERPBridgeServer,
    create_mcp_erp_app,
)
from secure_rag_engine.app import create_rag_app
from secure_rag_engine.embeddings import DeterministicFinancialEmbedder
from secure_rag_engine.engine import SecureRAGEngine
from secure_rag_engine.store import PostgresRLSRetrievalStore
from shadow_replay_harness.harness import ShadowReplayHarness
from sso_delegation_broker.broker import SSODelegationBroker
from sso_delegation_broker.revocation import InMemoryRevocationStore
from temporal_approval_gate.gate import (
    DurableApprovalGate,
    create_approval_gate_app,
    sign_slack_webhook_payload,
)
from temporal_approval_gate.temporal_defs import (
    HighValuePOApprovalWorkflow,
    TemporalApprovalDecisionSignal,
    TemporalPOInput,
    commit_approved_po_activity,
    dispatch_slack_approval_card_activity,
)

pytestmark = pytest.mark.integration

_GLYPHS_5X7: dict[str, tuple[str, ...]] = {
    "C": ("01110", "10001", "10000", "10000", "10000", "10001", "01110"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    " ": ("00000", "00000", "00000", "00000", "00000", "00000", "00000"),
    "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
}


def _render_crisp_grayscale_png(text: str, scale: int = 6) -> bytes:
    """Render clean high-DPI grayscale PNG bytes using stdlib `zlib`+`struct` for Tesseract OCR."""
    pad = 24
    char_w = 6 * scale
    width = pad * 2 + len(text) * char_w
    height = pad * 2 + 7 * scale
    pixels = [[255 for _ in range(width)] for _ in range(height)]

    for c_idx, ch in enumerate(text):
        glyph = _GLYPHS_5X7.get(ch, _GLYPHS_5X7[" "])
        ox = pad + c_idx * char_w
        for r_idx, row_bits in enumerate(glyph):
            for b_idx, bit in enumerate(row_bits):
                if bit == "1":
                    for dy in range(scale):
                        for dx in range(scale):
                            pixels[pad + r_idx * scale + dy][ox + b_idx * scale + dx] = 0

    raw_scanlines = b"".join(b"\x00" + bytes(row) for row in pixels)

    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(raw_scanlines, 9))
        + _chunk(b"IEND", b"")
    )


def _blank_single_page_pdf() -> bytes:
    """Valid 1-page empty-text PDF triggering scanned-image OCR fallback."""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        b"<< /Length 0 >>\nstream\n\nendstream",
    ]
    buf = bytearray(b"%PDF-1.4\n")
    offs = [0]
    for i, o in enumerate(objs, 1):
        offs.append(len(buf))
        buf.extend(f"{i} 0 obj\n".encode("ascii") + o + b"\nendobj\n")
    xref = len(buf)
    buf.extend(b"xref\n0 5\n0000000000 65535 f \n")
    for off in offs[1:]:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(f"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(buf)


def test_integration_tesseract_ocr_fallback_on_scanned_pdf(tmp_path: Path) -> None:
    png_path = tmp_path / "page_1.png"
    png_path.write_bytes(_render_crisp_grayscale_png("COCO OHS"))
    blank_pdf = _blank_single_page_pdf()

    extracted = extract_layout_aware_pdf_chunks(blank_pdf, ocr_image_fallback_dir=tmp_path)
    if shutil.which("tesseract") or Path("/opt/homebrew/bin/tesseract").exists():
        assert len(extracted) == 1
        assert extracted[0].extraction_method == "tesseract_ocr"
        assert "COCO" in extracted[0].content.upper()


async def test_integration_secure_rag_http_app_and_auth_failures(pg_rls_dsn: str) -> None:
    store = PostgresRLSRetrievalStore(
        dsn=pg_rls_dsn, embedder=DeterministicFinancialEmbedder(dim=64)
    )
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
    app = create_rag_app(SecureRAGEngine(broker=broker, store=store, audit_ledger=audit))

    elena_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://rag") as client:
        assert (await client.get("/healthz")).status_code == 200
        assert (await client.post("/v1/retrieve", json={"query": "Chronos"})).status_code == 401
        assert (
            await client.post(
                "/v1/retrieve",
                headers={"Authorization": "Bearer tampered.jwt.value"},
                json={"query": "Chronos"},
            )
        ).status_code == 401

        ok = await client.post(
            "/v1/retrieve",
            headers={"Authorization": f"Bearer {elena_tok.access_token}"},
            json={"query": "Project Chronos Helios valuation", "top_k": 3},
        )
        assert ok.status_code == 200
        assert ok.json()["security_receipt"]["rls_forced"] is True


async def test_integration_mcp_triage_finops_and_control_plane_http_apps() -> None:
    telemetry = AegisTelemetry("http-int")
    idp = MeridianIdentityProvider()
    audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
        telemetry=telemetry,
    )

    # 1. MCP HTTP App (`/mcp` initialize, tools/list, vendor check, idempotency conflict, >50k gate)
    sap = LegacySAPSoapTwin()
    mcp_app = create_mcp_erp_app(
        MCPERPBridgeServer(
            broker=broker,
            soap_transport=DirectInProcessSOAPTransport(sap),
            audit_ledger=audit,
            telemetry=telemetry,
        )
    )
    priya_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_saml2_assertion_for_persona("priya.nair"),
            subject_token_type="urn:ietf:params:oauth:token-type:saml2",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read", "erp:po:create"],
        )
    )
    p_hdr = {"Authorization": f"Bearer {priya_tok.access_token}"}

    async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://mcp") as m_cli:
        assert (await m_cli.get("/healthz")).status_code == 200
        init_r = await m_cli.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert init_r.json()["result"]["serverInfo"]["name"] == "aegis-sap-erp-mcp"

        list_r = await m_cli.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert len(list_r.json()["result"]["tools"]) == 3

        ven_r = await m_cli.post(
            "/mcp",
            headers=p_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "sap_get_vendor_status", "arguments": {"vendor_id": "0000100450"}},
            },
        )
        assert ven_r.json()["result"]["structuredContent"]["purchasing_blocked"] is False

        # PO > $50k without erp:po:approve is blocked at MCP bridge
        over_r = await m_cli.post(
            "/mcp",
            headers=p_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "sap_create_purchase_order",
                    "arguments": {
                        "vendor_id": "0000100450",
                        "description": "Big PO",
                        "amount_usd": 65_000.0,
                        "idempotency_key": "k-65k",
                    },
                },
            },
        )
        assert over_r.json()["result"]["structuredContent"]["error"] == "temporal_approval_required"

        # Idempotency conflict (-32009) when reusing key with different amount
        await m_cli.post(
            "/mcp",
            headers=p_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "sap_create_purchase_order",
                    "arguments": {
                        "vendor_id": "0000100450",
                        "description": "Small PO",
                        "amount_usd": 10_000.0,
                        "idempotency_key": "k-conflict",
                    },
                },
            },
        )
        conflict_r = await m_cli.post(
            "/mcp",
            headers=p_hdr,
            json={
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "sap_create_purchase_order",
                    "arguments": {
                        "vendor_id": "0000100450",
                        "description": "Small PO",
                        "amount_usd": 12_000.0,
                        "idempotency_key": "k-conflict",
                    },
                },
            },
        )
        assert conflict_r.json()["error"]["code"] == -32009

    # 2. Edge Triage HTTP App (`/v1/triage` 200, 401, and 503 overload)
    triage_router = LocalQuantizedTriageRouter(
        broker=broker,
        classifier=DeterministicOnPremClassifierAdapter(),
        audit_ledger=audit,
        max_kv_cache_tokens=512,
    )
    triage_app = create_edge_triage_app(triage_router)
    async with AsyncClient(transport=ASGITransport(app=triage_app), base_url="http://edge") as e_cli:
        assert (await e_cli.get("/healthz")).status_code == 200
        assert (await e_cli.post("/v1/triage", json={"prompt": "hi"})).status_code == 401
        ok_t = await e_cli.post("/v1/triage", headers=p_hdr, json={"prompt": "Project Chronos deal"})
        assert ok_t.status_code == 200
        assert ok_t.json()["egress_permitted"] is False

        triage_router.simulate_gpu_kv_load(500)
        shed_r = await e_cli.post("/v1/triage", headers=p_hdr, json={"prompt": "Project Chronos"})
        assert shed_r.status_code == 503

    # 3. FinOps HTTP App + Admin Control Plane Traces & FinOps views
    finops = FinOpsTelemetryEngine()
    finops_app = create_finops_app(finops)
    async with AsyncClient(transport=ASGITransport(app=finops_app), base_url="http://fin") as f_cli:
        assert (await f_cli.get("/healthz")).status_code == 200
        ev_r = await f_cli.post(
            "/v1/finops/events",
            json={
                "event_id": "ev-http-1",
                "trace_id": "tr-http-1",
                "tenant_id": "meridian-fin",
                "cost_center": "FINANCE_OPS",
                "workflow_type": "sap_po_triage",
                "human_subject": "priya.nair",
                "actor_spiffe_id": "spiffe://meridian.fin/agent/meridian-procurement-agent",
                "model_id": "qwen2.5-8b-awq-local",
                "uncached_input_tokens": 1000,
                "output_tokens": 100,
                "outcome": "VERIFIED_RESOLVED",
            },
        )
        assert ev_r.status_code == 200
        roi_r = await f_cli.get("/v1/finops/roi/meridian-fin")
        assert roi_r.status_code == 200
        assert roi_r.json()[0]["cost_center"] == "FINANCE_OPS"

    cp_svc = ControlPlaneService(
        broker=broker,
        replay_harness=ShadowReplayHarness(),
        golden_tickets=generate_500_historical_tickets(20),
        finops_engine=finops,
        telemetry=telemetry,
        audit_ledger=audit,
    )
    cp_app = create_admin_control_plane_app(cp_svc)
    admin_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("david.kim"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-admin-console",
            requested_scopes=["admin:control_plane", "admin:prompts:write", "admin:traces:read"],
        )
    )
    a_hdr = {"Authorization": f"Bearer {admin_tok.access_token}"}
    assert len(cp_svc.get_finops_dashboard(bearer_token=admin_tok.access_token)) == 1

    async with AsyncClient(transport=ASGITransport(app=cp_app), base_url="http://cp") as c_cli:
        tr_r = await c_cli.get("/v1/admin/traces", headers=a_hdr)
        assert tr_r.status_code == 200
        assert len(tr_r.json()) >= 3
        # Non-admin Priya token MUST get 403 on admin endpoints!
        assert (await c_cli.get("/v1/admin/traces", headers=p_hdr)).status_code == 403


async def test_integration_temporal_72h_timeout_and_human_rejection(tmp_path: Path) -> None:
    # 1. Verify Temporal 72h SLA auto-escalation timeout using time-skipping WorkflowEnvironment
    async with await WorkflowEnvironment.start_time_skipping() as env, Worker(
        env.client,
        task_queue="q-timeout",
        workflows=[HighValuePOApprovalWorkflow],
        activities=[dispatch_slack_approval_card_activity, commit_approved_po_activity],
    ):
        # Start workflow with NO human approval signal -> time-skipping advances 72 hours instantly!
        timeout_res = await env.client.execute_workflow(
            HighValuePOApprovalWorkflow.run,
            TemporalPOInput(
                workflow_id="wf-sla-timeout",
                tenant_id="meridian-fin",
                requester_sub="priya.nair",
                vendor_id="0000100450",
                company_code="1000",
                description="Unanswered PO",
                amount_usd=75_000.0,
                expected_vendor_state_etag="etag",
            ),
            id="wf-sla-timeout",
            task_queue="q-timeout",
        )
        assert timeout_res["status"] == "TIMED_OUT_ESCALATED"
        assert timeout_res["approved"] is False

        # Also verify human rejection signal in Temporal SDK
        rej_handle = await env.client.start_workflow(
            HighValuePOApprovalWorkflow.run,
            TemporalPOInput(
                workflow_id="wf-sdk-reject",
                tenant_id="meridian-fin",
                requester_sub="priya.nair",
                vendor_id="0000100450",
                company_code="1000",
                description="Rejected PO",
                amount_usd=80_000.0,
                expected_vendor_state_etag="etag",
            ),
            id="wf-sdk-reject",
            task_queue="q-timeout",
        )
        assert await rej_handle.query(HighValuePOApprovalWorkflow.current_status) in (
            "INITIALIZING",
            "AWAITING_HUMAN_APPROVAL",
        )
        await rej_handle.signal(
            HighValuePOApprovalWorkflow.submit_decision,
            TemporalApprovalDecisionSignal(
                approved=False,
                approver_sub="elena.vance",
                approver_subject_token="tok",
                approver_token_type="urn:ietf:params:oauth:token-type:access_token",
                comment="Budget frozen",
            ),
        )
        rej_res = await rej_handle.result()
        assert rej_res["status"] == "REJECTED_BY_APPROVER"

    # 2. Verify HTTP rejection + status lookup on DurableApprovalGate
    idp = MeridianIdentityProvider()
    audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
    )
    mcp = MCPERPBridgeServer(
        broker=broker,
        soap_transport=DirectInProcessSOAPTransport(LegacySAPSoapTwin()),
        audit_ledger=audit,
    )
    gate = DurableApprovalGate(
        db_path=tmp_path / "rej.sqlite",
        broker=broker,
        mcp_bridge=mcp,
        audit_ledger=audit,
    )
    app = create_approval_gate_app(gate)
    priya_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_saml2_assertion_for_persona("priya.nair"),
            subject_token_type="urn:ietf:params:oauth:token-type:saml2",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read", "erp:po:create"],
        )
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://gate") as g_cli:
        assert (await g_cli.get("/healthz")).status_code == 200
        assert (await g_cli.get("/v1/approvals/missing-id")).status_code == 404
        sub = await g_cli.post(
            "/v1/approvals/po",
            headers={"Authorization": f"Bearer {priya_tok.access_token}"},
            json={"vendor_id": "0000100450", "description": "Optional tool", "amount_usd": 60_000.0},
        )
        wf_id = sub.json()["workflow_id"]
        assert (await g_cli.get(f"/v1/approvals/{wf_id}")).json()["status"] == "AWAITING_APPROVAL"

        rej_body = json.dumps(
            {
                "workflow_id": wf_id,
                "action": "reject",
                "approver_subject_token": idp.issue_oidc_token_for_persona("elena.vance"),
                "comment": "Deferred to Q1",
            }
        ).encode("utf-8")
        ts = int(time.time())
        sig = sign_slack_webhook_payload(
            signing_secret=gate.slack_signing_secret, timestamp=ts, raw_body=rej_body
        )
        dec = await g_cli.post(
            "/v1/webhooks/slack/interactive",
            content=rej_body,
            headers={"X-Slack-Request-Timestamp": str(ts), "X-Slack-Signature": sig},
        )
        assert dec.json()["status"] == "REJECTED"
