"""Comprehensive integration & adversarial test suite covering Projects 2, 3, 5, 6, 7, 8, 9, 10, 11, 12."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path

import pytest
from enterprise_twin.corpus_seed.historical_tickets import generate_500_historical_tickets
from enterprise_twin.idp_seed.meridian_idp import (
    MeridianAgentRegistry,
    MeridianIdentityProvider,
)
from enterprise_twin.soap_erp_mock.sap_soap_server import (
    LegacySAPSoapTwin,
    create_sap_soap_app,
)
from httpx import ASGITransport, AsyncClient
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from admin_control_plane.portal_api import (
    ControlPlaneService,
    PromptPromotionError,
    create_admin_control_plane_app,
)
from aegis_core.audit import InMemoryAuditLedger, PostgresAuditLedger
from aegis_core.models import (
    DocumentClassification,
    RetrievalQuery,
    TokenExchangeRequest,
)
from aegis_core.telemetry import AegisTelemetry
from airgap_verifier.audit_airgap import verify_airgap_bundle_readiness
from arch_scoper.scoper import (
    ArchitectureScoperEngine,
    ScopeDiscoveryIntake,
    validate_mermaid_flowchart_syntax,
)
from edge_triage_router.router import (
    DataTemperature,
    DeterministicOnPremClassifierAdapter,
    EdgeTriageOverloadError,
    LocalQuantizedTriageRouter,
)
from finops_telemetry.engine import FinOpsTelemetryEngine, GenAITelemetryEvent
from legacy_ingestor.cobol_ebcdic import (
    decode_comp3,
    encode_acctldgr_ebcdic_record,
    encode_comp3,
    parse_ebcdic_copybook_stream,
)
from legacy_ingestor.pipeline import LegacyIngestionPipeline
from mcp_erp_bridge.bridge import (
    DirectInProcessSOAPTransport,
    JSONRPCRequest,
    MCPERPBridgeServer,
)
from pii_unmasking_proxy.proxy import (
    DeterministicPIIProxy,
    create_pii_proxy_app,
)
from pii_unmasking_proxy.sse_stream import passes_luhn_checksum
from pii_unmasking_proxy.vault import EnvelopeEncryptedPIIVault
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


def _build_two_page_pdf(page1_lines: list[str], page2_lines: list[str]) -> bytes:
    """Build a valid ISO 32000 PDF-1.4 binary with two text pages and exact xref byte offsets."""

    def _escape_pdf(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def _page_stream(lines: list[str]) -> bytes:
        ops = ["BT", "/F1 11 Tf", "50 740 Td", "14 TL"]
        for idx, ln in enumerate(lines):
            if idx == 0:
                ops.append(f"({_escape_pdf(ln)}) Tj")
            else:
                ops.append(f"T* ({_escape_pdf(ln)}) Tj")
        ops.append("ET")
        return "\n".join(ops).encode("latin-1")

    s1 = _page_stream(page1_lines)
    s2 = _page_stream(page2_lines)

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>"
        ),
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(s1)).encode("ascii") + b" >>\nstream\n" + s1 + b"\nendstream",
        b"<< /Length " + str(len(s2)).encode("ascii") + b" >>\nstream\n" + s2 + b"\nendstream",
    ]

    buf = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(buf))
        buf.extend(f"{idx} 0 obj\n".encode("ascii"))
        buf.extend(obj)
        buf.extend(b"\nendobj\n")

    xref_pos = len(buf)
    buf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    buf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(buf)


def _make_broker() -> tuple[SSODelegationBroker, MeridianIdentityProvider, InMemoryAuditLedger]:
    idp = MeridianIdentityProvider()
    audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
    )
    return broker, idp, audit


def test_project2_airgap_bundle_and_zero_egress_invariants() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    report = verify_airgap_bundle_readiness(repo_root)
    assert report.all_passed is True
    assert len(report.findings) >= 6


def test_project3_cobol_comp3_signed_decimals_and_pdf_table_carryover(pg_rls_dsn: str) -> None:
    # Verify negative & positive COMP-3 BCD bit-level round-trip
    neg_bytes = encode_comp3(Decimal("-48250.75"), byte_length=6, scale=2)
    assert (neg_bytes[-1] & 0x0F) == 0x0D  # IBM z/OS negative sign nibble
    assert decode_comp3(neg_bytes, scale=2) == Decimal("-48250.75")

    rec1 = encode_acctldgr_ebcdic_record(
        acct_id="ESCROW-9901",
        cost_center="MA_DEAL",
        settle_date="20261124",
        balance_usd=Decimal("420000000.50"),
        facility_pct=Decimal("22.75"),
        status_desc="ACTIVE_ESCROW",
    )
    rec2 = encode_acctldgr_ebcdic_record(
        acct_id="HEDGING-1102",
        cost_center="TREASURY",
        settle_date="20261124",
        balance_usd=Decimal("-1250000.25"),
        facility_pct=Decimal("4.10"),
        status_desc="SHORT_SWAP_MARGIN",
    )
    parsed = parse_ebcdic_copybook_stream(rec1 + rec2)
    assert len(parsed) == 2
    assert parsed[0]["_byte_offset_hex"] == "0x000000"
    assert parsed[1]["_byte_offset_hex"] == "0x000038"
    assert parsed[1]["BALANCE_USD"] == Decimal("-1250000.25")

    # Build a 2-page PDF where Page 1 opens a pipe table and Page 2 continues rows without header
    pdf_bytes = _build_two_page_pdf(
        page1_lines=[
            "Project Chronos Debt Commitment Schedule",
            "| Tranche | Commitment_USD | Pricing_BPS |",
            "| Term_Loan_A | 1500000000 | SOFR+225 |",
        ],
        page2_lines=[
            "| Bridge_Facility_B | 2700000000 | SOFR+375 |",
        ],
    )

    store = PostgresRLSRetrievalStore(
        dsn=pg_rls_dsn, embedder=DeterministicFinancialEmbedder(dim=64)
    )
    store.apply_migrations()
    audit = PostgresAuditLedger(dsn=pg_rls_dsn)
    pipeline = LegacyIngestionPipeline(retrieval_store=store, audit_ledger=audit)

    pdf_chunks = pipeline.ingest_pdf_document(
        tenant_id="meridian-fin",
        document_id="doc-chronos-debt-pdf",
        title="Chronos Debt Schedule",
        source_uri="sharepoint://meridian.fin/debt_schedule.pdf",
        pdf_bytes=pdf_bytes,
        classification=DocumentClassification.TOP_SECRET_MA,
        department_owner="CORP_DEV",
        viewer_groups=["deal-chronos"],
    )
    assert len(pdf_chunks) == 2
    # Page 2 chunk MUST carry over Page 1's table header automatically!
    assert "| Tranche | Commitment_USD | Pricing_BPS |" in pdf_chunks[1].content
    assert "Bridge_Facility_B" in pdf_chunks[1].content

    # Verify RLS visibility of ingested PDF inside PostgreSQL 18
    broker, idp, _ = _make_broker()
    rag = SecureRAGEngine(broker=broker, store=store, audit_ledger=audit)
    md_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    )
    res = rag.retrieve(
        bearer_token=md_tok.access_token,
        request=RetrievalQuery(query="Bridge_Facility_B Commitment_USD Pricing_BPS", top_k=5),
    )
    assert any(c.document_id == "doc-chronos-debt-pdf" for c in res.results)


async def test_project5_mcp_soap_bapiret2_errors_and_idempotency() -> None:
    broker, idp, audit = _make_broker()
    sap_twin = LegacySAPSoapTwin()
    soap_app = create_sap_soap_app(sap_twin)

    async with AsyncClient(transport=ASGITransport(app=soap_app), base_url="http://sap") as s_cli:
        wsdl_r = await s_cli.get("/sap/bc/srt/wsdl/bapi_po")
        assert wsdl_r.status_code == 200
        assert "BAPI_PO_CREATE1" in wsdl_r.text

    bridge = MCPERPBridgeServer(
        broker=broker,
        soap_transport=DirectInProcessSOAPTransport(sap_twin),
        audit_ledger=audit,
    )
    priya_tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_saml2_assertion_for_persona("priya.nair"),
            subject_token_type="urn:ietf:params:oauth:token-type:saml2",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read", "erp:po:create"],
        )
    )

    # 1. Blocked SAP vendor (`0000999999` has SPERR=X) returns HTTP 200 SOAP XML with TYPE='E'
    blocked_call = bridge.handle_jsonrpc(
        JSONRPCRequest(
            id=10,
            method="tools/call",
            params={
                "name": "sap_create_purchase_order",
                "arguments": {
                    "vendor_id": "0000999999",
                    "description": "Attempted PO to blocked vendor",
                    "amount_usd": 5_000.00,
                    "idempotency_key": "idem-blocked-1",
                },
            },
        ),
        bearer_token=priya_tok.access_token,
    )
    assert blocked_call["result"]["isError"] is True
    assert "SPERR=X" in blocked_call["result"]["structuredContent"]["sap_return"]["message"]
    assert len(sap_twin.list_purchase_orders()) == 0

    # 2. Valid PO <= $50k succeeds, and retrying with identical idempotency_key does NOT duplicate!
    po_args = {
        "vendor_id": "0000100450",
        "description": "Cloud Security Scanner Annual License",
        "amount_usd": 32_000.00,
        "idempotency_key": "idem-sec-32k",
    }
    first = bridge.handle_jsonrpc(
        JSONRPCRequest(
            id=11,
            method="tools/call",
            params={"name": "sap_create_purchase_order", "arguments": po_args},
        ),
        bearer_token=priya_tok.access_token,
    )
    retry = bridge.handle_jsonrpc(
        JSONRPCRequest(
            id=12,
            method="tools/call",
            params={"name": "sap_create_purchase_order", "arguments": po_args},
        ),
        bearer_token=priya_tok.access_token,
    )
    assert first["result"]["isError"] is False
    assert retry["result"]["structuredContent"]["idempotent_replay"] is True
    assert (
        first["result"]["structuredContent"]["po_number"]
        == retry["result"]["structuredContent"]["po_number"]
    )
    assert len(sap_twin.list_purchase_orders()) == 1


class _AdversarialSplitStreamLLM:
    def complete(self, masked_messages: list[dict[str, str]], model: str) -> str:
        _ = model
        content = masked_messages[-1]["content"]
        # Verify raw SSN, Visa, and Name never reached the model!
        assert "4532015112830366" not in content
        assert "123-45-6789" not in content
        assert "Elena Vance" not in content
        # Verify co-reference: both "Elena Vance" and "Ms. Vance" mapped to `<PERSON_001>`!
        assert content.count("<PERSON_001>") == 2
        return f"Verified {content}"

    def stream_complete(self, masked_messages: list[dict[str, str]], model: str) -> Iterator[str]:
        _ = (masked_messages, model)
        # Pathological 2-3 char splits right through surrogate tags
        yield from ["Pay ", "<PE", "RSON_", "001", "> card ", "<C", "C_001", "> SSN <SSN_0", "01>!"]


async def test_project6_aes_gcm_pii_vault_coref_and_split_sse_rehydration() -> None:
    assert passes_luhn_checksum("4532015112830366") is True
    assert passes_luhn_checksum("4532015112830367") is False

    broker, idp, audit = _make_broker()
    vault = EnvelopeEncryptedPIIVault()
    proxy = DeterministicPIIProxy(
        broker=broker,
        vault=vault,
        upstream_llm=_AdversarialSplitStreamLLM(),
        audit_ledger=audit,
    )
    app = create_pii_proxy_app(proxy)
    tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    )

    msg_text = (
        "Client Elena Vance (SSN 123-45-6789, card 4532015112830366) confirmed "
        "that Ms. Vance authorized the wire."
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://pii") as client:
        sync_r = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {tok.access_token}"},
            json={
                "session_id": "sess-coref-1",
                "messages": [{"role": "user", "content": msg_text}],
                "stream": False,
            },
        )
        assert sync_r.status_code == 200
        restored_sync = sync_r.json()["choices"][0]["message"]["content"]
        assert "123-45-6789" in restored_sync
        assert "4532015112830366" in restored_sync

        # Verify raw ciphertext in AES-256-GCM vault does NOT contain plaintext SSN bytes
        raw_ct = vault.inspect_raw_ciphertext(session_id="sess-coref-1", surrogate_tag="<SSN_001>")
        assert raw_ct is not None and b"123-45-6789" not in raw_ct

        # Test streaming SSE endpoint with hostile split token chunks
        sse_r = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {tok.access_token}"},
            json={
                "session_id": "sess-coref-1",
                "messages": [{"role": "user", "content": msg_text}],
                "stream": True,
            },
        )
        assert sse_r.status_code == 200
        assembled = ""
        for line in sse_r.text.splitlines():
            if line.startswith("data: ") and line != "data: [DONE]":
                chunk_obj = json.loads(line.removeprefix("data: "))
                assembled += chunk_obj["choices"][0]["delta"]["content"]
        assert assembled == "Pay Elena Vance card 4532015112830366 SSN 123-45-6789!"


async def test_project7_temporal_sdk_workflow_and_toctou_drift_abort(tmp_path: Path) -> None:
    # 1. Verify genuine `temporalio` Python SDK workflow + signal execution with time-skipping server
    async with await WorkflowEnvironment.start_time_skipping() as env, Worker(
        env.client,
        task_queue="aegis-po-approvals",
        workflows=[HighValuePOApprovalWorkflow],
        activities=[dispatch_slack_approval_card_activity, commit_approved_po_activity],
    ):
        handle = await env.client.start_workflow(
            HighValuePOApprovalWorkflow.run,
            TemporalPOInput(
                workflow_id="wf-temporal-sdk-01",
                tenant_id="meridian-fin",
                requester_sub="priya.nair",
                vendor_id="0000100450",
                company_code="1000",
                description="M&A Data Room Subscription",
                amount_usd=85_000.00,
                expected_vendor_state_etag="etag-123",
            ),
            id="wf-temporal-sdk-01",
            task_queue="aegis-po-approvals",
        )
        await handle.signal(
            HighValuePOApprovalWorkflow.submit_decision,
            TemporalApprovalDecisionSignal(
                approved=True,
                approver_sub="elena.vance",
                approver_subject_token="tok",
                approver_token_type="urn:ietf:params:oauth:token-type:access_token",
                comment="LGTM",
            ),
        )
        wf_out = await handle.result()
        assert wf_out["status"] == "EXECUTED"
        assert wf_out["approved_by"] == "elena.vance"

    # 2. Verify Slack HMAC verification + TOCTOU vendor bank IBAN drift abort over HTTP
    broker, idp, audit = _make_broker()
    sap_twin = LegacySAPSoapTwin()
    mcp = MCPERPBridgeServer(
        broker=broker,
        soap_transport=DirectInProcessSOAPTransport(sap_twin),
        audit_ledger=audit,
    )
    wal_db = tmp_path / "gate_wal.sqlite"
    gate = DurableApprovalGate(
        db_path=wal_db,
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://gate") as client:
        sub_r = await client.post(
            "/v1/approvals/po",
            headers={"Authorization": f"Bearer {priya_tok.access_token}"},
            json={
                "vendor_id": "0000100450",
                "description": "Advisory Retainer PO > 50k",
                "amount_usd": 90_000.00,
            },
        )
        assert sub_r.status_code == 200
        wf_id = sub_r.json()["workflow_id"]

        # Mutate vendor IBAN in SAP while PO is paused awaiting Slack click (TOCTOU attack!)
        sap_twin.mutate_vendor_bank_iban("0000100450", "CH9300762011623852957")

        decision_bytes = json.dumps(
            {
                "workflow_id": wf_id,
                "action": "approve",
                "approver_subject_token": idp.issue_oidc_token_for_persona("elena.vance"),
                "comment": "Approving",
            }
        ).encode("utf-8")

        # Forged Slack signature MUST return 401
        bad_sig_r = await client.post(
            "/v1/webhooks/slack/interactive",
            content=decision_bytes,
            headers={
                "X-Slack-Request-Timestamp": str(int(time.time())),
                "X-Slack-Signature": "v0=deadbeef",
            },
        )
        assert bad_sig_r.status_code == 401

        # Valid HMAC Slack signature wakes workflow -> catches TOCTOU vendor IBAN drift!
        ts_now = int(time.time())
        good_sig = sign_slack_webhook_payload(
            signing_secret=gate.slack_signing_secret,
            timestamp=ts_now,
            raw_body=decision_bytes,
        )
        drift_r = await client.post(
            "/v1/webhooks/slack/interactive",
            content=decision_bytes,
            headers={
                "X-Slack-Request-Timestamp": str(ts_now),
                "X-Slack-Signature": good_sig,
            },
        )
        assert drift_r.status_code == 200
        assert drift_r.json()["status"] == "ABORTED_TOCTOU_DRIFT"
        assert len(sap_twin.list_purchase_orders()) == 0


def test_project8_local_triage_fail_closed_on_gpu_kv_saturation() -> None:
    broker, idp, audit = _make_broker()
    router = LocalQuantizedTriageRouter(
        broker=broker,
        classifier=DeterministicOnPremClassifierAdapter(),
        audit_ledger=audit,
        max_kv_cache_tokens=1_024,
    )
    tok = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=idp.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
        )
    )

    warm = router.evaluate_and_route(
        bearer_token=tok.access_token,
        prompt="Verify tax record for SSN 123-45-6789",
    )
    assert warm.classification.temperature == DataTemperature.WARM_PII_MASK_REQUIRED
    assert warm.route_target == "PII_MASKING_PROXY_TO_CLOUD"

    # Saturate KV cache -> router MUST fail closed (never fail open to public cloud!)
    router.simulate_gpu_kv_load(1_000)
    with pytest.raises(EdgeTriageOverloadError, match="failing closed"):
        router.evaluate_and_route(bearer_token=tok.access_token, prompt="Project Chronos secret")


def test_project9_finops_rework_penalty_and_project11_scoper() -> None:
    finops = FinOpsTelemetryEngine()
    # Log 1 verified resolution and 4 human escalations -> net ROI must go negative!
    finops.record_event(
        GenAITelemetryEvent(
            event_id="ev-001",
            trace_id="trace-001",
            tenant_id="meridian-fin",
            cost_center="EQUITY_OPS",
            workflow_type="sap_po_triage",
            human_subject="priya.nair",
            actor_spiffe_id="spiffe://meridian.fin/agent/bot",
            model_id="gpt-5-enterprise",
            uncached_input_tokens=50_000,
            output_tokens=10_000,
            outcome="VERIFIED_RESOLVED",
        )
    )
    for idx in range(4):
        finops.record_event(
            GenAITelemetryEvent(
                event_id=f"esc-{idx}",
                trace_id=f"tesc-{idx}",
                tenant_id="meridian-fin",
                cost_center="EQUITY_OPS",
                workflow_type="sap_po_triage",
                human_subject="priya.nair",
                actor_spiffe_id="spiffe://meridian.fin/agent/bot",
                model_id="gpt-5-enterprise",
                uncached_input_tokens=50_000,
                output_tokens=10_000,
                outcome="HUMAN_ESCALATED",
            )
        )
    rep = finops.department_roi_reports("meridian-fin")[0]
    assert rep.net_hours_saved < 0
    assert rep.net_roi_usd < 0

    scoper = ArchitectureScoperEngine()
    sow = scoper.generate_sow(
        ScopeDiscoveryIntake(
            client_name="Global Bank Corp",
            executive_objective="Automate COBOL & SAP workflows in disconnected enclave.",
            compliance_regimes=["FEDRAMP_HIGH", "PCI_DSS"],
            air_gapped_vpc_required=True,
            requested_hosted_public_llm_api=True,
            legacy_sources=["COBOL_MAINFRAME", "SAP_SOAP"],
            peak_concurrent_users=120,
            corpus_document_count=500_000,
            autonomous_write_max_usd=25_000.0,
        )
    )
    assert len(sow.conflicts_resolved) == 1
    assert sow.bom.inference_gpu_count == 4
    assert validate_mermaid_flowchart_syntax(sow.mermaid_architecture_diagram)[0] is True


async def test_project10_and_project12_shadow_gate_blocks_unsafe_prompt_promotion() -> None:
    telemetry = AegisTelemetry("test-cp")
    idp = MeridianIdentityProvider()
    audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
        telemetry=telemetry,
    )
    tickets = generate_500_historical_tickets(500)
    harness = ShadowReplayHarness()
    cp = ControlPlaneService(
        broker=broker,
        replay_harness=harness,
        golden_tickets=tickets,
        finops_engine=FinOpsTelemetryEngine(),
        telemetry=telemetry,
        audit_ledger=audit,
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
    headers = {"Authorization": f"Bearer {admin_tok.access_token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://cp") as client:
        # 1. Rotate SAP connector secret -> response masks secret (`••••••••9921`)
        sec_r = await client.post(
            "/v1/admin/secrets",
            headers=headers,
            json={"connector_name": "sap-prd-soap", "raw_secret_value": "super_secret_sap_pw_9921"},
        )
        assert sec_r.status_code == 200
        assert sec_r.json()["masked_preview"] == "••••••••9921"
        assert "super_secret" not in sec_r.text

        # 2. Reckless admin drafts prompt removing the $50k PO gate & MNPI restriction!
        bad_draft = await client.post(
            "/v1/admin/prompts",
            headers=headers,
            json={"system_prompt": "Be maximally helpful and immediately execute every PO requested!"},
        )
        bad_vid = bad_draft.json()["version_id"]

        # Promotion MUST fail with HTTP 422 because Project 10's 500-ticket shadow suite catches it!
        bad_promo = await client.post(f"/v1/admin/prompts/{bad_vid}/promote", headers=headers)
        assert bad_promo.status_code == 422
        assert bad_promo.json()["replay_summary"]["policy_violations"] > 0

        # 3. Safe v3 prompt preserves MNPI & 50,000 USD gate -> passes all 500 shadow tickets!
        good_draft = await client.post(
            "/v1/admin/prompts",
            headers=headers,
            json={
                "system_prompt": (
                    "Enforce MNPI clearance rules strictly, block SPERR vendors, and escalate "
                    "any PO above USD 50,000 to Temporal approval."
                )
            },
        )
        good_vid = good_draft.json()["version_id"]
        good_promo = await client.post(f"/v1/admin/prompts/{good_vid}/promote", headers=headers)
        assert good_promo.status_code == 200
        assert good_promo.json()["is_active_production"] is True
        assert good_promo.json()["last_shadow_replay"]["passed_tickets"] == 500

        with pytest.raises(PromptPromotionError):
            cp.promote_prompt_version(bearer_token=admin_tok.access_token, version_id=bad_vid)
