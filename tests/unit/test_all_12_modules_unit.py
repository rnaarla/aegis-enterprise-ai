"""Tier 1 Unit Test Suite: Exhaustive isolated unit tests across all 12 Aegis modules."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

import httpx
import jwt
import pytest
from enterprise_twin.corpus_seed.historical_tickets import generate_500_historical_tickets
from enterprise_twin.soap_erp_mock.sap_soap_server import LegacySAPSoapTwin

from aegis_core.audit import InMemoryAuditLedger
from aegis_core.crypto import JWKSVerifier, SigningKeyPair, TokenVerificationError
from aegis_core.models import ClearanceLevel, DocumentClassification
from aegis_core.telemetry import AegisTelemetry
from arch_scoper.scoper import (
    ArchitectureScoperEngine,
    ScopeDiscoveryIntake,
    validate_mermaid_flowchart_syntax,
)
from edge_triage_router.router import (
    DataTemperature,
    DeterministicOnPremClassifierAdapter,
    TriageClassification,
    VLLMGuidedJSONClassifierAdapter,
)
from finops_telemetry.engine import FinOpsTelemetryEngine, GenAITelemetryEvent
from legacy_ingestor.cobol_ebcdic import (
    decode_comp3,
    encode_comp3,
    parse_ebcdic_copybook_stream,
)
from mcp_erp_bridge.bridge import HttpSOAPTransport
from pii_unmasking_proxy.sse_stream import StreamingSurrogateRehydrator, passes_luhn_checksum
from pii_unmasking_proxy.vault import EnvelopeEncryptedPIIVault
from secure_rag_engine.embeddings import (
    DeterministicFinancialEmbedder,
    OpenAICompatibleEmbeddingAdapter,
)
from shadow_replay_harness.harness import (
    PolicyGuidedShadowAgent,
)
from sso_delegation_broker.revocation import InMemoryRevocationStore, RedisRevocationStore
from temporal_approval_gate.gate import (
    SlackWebhookVerificationError,
    sign_slack_webhook_payload,
    verify_slack_webhook_signature,
)

pytestmark = pytest.mark.unit


class _FakeRedisPipeline:
    def __init__(self, store: _FakeRedisClient) -> None:
        self._store = store
        self._ops: list[tuple[str, tuple[Any, ...]]] = []

    def setex(self, key: str, ttl: int, val: str) -> _FakeRedisPipeline:
        self._ops.append(("setex", (key, ttl, val)))
        return self

    def sadd(self, key: str, member: str) -> _FakeRedisPipeline:
        self._ops.append(("sadd", (key, member)))
        return self

    def expire(self, key: str, ttl: int) -> _FakeRedisPipeline:
        self._ops.append(("expire", (key, ttl)))
        return self

    def get(self, key: str) -> _FakeRedisPipeline:
        self._ops.append(("get", (key,)))
        return self

    def execute(self) -> list[Any]:
        results: list[Any] = []
        for op, args in self._ops:
            if op == "setex":
                self._store.setex(args[0], args[1], args[2])
                results.append(True)
            elif op == "sadd":
                self._store.sets.setdefault(args[0], set()).add(args[1].encode("utf-8"))
                results.append(1)
            elif op == "expire":
                results.append(True)
            elif op == "get":
                results.append(self._store.kv.get(args[0]))
        self._ops.clear()
        return results


class _FakeRedisClient:
    """Wire-compatible in-memory Redis mock storing raw UTF-8 `bytes` like redis-py."""

    def __init__(self) -> None:
        self.kv: dict[str, bytes] = {}
        self.sets: dict[str, set[bytes]] = {}

    def pipeline(self) -> _FakeRedisPipeline:
        return _FakeRedisPipeline(self)

    def setex(self, key: str, _ttl: int, val: str) -> None:
        self.kv[key] = val.encode("utf-8")

    def smembers(self, key: str) -> set[bytes]:
        return set(self.sets.get(key, set()))


def test_unit_core_crypto_edge_cases_and_telemetry() -> None:
    key = SigningKeyPair.generate_es256()
    verifier = JWKSVerifier(
        issuer="https://iss",
        expected_audience="aud-1",
        jwks={"keys": [key.public_jwk]},
    )

    with pytest.raises(ValueError, match="must be a list"):
        verifier.reload_jwks({"keys": "bad"})

    with pytest.raises(TokenVerificationError, match="Malformed JWT"):
        verifier.verify_delegated_jwt("not-a-jwt")

    wrong_typ = jwt.encode(
        {
            "iss": "https://iss",
            "sub": "u",
            "aud": "aud-1",
            "exp": 200,
            "iat": 100,
            "nbf": 100,
            "jti": "1",
            "act": {"sub": "a", "client_id": "c"},
        },
        key.private_pem,
        algorithm="ES256",
        headers={"kid": key.kid, "typ": "JWT"},
    )
    with pytest.raises(TokenVerificationError, match="at\\+jwt"):
        verifier.verify_delegated_jwt(wrong_typ, now_epoch=120)

    unknown_kid = jwt.encode(
        {"iss": "https://iss"},
        key.private_pem,
        algorithm="ES256",
        headers={"kid": "missing-kid", "typ": "at+jwt"},
    )
    with pytest.raises(TokenVerificationError, match="Unknown signing key"):
        verifier.verify_delegated_jwt(unknown_kid)

    tel = AegisTelemetry("unit-svc")
    with tel.span("unit.op", {"k": "v"}):
        pass
    assert len(tel.finished_spans()) == 1
    tel.clear_spans()
    assert len(tel.finished_spans()) == 0
    tel.collector.shutdown()

    assert DocumentClassification.TOP_SECRET_MA.to_clearance() == ClearanceLevel.TOP_SECRET_MA


def test_unit_p1_inmemory_and_redis_revocation_cascades() -> None:
    # 1. InMemory subject-wide cascade + pruning
    mem = InMemoryRevocationStore()
    mem.register_issued_token("jti-live", "elena.vance", "agent-a", exp_epoch=9_999_999_999)
    mem.register_issued_token("jti-expired", "elena.vance", "agent-a", exp_epoch=100)
    count = mem.revoke_all_for_subject("elena.vance", "idp_backchannel_logout")
    assert count == 1
    rev, reason = mem.is_revoked("jti-live", "elena.vance", "agent-a")
    assert rev is True and reason == "subject_revoked:idp_backchannel_logout"

    # 2. RedisRevocationStore full lifecycle (JTI, subject cascade, agent killswitch)
    fake_redis = _FakeRedisClient()
    r_store = RedisRevocationStore(fake_redis)
    r_store.register_issued_token("jti-r1", "priya.nair", "proc-bot", exp_epoch=9_999_999_999)
    r_store.register_issued_token("jti-r2", "marcus.chen", "proc-bot", exp_epoch=9_999_999_999)
    assert r_store.is_revoked("jti-r1", "priya.nair", "proc-bot") == (False, None)

    r_store.revoke_jti("jti-r1", 9_999_999_999, "manual_jti")
    assert r_store.is_revoked("jti-r1", "other", "other") == (True, "jti_revoked:manual_jti")

    sub_cnt = r_store.revoke_all_for_subject("priya.nair", "hr_offboard")
    assert sub_cnt == 1
    assert r_store.is_revoked("other", "priya.nair", "other") == (
        True,
        "subject_revoked:hr_offboard",
    )

    ag_cnt = r_store.revoke_all_for_agent("proc-bot", "emergency_stop")
    assert ag_cnt == 2
    assert r_store.is_revoked("any", "any", "proc-bot") == (
        True,
        "agent_killswitch:emergency_stop",
    )


def test_unit_p3_cobol_comp3_overflow_and_corrupt_nibble_guards() -> None:
    with pytest.raises(ValueError, match="overflows COMP-3"):
        encode_comp3(Decimal("999999999"), byte_length=3, scale=0)

    with pytest.raises(ValueError, match="Empty COMP-3"):
        decode_comp3(b"")

    with pytest.raises(ValueError, match="Invalid BCD digit"):
        decode_comp3(b"\xaa\x1c")

    with pytest.raises(ValueError, match="Invalid COMP-3 sign nibble"):
        decode_comp3(b"\x12\x30")

    with pytest.raises(ValueError, match="not a multiple"):
        parse_ebcdic_copybook_stream(b"short")


def test_unit_p4_and_p8_and_p5_http_client_adapters_via_mock_transport() -> None:
    # 1. OpenAICompatibleEmbeddingAdapter (P4)
    def _emb_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "bge-m3"
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0.0, 1.0, 0.0, 0.0]},
                    {"index": 0, "embedding": [1.0, 0.0, 0.0, 0.0]},
                ]
            },
        )

    emb_adapter = OpenAICompatibleEmbeddingAdapter(
        base_url="http://vllm.internal/v1",
        api_key="local-key",
        model="bge-m3",
        dim=4,
        transport=httpx.MockTransport(_emb_handler),
    )
    assert emb_adapter.dimension == 4
    vecs = emb_adapter.embed_texts(["first", "second"])
    assert vecs == [[1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0]]

    det = DeterministicFinancialEmbedder(dim=32)
    assert det.dimension == 32
    assert det.embed_texts([""])[0][0] == 1.0

    # 2. VLLMGuidedJSONClassifierAdapter (P8)
    def _vllm_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert "guided_json" in body
        cls_json = TriageClassification(
            temperature=DataTemperature.HOT_MNPI_ONPREM_ONLY,
            detected_signals=["mnpi:chronos"],
            confidence=0.98,
            local_triage_summary="Local GPU blocked egress",
        ).model_dump_json()
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": cls_json}}]},
        )

    vllm_cls = VLLMGuidedJSONClassifierAdapter(
        vllm_base_url="http://gpu-node:8000/v1",
        transport=httpx.MockTransport(_vllm_handler),
    )
    res = vllm_cls.classify_prompt("Project Chronos")
    assert res.temperature == DataTemperature.HOT_MNPI_ONPREM_ONLY

    #Cold public path in deterministic classifier
    cold = DeterministicOnPremClassifierAdapter().classify_prompt(
        "What are standard GAAP depreciation rules for server hardware?"
    )
    assert cold.temperature == DataTemperature.COLD_PUBLIC_CLOUD_SAFE

    # 3. HttpSOAPTransport (P5)
    twin = LegacySAPSoapTwin()

    def _soap_handler(request: httpx.Request) -> httpx.Response:
        code, resp_xml = twin.handle_soap_envelope(request.content)
        return httpx.Response(code, content=resp_xml)

    soap_http = HttpSOAPTransport(
        "http://sap.internal/soap",
        transport=httpx.MockTransport(_soap_handler),
    )
    bad_status, _ = soap_http.post_envelope(b"<not-xml")
    assert bad_status == 400


def test_unit_p6_sse_buffer_non_tag_and_overflow_edge_cases() -> None:
    with pytest.raises(ValueError, match="256 bits"):
        EnvelopeEncryptedPIIVault(master_kek=b"short")

    assert passes_luhn_checksum("123") is False

    # Test `<` followed by math comparison `< 50000` (exceeding MAX_SURROGATE_TAG_LEN)
    # and nested `<` (`a < b <SSN_001>`)
    rehydrator = StreamingSurrogateRehydrator(
        lambda tag: "123-45-6789" if tag == "<SSN_001>" else None
    )
    out1 = rehydrator.feed("If amount < 50000 and x < ")
    out2 = rehydrator.feed("<SSN_001> or <UNKNOWN_999> and <HTML_TAG> trailing <inc")
    out3 = rehydrator.flush()
    combined = out1 + out2 + out3
    assert "123-45-6789" in combined
    assert "<UNKNOWN_999>" in combined
    assert combined.endswith("<inc")


def test_unit_p7_slack_hmac_timestamp_and_signature_errors() -> None:
    body = b'{"workflow_id":"wf-1"}'
    sig = sign_slack_webhook_payload(signing_secret="sec", timestamp=1_000_000, raw_body=body)
    verify_slack_webhook_signature(
        signing_secret="sec",
        timestamp_header="1000000",
        signature_header=sig,
        raw_body=body,
        now_epoch=1_000_100,
    )

    with pytest.raises(SlackWebhookVerificationError, match="Invalid X-Slack"):
        verify_slack_webhook_signature(
            signing_secret="sec",
            timestamp_header="not-an-int",
            signature_header=sig,
            raw_body=body,
        )

    with pytest.raises(SlackWebhookVerificationError, match="replay window"):
        verify_slack_webhook_signature(
            signing_secret="sec",
            timestamp_header="1000000",
            signature_header=sig,
            raw_body=body,
            now_epoch=1_000_500,
        )


def test_unit_p9_p10_p11_edge_cases() -> None:
    # P9 unknown model rate card error
    finops = FinOpsTelemetryEngine()
    with pytest.raises(KeyError, match="Missing pricing rate card"):
        finops.compute_event_cost_usd(
            GenAITelemetryEvent(
                event_id="ev-bad",
                trace_id="tr-bad",
                tenant_id="t1",
                cost_center="CC",
                workflow_type="wf",
                human_subject="u",
                actor_spiffe_id="spiffe://m/agent/a",
                model_id="unknown-model-xyz",
                uncached_input_tokens=100,
                outcome="VERIFIED_RESOLVED",
            )
        )

    # P10 temporal leakage detector triggers when contaminated snapshot is passed
    contaminated_tickets = generate_500_historical_tickets(4)
    agent = PolicyGuidedShadowAgent()
    leak_call = agent.decide_shadow_action(
        system_prompt="50,000 mnpi",
        requester_role="procurement_vp",
        user_message="cut PO",
        snapshot_at_t0={"existing_po_status": "ALREADY_CLOSED_PO_45001"},
    )
    assert leak_call.tool_name == "temporal_leak_detected"
    assert len(contaminated_tickets) == 4

    # P11 Mermaid validator + cloud non-airgap BOM branch
    assert validate_mermaid_flowchart_syntax("") == (
        False,
        "Diagram must open with 'flowchart <DIR>' or 'graph <DIR>'",
    )
    assert validate_mermaid_flowchart_syntax('flowchart LR\nA["bad<br/>html"]')[0] is False
    assert validate_mermaid_flowchart_syntax('flowchart LR\nA["unclosed')[0] is False

    cloud_sow = ArchitectureScoperEngine().generate_sow(
        ScopeDiscoveryIntake(
            client_name="Cloud Advisory Co",
            executive_objective="Deploy cloud RAG with local PII triage GPU.",
            compliance_regimes=["SOC2", "PCI_DSS"],
            air_gapped_vpc_required=False,
            requested_hosted_public_llm_api=True,
            legacy_sources=["SHAREPOINT"],
            peak_concurrent_users=100,
            corpus_document_count=10_000,
            autonomous_write_max_usd=0.0,
        )
    )
    assert len(cloud_sow.conflicts_resolved) == 0
    assert "Edge Triage" in cloud_sow.bom.inference_gpu_type
    assert InMemoryAuditLedger().verify_integrity()[0] is True
