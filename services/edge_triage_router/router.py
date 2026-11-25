"""Single-GPU AWQ 4-bit 8B Triage Node with fail-closed KV-cache backpressure.

Critical CISO Guarantee: If the local customer-owned GPU KV-cache reaches saturation,
this router FAILS CLOSED (`503 EdgeTriageOverloadError`) rather than failing open and
accidentally forwarding unscreened MNPI/PII payloads to an external cloud LLM endpoint.
"""

from __future__ import annotations

import re
import threading
import time
from enum import StrEnum
from typing import Any, Literal, Protocol

import httpx
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis_core.crypto import TokenVerificationError
from aegis_core.http_middleware import (
    MissingBearerTokenError,
    extract_bearer_token,
    install_aegis_http_layer,
)
from aegis_core.models import AuditEventType
from aegis_core.ports import AuditLedgerPort
from aegis_core.resilience import (
    CircuitBreaker,
    TransientDependencyError,
    execute_with_full_jitter_retry,
)
from pii_unmasking_proxy.sse_stream import mask_text_entities
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker


class DataTemperature(StrEnum):
    """Data gravity & compliance temperature determined on customer-owned GPU."""

    HOT_MNPI_ONPREM_ONLY = "HOT_MNPI_ONPREM_ONLY"
    WARM_PII_MASK_REQUIRED = "WARM_PII_MASK_REQUIRED"
    COLD_PUBLIC_CLOUD_SAFE = "COLD_PUBLIC_CLOUD_SAFE"


class TriageClassification(BaseModel):
    """Guided-JSON schema (<48 tokens) emitted by local `vLLM` AWQ 8B model via `xgrammar`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    temperature: DataTemperature
    detected_signals: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    local_triage_summary: str = Field(max_length=240)


class TriageRoutingResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    route_target: Literal[
        "LOCAL_AWQ_8B_ENCLAVE",
        "PII_MASKING_PROXY_TO_CLOUD",
        "DIRECT_FRONTIER_CLOUD",
    ]
    classification: TriageClassification
    egress_permitted: bool
    triage_latency_ms: float
    kv_cache_utilization_pct: float
    audit_entry_hash: str


class LocalTriageModelPort(Protocol):
    """Port for local single-GPU quantized classifier (`vLLM` AWQ 8B or offline deterministic)."""

    def classify_prompt(self, prompt: str) -> TriageClassification:
        ...


class EdgeTriageOverloadError(Exception):
    """Raised when local GPU KV-cache capacity is exhausted (fail-closed backpressure)."""


_MNPI_KEYWORDS = (
    "project chronos",
    "helios semiconductor",
    "breakup fee",
    "fairness opinion",
    "nostro",
    "fedwire",
    "acctldgr",
    "divestiture cap",
    "mnpi",
)
# Single compiled multi-pattern alternation DFA scanning prompt in one O(L) pass
_MNPI_COMPILED_RE = re.compile("|".join(re.escape(kw) for kw in _MNPI_KEYWORDS), re.IGNORECASE)


class DeterministicOnPremClassifierAdapter:
    """Zero-egress deterministic sensitivity classifier matching `vLLM` guided-JSON schema."""

    def classify_prompt(self, prompt: str) -> TriageClassification:
        mnpi_hits = sorted({m.group(0).lower() for m in _MNPI_COMPILED_RE.finditer(prompt)})
        _, pii_tags = mask_text_entities(prompt, lambda etype, _val: f"<{etype}_001>")

        if mnpi_hits:
            return TriageClassification(
                temperature=DataTemperature.HOT_MNPI_ONPREM_ONLY,
                detected_signals=[f"mnpi:{kw}" for kw in mnpi_hits] + pii_tags,
                confidence=0.99,
                local_triage_summary="Contains regulated M&A / Core-Banking MNPI; cloud egress prohibited.",
            )
        if pii_tags:
            return TriageClassification(
                temperature=DataTemperature.WARM_PII_MASK_REQUIRED,
                detected_signals=sorted(set(pii_tags)),
                confidence=0.97,
                local_triage_summary="Contains regulated PII/PCI; route strictly via Deterministic PII Proxy.",
            )
        return TriageClassification(
            temperature=DataTemperature.COLD_PUBLIC_CLOUD_SAFE,
            detected_signals=[],
            confidence=0.95,
            local_triage_summary="No MNPI or PII detected; safe for frontier cloud inference.",
        )


class VLLMGuidedJSONClassifierAdapter:
    """Circuit-broken + jitter-retried HTTP adapter for single-GPU `vLLM` AWQ 8B."""

    def __init__(
        self,
        *,
        vllm_base_url: str = "http://127.0.0.1:8000/v1",
        model_name: str = "Qwen/Qwen2.5-8B-Instruct-AWQ",
        timeout_seconds: float = 1.5,
        transport: httpx.BaseTransport | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        max_attempts: int = 2,
    ) -> None:
        self._url = vllm_base_url.rstrip("/")
        self._model = model_name
        self._timeout = timeout_seconds
        self._transport = transport
        self._breaker = circuit_breaker or CircuitBreaker("vllm-edge-triage", failure_threshold=4)
        self._max_attempts = max_attempts

    def classify_prompt(self, prompt: str) -> TriageClassification:
        payload: dict[str, Any] = {
            "model": self._model,
            "temperature": 0.0,
            "max_tokens": 64,
            "messages": [
                {
                    "role": "system",
                    "content": "Classify enterprise prompt sensitivity into strict JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            "guided_json": TriageClassification.model_json_schema(),
        }

        def _call_vllm() -> str:
            try:
                with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                    resp = client.post(f"{self._url}/chat/completions", json=payload)
            except httpx.TransportError as exc:
                raise TransientDependencyError(f"vLLM transport error: {exc}") from exc
            if resp.status_code in (502, 503, 504):
                raise TransientDependencyError(f"vLLM HTTP {resp.status_code}")
            resp.raise_for_status()
            return str(resp.json()["choices"][0]["message"]["content"])

        content = self._breaker.call(
            lambda: execute_with_full_jitter_retry(_call_vllm, max_attempts=self._max_attempts)
        )
        return TriageClassification.model_validate_json(content)


class LocalQuantizedTriageRouter:
    """Customer-premises GPU triage gateway enforcing fail-closed KV-cache admission control."""

    def __init__(
        self,
        *,
        broker: SSODelegationBroker,
        classifier: LocalTriageModelPort,
        audit_ledger: AuditLedgerPort,
        max_kv_cache_tokens: int = 32_768,
    ) -> None:
        self._broker = broker
        self._classifier = classifier
        self._audit = audit_ledger
        self._max_kv_tokens = max_kv_cache_tokens
        self._lock = threading.Lock()
        self._inflight_kv_tokens = 0

    def simulate_gpu_kv_load(self, reserved_tokens: int) -> None:
        """Allow tests to saturate simulated GPU KV-cache to verify fail-closed shedding."""
        with self._lock:
            self._inflight_kv_tokens = max(0, reserved_tokens)

    def evaluate_and_route(
        self,
        *,
        bearer_token: str,
        prompt: str,
    ) -> TriageRoutingResult:
        t0 = time.perf_counter()
        claims = self._broker.verify_and_check_revocation(bearer_token, required_scope="rag:read")

        estimated_tokens = max(64, len(prompt) // 3 + 64)
        with self._lock:
            if self._inflight_kv_tokens + estimated_tokens > self._max_kv_tokens:
                self._audit.append(
                    tenant_id=claims.tenant_id,
                    event_type=AuditEventType.EDGE_TRIAGE_ROUTED,
                    human_subject=claims.sub,
                    actor_id=claims.act.sub,
                    jti=claims.jti,
                    decision="DENY",
                    detail={
                        "reason": "gpu_kv_cache_exhausted_fail_closed",
                        "inflight_kv_tokens": self._inflight_kv_tokens,
                        "max_kv_tokens": self._max_kv_tokens,
                    },
                )
                raise EdgeTriageOverloadError(
                    "Local AWQ 8B GPU KV-cache saturated; failing closed (zero unscreened cloud egress)"
                )
            self._inflight_kv_tokens += estimated_tokens
            kv_pct = round((self._inflight_kv_tokens / self._max_kv_tokens) * 100.0, 2)

        try:
            classification = self._classifier.classify_prompt(prompt)
        finally:
            with self._lock:
                self._inflight_kv_tokens = max(0, self._inflight_kv_tokens - estimated_tokens)

        if classification.temperature == DataTemperature.HOT_MNPI_ONPREM_ONLY:
            target: Literal[
                "LOCAL_AWQ_8B_ENCLAVE",
                "PII_MASKING_PROXY_TO_CLOUD",
                "DIRECT_FRONTIER_CLOUD",
            ] = "LOCAL_AWQ_8B_ENCLAVE"
            egress = False
        elif classification.temperature == DataTemperature.WARM_PII_MASK_REQUIRED:
            target = "PII_MASKING_PROXY_TO_CLOUD"
            egress = True
        else:
            target = "DIRECT_FRONTIER_CLOUD"
            egress = True

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        audit_rec = self._audit.append(
            tenant_id=claims.tenant_id,
            event_type=AuditEventType.EDGE_TRIAGE_ROUTED,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
            decision="ALLOW",
            detail={
                "temperature": classification.temperature.value,
                "route_target": target,
                "egress_permitted": egress,
                "latency_ms": elapsed_ms,
            },
        )
        return TriageRoutingResult(
            route_target=target,
            classification=classification,
            egress_permitted=egress,
            triage_latency_ms=elapsed_ms,
            kv_cache_utilization_pct=kv_pct,
            audit_entry_hash=audit_rec.entry_hash,
        )


class TriageRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    prompt: str = Field(min_length=1, max_length=16_000)


def create_edge_triage_app(router: LocalQuantizedTriageRouter) -> FastAPI:
    app = FastAPI(title="Aegis Local Quantized AWQ 8B Triage Node", version="0.2.0")
    install_aegis_http_layer(app, service_name="edge-triage-router")

    @app.post("/v1/triage", response_model=TriageRoutingResult)
    def triage(
        req: TriageRequest,
        authorization: str | None = Header(default=None),
    ) -> TriageRoutingResult | JSONResponse:
        try:
            token = extract_bearer_token(authorization)
            return router.evaluate_and_route(bearer_token=token, prompt=req.prompt)
        except MissingBearerTokenError as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})
        except EdgeTriageOverloadError as exc:
            return JSONResponse(
                status_code=503, content={"error": "gpu_overload", "detail": str(exc)}
            )
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})

    return app
