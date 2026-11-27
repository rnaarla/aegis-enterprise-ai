"""OpenAI-compatible HTTP & SSE PII Proxy with Feistel FPE, Aho-Corasick & Exfiltration Firewall."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Iterator
from typing import Any, Protocol

import anyio
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis_core.crypto import TokenVerificationError
from aegis_core.http_middleware import (
    MissingBearerTokenError,
    extract_bearer_token,
    install_aegis_http_layer,
)
from aegis_core.models import AuditEventType
from aegis_core.ports import AuditLedgerPort
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry
from pii_unmasking_proxy.fpe_and_automaton import (
    AhoCorasickEntityMatcher,
    FeistelNumericFPE,
    PIIExfiltrationBlockedError,
    assert_no_surrogate_exfiltration,
)
from pii_unmasking_proxy.sse_stream import StreamingSurrogateRehydrator, mask_text_entities
from pii_unmasking_proxy.vault import EnvelopeEncryptedPIIVault
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker

_STREAM_END = object()


class UpstreamChatBackendPort(Protocol):
    """Port for upstream LLM receiving ONLY surrogate-masked payloads."""

    def complete(self, masked_messages: list[dict[str, str]], model: str) -> str:
        ...

    def stream_complete(self, masked_messages: list[dict[str, str]], model: str) -> Iterator[str]:
        ...


class ChatMessage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    role: str
    content: str


class ToolCallFunctionSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    arguments_json: str


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str = "gpt-5-enterprise"
    session_id: str = Field(min_length=3, max_length=128)
    messages: list[ChatMessage] = Field(min_length=1)
    stream: bool = False
    format_preserving_fpe: bool = False
    tool_calls_to_rehydrate: list[ToolCallFunctionSpec] = Field(default_factory=list)


class DeterministicPIIProxy:
    """Swaps PII/PCI/Codenames pre-LLM (AES-GCM surrogates or Feistel FPE) & guards exfiltration."""

    def __init__(
        self,
        *,
        broker: SSODelegationBroker,
        vault: EnvelopeEncryptedPIIVault,
        upstream_llm: UpstreamChatBackendPort,
        audit_ledger: AuditLedgerPort,
        custom_entity_dictionary: dict[str, str] | None = None,
        fpe_master_key: bytes | None = None,
        allowlisted_rehydrate_tools: set[str] | None = None,
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self._broker = broker
        self._vault = vault
        self._llm = upstream_llm
        self._audit = audit_ledger
        self._automaton = AhoCorasickEntityMatcher(custom_entity_dictionary or {})
        self._fpe = FeistelNumericFPE(fpe_master_key or os.urandom(32))
        self._allowlisted_tools = allowlisted_rehydrate_tools or {
            "sap_create_purchase_order",
            "sap_get_vendor_status",
            "wire_transfer_lookup",
        }
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY

    def _mask_single_text(
        self,
        text: str,
        *,
        session_id: str,
        use_fpe: bool,
    ) -> tuple[str, list[str]]:
        tags: list[str] = []
        # 1. Single-pass O(L + Z) Aho-Corasick scan for 10,000+ custom deal/client codenames
        ac_hits = self._automaton.find_non_overlapping(text)
        if ac_hits:
            pieces: list[str] = []
            cur = 0
            for start, end, etype in ac_hits:
                pieces.append(text[cur:start])
                tag = self._vault.mask_entity(
                    session_id=session_id, entity_type=etype, raw_value=text[start:end]
                )
                tags.append(tag)
                pieces.append(tag)
                cur = end
            pieces.append(text[cur:])
            text = "".join(pieces)

        # 2. Single-pass O(L) regex + Luhn/IRS check with optional Feistel FPE for 16-digit PANs
        def _mask_cb(etype: str, raw_val: str) -> str:
            if use_fpe and etype == "CC":
                digits = "".join(c for c in raw_val if c.isdigit())
                if len(digits) == 16:
                    fpe_pan = self._fpe.mask_credit_card_luhn_preserving(
                        digits, session_id=session_id
                    )
                    self._sli.inc_counter("aegis_pii_fpe_operations_total", 1.0)
                    return fpe_pan
            return self._vault.mask_entity(
                session_id=session_id, entity_type=etype, raw_value=raw_val
            )

        masked, regex_tags = mask_text_entities(text, _mask_cb)
        tags.extend(regex_tags)
        return masked, tags

    def mask_messages(
        self,
        *,
        session_id: str,
        messages: list[ChatMessage],
        tenant_id: str,
        human_subject: str,
        actor_id: str,
        jti: str,
        use_fpe: bool = False,
    ) -> tuple[list[dict[str, str]], list[str]]:
        masked_msgs: list[dict[str, str]] = []
        all_tags: list[str] = []

        for msg in messages:
            masked_content, tags = self._mask_single_text(
                msg.content, session_id=session_id, use_fpe=use_fpe
            )
            masked_msgs.append({"role": msg.role, "content": masked_content})
            all_tags.extend(tags)

        self._audit.append(
            tenant_id=tenant_id,
            event_type=AuditEventType.PII_MASKED,
            human_subject=human_subject,
            actor_id=actor_id,
            jti=jti,
            decision="ALLOW",
            detail={
                "session_id": session_id,
                "masked_surrogate_count": len(all_tags),
                "surrogate_tags": sorted(set(all_tags)),
                "fpe_enabled": use_fpe,
            },
        )
        return masked_msgs, all_tags

    def rehydrate_tool_call_arguments(
        self,
        *,
        session_id: str,
        tool_call: ToolCallFunctionSpec,
    ) -> dict[str, Any]:
        """Deterministically rehydrate `<IBAN_001>` inside JSON `tool_calls` ONLY for trusted tools."""
        if tool_call.name not in self._allowlisted_tools:
            raise PIIExfiltrationBlockedError(
                f"Tool {tool_call.name!r} is not allowlisted to receive rehydrated PII arguments"
            )
        rehydrator = StreamingSurrogateRehydrator(
            lambda tag: self._vault.unmask_tag(session_id=session_id, surrogate_tag=tag)
        )
        rehydrated_json = rehydrator.feed(tool_call.arguments_json) + rehydrator.flush()
        parsed: dict[str, Any] = json.loads(rehydrated_json)
        return parsed

    def complete_sync(
        self,
        *,
        bearer_token: str,
        req: ChatCompletionRequest,
    ) -> dict[str, Any]:
        claims = self._broker.verify_and_check_revocation(bearer_token, required_scope="rag:read")
        masked_msgs, masked_tags = self.mask_messages(
            session_id=req.session_id,
            messages=req.messages,
            tenant_id=claims.tenant_id,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
            use_fpe=req.format_preserving_fpe,
        )
        raw_llm_output = self._llm.complete(masked_msgs, req.model)
        try:
            assert_no_surrogate_exfiltration(raw_llm_output, masked_tags)
        except PIIExfiltrationBlockedError as exc:
            self._sli.inc_counter("aegis_pii_exfiltration_blocks_total", 1.0)
            self._audit.append(
                tenant_id=claims.tenant_id,
                event_type=AuditEventType.PII_EXFILTRATION_BLOCKED,
                human_subject=claims.sub,
                actor_id=claims.act.sub,
                jti=claims.jti,
                decision="DENY",
                detail={"session_id": req.session_id, "reason": str(exc)},
            )
            raise

        rehydrator = StreamingSurrogateRehydrator(
            lambda tag: self._vault.unmask_tag(session_id=req.session_id, surrogate_tag=tag)
        )
        restored_output = rehydrator.feed(raw_llm_output) + rehydrator.flush()

        rehydrated_tools = [
            {
                "name": tc.name,
                "arguments": self.rehydrate_tool_call_arguments(
                    session_id=req.session_id, tool_call=tc
                ),
            }
            for tc in req.tool_calls_to_rehydrate
        ]

        audit_rec = self._audit.append(
            tenant_id=claims.tenant_id,
            event_type=AuditEventType.PII_UNMASKED,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
            decision="ALLOW",
            detail={
                "session_id": req.session_id,
                "restored_count": len(rehydrator.unmasked_tags),
                "restored_tags": sorted(set(rehydrator.unmasked_tags)),
            },
        )
        resp: dict[str, Any] = {
            "id": f"chatcmpl-{claims.jti[:12]}",
            "object": "chat.completion",
            "model": req.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": restored_output},
                    "finish_reason": "stop",
                }
            ],
            "aegis_pii_receipt": {
                "masked_pre_inference": sorted(set(masked_tags)),
                "restored_post_inference": sorted(set(rehydrator.unmasked_tags)),
                "rehydrated_tool_calls": rehydrated_tools,
                "audit_entry_hash": audit_rec.entry_hash,
            },
        }
        return resp

    def stream_sse(
        self,
        *,
        bearer_token: str,
        req: ChatCompletionRequest,
    ) -> Iterator[str]:
        claims = self._broker.verify_and_check_revocation(bearer_token, required_scope="rag:read")
        masked_msgs, masked_tags = self.mask_messages(
            session_id=req.session_id,
            messages=req.messages,
            tenant_id=claims.tenant_id,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
            use_fpe=req.format_preserving_fpe,
        )
        rehydrator = StreamingSurrogateRehydrator(
            lambda tag: self._vault.unmask_tag(session_id=req.session_id, surrogate_tag=tag)
        )
        rolling_window = ""

        for token_delta in self._llm.stream_complete(masked_msgs, req.model):
            rolling_window = (rolling_window + token_delta)[-256:]
            assert_no_surrogate_exfiltration(rolling_window, masked_tags)
            ready_text = rehydrator.feed(token_delta)
            if ready_text:
                frame = {
                    "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {"content": ready_text}}],
                }
                yield f"data: {json.dumps(frame)}\n\n"

        tail = rehydrator.flush()
        if tail:
            frame = {
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": tail}}],
            }
            yield f"data: {json.dumps(frame)}\n\n"

        self._audit.append(
            tenant_id=claims.tenant_id,
            event_type=AuditEventType.PII_UNMASKED,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
            decision="ALLOW",
            detail={
                "session_id": req.session_id,
                "streaming": True,
                "restored_count": len(rehydrator.unmasked_tags),
                "restored_tags": sorted(set(rehydrator.unmasked_tags)),
            },
        )
        yield "data: [DONE]\n\n"


def create_pii_proxy_app(proxy: DeterministicPIIProxy) -> FastAPI:
    """Non-blocking FastAPI `/v1/chat/completions` with SRE SLIs & exfiltration enforcement."""
    app = FastAPI(title="Aegis Deterministic PII Unmasking Proxy", version="0.3.0")
    install_aegis_http_layer(app, service_name="pii-unmasking-proxy")

    @app.post("/v1/chat/completions", response_model=None)
    async def chat_completions(
        req: ChatCompletionRequest,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse | StreamingResponse:
        try:
            token = extract_bearer_token(authorization)
        except MissingBearerTokenError:
            return JSONResponse(status_code=401, content={"error": "missing_bearer_token"})

        try:
            if not req.stream:
                result = await anyio.to_thread.run_sync(
                    lambda: proxy.complete_sync(bearer_token=token, req=req)
                )
                return JSONResponse(status_code=200, content=result)

            sync_iter = proxy.stream_sse(bearer_token=token, req=req)
            first_frame = await anyio.to_thread.run_sync(lambda: next(sync_iter, _STREAM_END))

            async def _non_blocking_sse() -> AsyncIterator[str]:
                if first_frame is not _STREAM_END:
                    yield str(first_frame)
                while True:
                    nxt = await anyio.to_thread.run_sync(lambda: next(sync_iter, _STREAM_END))
                    if nxt is _STREAM_END:
                        break
                    yield str(nxt)

            return StreamingResponse(_non_blocking_sse(), media_type="text/event-stream")
        except PIIExfiltrationBlockedError as exc:
            return JSONResponse(
                status_code=422,
                content={"error": "pii_exfiltration_blocked", "detail": str(exc)},
            )
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})

    return app
