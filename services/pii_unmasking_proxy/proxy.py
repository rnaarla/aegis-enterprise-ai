"""OpenAI-compatible non-blocking HTTP & Streaming SSE PII Reverse Proxy."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any, Protocol

import anyio
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis_core.crypto import TokenVerificationError
from aegis_core.models import AuditEventType
from aegis_core.ports import AuditLedgerPort
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


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str = "gpt-5-enterprise"
    session_id: str = Field(min_length=3, max_length=128)
    messages: list[ChatMessage] = Field(min_length=1)
    stream: bool = False


class DeterministicPIIProxy:
    """Swaps PII/PCI for typed AES-GCM vault surrogates pre-LLM and restores post-generation."""

    def __init__(
        self,
        *,
        broker: SSODelegationBroker,
        vault: EnvelopeEncryptedPIIVault,
        upstream_llm: UpstreamChatBackendPort,
        audit_ledger: AuditLedgerPort,
    ) -> None:
        self._broker = broker
        self._vault = vault
        self._llm = upstream_llm
        self._audit = audit_ledger

    def mask_messages(
        self,
        *,
        session_id: str,
        messages: list[ChatMessage],
        tenant_id: str,
        human_subject: str,
        actor_id: str,
        jti: str,
    ) -> tuple[list[dict[str, str]], list[str]]:
        masked_msgs: list[dict[str, str]] = []
        all_tags: list[str] = []

        for msg in messages:
            masked_content, tags = mask_text_entities(
                msg.content,
                lambda etype, val: self._vault.mask_entity(
                    session_id=session_id, entity_type=etype, raw_value=val
                ),
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
            },
        )
        return masked_msgs, all_tags

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
        )
        raw_llm_output = self._llm.complete(masked_msgs, req.model)
        rehydrator = StreamingSurrogateRehydrator(
            lambda tag: self._vault.unmask_tag(session_id=req.session_id, surrogate_tag=tag)
        )
        restored_output = rehydrator.feed(raw_llm_output) + rehydrator.flush()

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
        return {
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
                "audit_entry_hash": audit_rec.entry_hash,
            },
        }

    def stream_sse(
        self,
        *,
        bearer_token: str,
        req: ChatCompletionRequest,
    ) -> Iterator[str]:
        claims = self._broker.verify_and_check_revocation(bearer_token, required_scope="rag:read")
        masked_msgs, _ = self.mask_messages(
            session_id=req.session_id,
            messages=req.messages,
            tenant_id=claims.tenant_id,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
        )
        rehydrator = StreamingSurrogateRehydrator(
            lambda tag: self._vault.unmask_tag(session_id=req.session_id, surrogate_tag=tag)
        )

        for token_delta in self._llm.stream_complete(masked_msgs, req.model):
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
    """Non-blocking FastAPI `/v1/chat/completions` offloading sync I/O via `anyio.to_thread`."""
    app = FastAPI(title="Aegis Deterministic PII Unmasking Proxy", version="0.2.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "pii-unmasking-proxy"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        return {"status": "ready", "service": "pii-unmasking-proxy"}

    @app.post("/v1/chat/completions", response_model=None)
    async def chat_completions(
        req: ChatCompletionRequest,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse | StreamingResponse:
        if not authorization or not authorization.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"error": "missing_bearer_token"})
        token = authorization.removeprefix("Bearer ").strip()

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
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})

    return app
