"""FastAPI HTTP transport for Project 1: Enterprise SSO & Delegation Broker (Streamlined)."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis_core.http_middleware import install_aegis_http_layer
from aegis_core.models import AuthorizationDetail, TokenExchangeRequest, TokenExchangeResponse
from aegis_core.ports import AuditLedgerPort
from sso_delegation_broker.broker import SSODelegationBroker


class IntrospectRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    token: str = Field(min_length=16)


class SubdelegateRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    parent_agent_token: str = Field(min_length=16)
    target_subagent_id: str = Field(min_length=3, max_length=128)
    requested_scopes: list[str] = Field(min_length=1)
    requested_ttl_seconds: int = Field(default=120, ge=10, le=300)
    authorization_details: list[AuthorizationDetail] = Field(default_factory=list)
    dpop_jkt: str | None = None


class SSFEventRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    set_jwt: str = Field(min_length=16)


class RevokeRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: Literal["jti", "agent_killswitch"] = "jti"
    tenant_id: str = Field(min_length=2, max_length=64)
    jti: str | None = None
    human_subject: str = "system"
    agent_id: str = Field(min_length=2, max_length=128)
    reason: str = Field(default="security_policy_revocation", min_length=3, max_length=256)


def create_broker_app(broker: SSODelegationBroker, audit_ledger: AuditLedgerPort) -> FastAPI:
    """Create production FastAPI application for OIDC/SAML -> RFC 8693 Token Exchange."""
    app = FastAPI(
        title="Aegis Enterprise SSO & Agent Delegation Broker",
        version="0.3.0",
        docs_url="/docs",
    )
    install_aegis_http_layer(
        app,
        service_name="sso-delegation-broker",
        dependency_checks={"jwks_active": lambda: len(broker.public_jwks().get("keys", [])) >= 1},
    )

    @app.get("/.well-known/jwks.json")
    def jwks_endpoint() -> dict[str, Any]:
        return broker.public_jwks()

    @app.post("/v1/oauth/token", response_model=TokenExchangeResponse)
    def token_exchange(
        req: TokenExchangeRequest,
        request: Request,
        dpop: str | None = Header(default=None, alias="DPoP"),
    ) -> TokenExchangeResponse:
        return broker.exchange_token(
            req,
            dpop_proof_jwt=dpop,
            http_method=request.method,
            http_url=str(request.url),
        )

    @app.post("/v1/oauth/subdelegate", response_model=TokenExchangeResponse)
    def subdelegate(req: SubdelegateRequest) -> TokenExchangeResponse:
        return broker.exchange_agent_to_agent(
            parent_agent_token=req.parent_agent_token,
            target_subagent_id=req.target_subagent_id,
            requested_scopes=req.requested_scopes,
            requested_ttl_seconds=req.requested_ttl_seconds,
            authorization_details=req.authorization_details or None,
            dpop_jkt=req.dpop_jkt,
        )

    @app.post("/v1/ssf/events", response_model=None)
    def ingest_ssf_event(req: SSFEventRequest) -> dict[str, Any]:
        return broker.ingest_ssf_security_event(req.set_jwt)

    @app.post("/v1/keys/rotate")
    def rotate_keys(tenant_id: str = "meridian-fin") -> dict[str, Any]:
        new_kid = broker.rotate_signing_key(tenant_id=tenant_id)
        return {
            "status": "rotated",
            "active_kid": new_kid,
            "jwks_count": len(broker.public_jwks()["keys"]),
        }

    @app.post("/v1/oauth/introspect")
    def introspect(req: IntrospectRequest) -> dict[str, Any]:
        return broker.introspect_token(req.token)

    @app.post("/v1/oauth/revoke", response_model=None)
    def revoke(req: RevokeRequest) -> dict[str, Any] | JSONResponse:
        if req.mode == "agent_killswitch":
            count, entry_hash = broker.killswitch_agent(
                tenant_id=req.tenant_id,
                agent_id=req.agent_id,
                reason=req.reason,
            )
            return {"status": "revoked", "revoked_count": count, "audit_entry_hash": entry_hash}
        if not req.jti:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "jti required"},
            )
        entry_hash = broker.revoke_token_by_jti(
            jti=req.jti,
            tenant_id=req.tenant_id,
            human_subject=req.human_subject,
            actor_id=req.agent_id,
            reason=req.reason,
        )
        return {"status": "revoked", "jti": req.jti, "audit_entry_hash": entry_hash}

    @app.get("/v1/audit/verify")
    def verify_audit() -> dict[str, Any]:
        valid, message = audit_ledger.verify_integrity()
        return {
            "valid": valid,
            "message": message,
            "record_count": len(audit_ledger.list_records()),
        }

    return app
