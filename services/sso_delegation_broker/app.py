"""FastAPI HTTP transport for Project 1: Enterprise SSO & Delegation Broker."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis_core.http_middleware import install_aegis_http_layer
from aegis_core.models import TokenExchangeRequest, TokenExchangeResponse
from aegis_core.ports import AuditLedgerPort
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker


class IntrospectRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    token: str = Field(min_length=16)


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
        version="0.2.0",
        docs_url="/docs",
    )
    install_aegis_http_layer(app, service_name="sso-delegation-broker")

    @app.get("/.well-known/jwks.json")
    def jwks_endpoint() -> dict[str, Any]:
        return broker.public_jwks()

    @app.post("/v1/oauth/token", response_model=TokenExchangeResponse)
    def token_exchange(req: TokenExchangeRequest) -> TokenExchangeResponse | JSONResponse:
        try:
            return broker.exchange_token(req)
        except DelegationPolicyError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": exc.oauth_error, "error_description": exc.description},
            )

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
