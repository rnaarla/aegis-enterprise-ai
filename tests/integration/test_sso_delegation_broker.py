"""Tests for Project 1: Enterprise SSO & RFC 8693 Agent Delegation Broker (OIDC + SAML 2.0)."""

from __future__ import annotations

import base64

import pytest
from enterprise_twin.idp_seed.meridian_idp import (
    MeridianAgentRegistry,
    MeridianIdentityProvider,
    UpstreamIdentityError,
)
from httpx import ASGITransport, AsyncClient

from aegis_core.audit import InMemoryAuditLedger
from aegis_core.models import ClearanceLevel, TokenExchangeRequest
from sso_delegation_broker.app import create_broker_app
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker
from sso_delegation_broker.revocation import InMemoryRevocationStore

pytestmark = pytest.mark.integration


def _build_broker() -> tuple[SSODelegationBroker, MeridianIdentityProvider, InMemoryAuditLedger]:
    idp = MeridianIdentityProvider()
    audit = InMemoryAuditLedger()
    broker = SSODelegationBroker(
        idp=idp,
        agent_registry=MeridianAgentRegistry(),
        revocation_store=InMemoryRevocationStore(),
        audit_ledger=audit,
    )
    return broker, idp, audit


def test_triple_scope_and_clearance_intersection() -> None:
    broker, idp, _ = _build_broker()
    # Elena has TOP_SECRET_MA (40) & erp:po:approve, but meridian-procurement-agent is capped
    # at CONFIDENTIAL (20) and lacks erp:po:approve (preventing autonomous self-approval).
    oidc_tok = idp.issue_oidc_token_for_persona("elena.vance")
    resp = broker.exchange_token(
        TokenExchangeRequest(
            subject_token=oidc_tok,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            agent_id="meridian-procurement-agent",
            requested_scopes=["rag:read", "erp:po:create", "erp:po:approve", "ma:valuation:read"],
        )
    )
    assert resp.scope == "rag:read erp:po:create"
    assert resp.narrowed_out_scopes == ["erp:po:approve", "ma:valuation:read"]
    assert resp.effective_clearance == ClearanceLevel.CONFIDENTIAL


def test_saml2_xxe_and_signature_tamper_rejected() -> None:
    _, idp, _ = _build_broker()
    valid_saml = idp.issue_saml2_assertion_for_persona("priya.nair")
    principal = idp.verify_subject_token(valid_saml, "urn:ietf:params:oauth:token-type:saml2")
    assert principal.subject_id == "priya.nair"

    # Tamper clearance from 20 to 40 inside decoded SAML XML
    padded = valid_saml + "=" * (-len(valid_saml) % 4)
    tampered_xml = base64.urlsafe_b64decode(padded).replace(b">20<", b">40<")
    tampered_b64 = base64.urlsafe_b64encode(tampered_xml).decode("ascii")
    with pytest.raises(UpstreamIdentityError, match="signature verification failed"):
        idp.verify_subject_token(tampered_b64, "urn:ietf:params:oauth:token-type:saml2")

    # Attempt XXE external entity payload
    xxe_xml = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b'<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</Assertion>'
    )
    xxe_b64 = base64.urlsafe_b64encode(xxe_xml).decode("ascii")
    with pytest.raises(UpstreamIdentityError):
        idp.verify_subject_token(xxe_b64, "urn:ietf:params:oauth:token-type:saml2")


def test_empty_scope_intersection_and_unknown_agent_denied() -> None:
    broker, idp, audit = _build_broker()
    marcus_tok = idp.issue_oidc_token_for_persona("marcus.chen")

    with pytest.raises(DelegationPolicyError) as exc_info:
        broker.exchange_token(
            TokenExchangeRequest(
                subject_token=marcus_tok,
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                agent_id="meridian-procurement-agent",
                requested_scopes=["erp:po:create"],
            )
        )
    assert exc_info.value.oauth_error == "invalid_scope"

    with pytest.raises(DelegationPolicyError) as exc_agent:
        broker.exchange_token(
            TokenExchangeRequest(
                subject_token=marcus_tok,
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                agent_id="shadow-rogue-agent",
                requested_scopes=["rag:read"],
            )
        )
    assert exc_agent.value.oauth_error == "unauthorized_client"
    assert audit.verify_integrity()[0] is True


async def test_broker_http_endpoints_and_agent_killswitch() -> None:
    broker, idp, audit = _build_broker()
    app = create_broker_app(broker, audit)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://broker") as client:
        jwks_r = await client.get("/.well-known/jwks.json")
        assert jwks_r.status_code == 200
        assert len(jwks_r.json()["keys"]) == 1

        elena_tok = idp.issue_oidc_token_for_persona("elena.vance")
        marcus_tok = idp.issue_oidc_token_for_persona("marcus.chen")

        t1 = await client.post(
            "/v1/oauth/token",
            json={
                "subject_token": elena_tok,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "agent_id": "meridian-ma-copilot",
                "requested_scopes": ["rag:read"],
            },
        )
        t2 = await client.post(
            "/v1/oauth/token",
            json={
                "subject_token": marcus_tok,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "agent_id": "meridian-ma-copilot",
                "requested_scopes": ["rag:read"],
            },
        )
        jwt_1 = t1.json()["access_token"]
        jwt_2 = t2.json()["access_token"]

        intro_before = await client.post("/v1/oauth/introspect", json={"token": jwt_1})
        assert intro_before.json()["active"] is True

        # Trigger emergency agent killswitch revoking ALL active tokens for meridian-ma-copilot
        kill_r = await client.post(
            "/v1/oauth/revoke",
            json={
                "mode": "agent_killswitch",
                "tenant_id": "meridian-fin",
                "agent_id": "meridian-ma-copilot",
                "reason": "anomalous_tool_loop_detected",
            },
        )
        assert kill_r.status_code == 200
        assert kill_r.json()["revoked_count"] == 2

        for revoked_jwt in (jwt_1, jwt_2):
            intro_after = await client.post("/v1/oauth/introspect", json={"token": revoked_jwt})
            assert intro_after.json()["active"] is False

        verify_r = await client.get("/v1/audit/verify")
        assert verify_r.json()["valid"] is True
