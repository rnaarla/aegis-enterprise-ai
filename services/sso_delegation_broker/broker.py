"""Core RFC 8693 OAuth 2.0 Token Exchange & Non-Human Identity Broker."""

from __future__ import annotations

import time
from typing import Any

from aegis_core.crypto import (
    MAX_DELEGATED_TTL_SECONDS,
    JWKSVerifier,
    SigningKeyPair,
    TokenVerificationError,
    mint_delegated_jwt,
)
from aegis_core.models import (
    AuditEventType,
    ClearanceLevel,
    DelegatedTokenClaims,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from aegis_core.ports import (
    AgentRegistryPort,
    AuditLedgerPort,
    IdentityProviderPort,
    RevocationStorePort,
)
from aegis_core.telemetry import AegisTelemetry


class DelegationPolicyError(Exception):
    """RFC 6749 / RFC 8693 compliant OAuth error with HTTP status mapping."""

    def __init__(self, oauth_error: str, description: str, status_code: int = 400) -> None:
        super().__init__(description)
        self.oauth_error = oauth_error
        self.description = description
        self.status_code = status_code


class SSODelegationBroker:
    """Enterprise OIDC/SAML -> 5-Minute Scoped Agent JWT Delegation Broker."""

    def __init__(
        self,
        *,
        issuer: str = "https://auth.aegis.meridian.fin",
        default_audience: str = "aegis-data-plane",
        idp: IdentityProviderPort,
        agent_registry: AgentRegistryPort,
        revocation_store: RevocationStorePort,
        audit_ledger: AuditLedgerPort,
        signing_key: SigningKeyPair | None = None,
        telemetry: AegisTelemetry | None = None,
    ) -> None:
        self.issuer = issuer
        self.default_audience = default_audience
        self._idp = idp
        self._agents = agent_registry
        self._revocation = revocation_store
        self._audit = audit_ledger
        self._signing_key = signing_key or SigningKeyPair.generate_es256()
        self._telemetry = telemetry or AegisTelemetry("aegis-sso-broker")
        self._verifier = JWKSVerifier(
            issuer=self.issuer,
            expected_audience=self.default_audience,
            jwks=self.public_jwks(),
        )

    def public_jwks(self) -> dict[str, Any]:
        """Publish RFC 7517 JWKS for downstream services (RAG, MCP, PII Proxy)."""
        return {"keys": [self._signing_key.public_jwk]}

    def exchange_token(
        self,
        req: TokenExchangeRequest,
        *,
        now_epoch: int | None = None,
    ) -> TokenExchangeResponse:
        """Validate upstream human token, intersect scopes/clearance, and issue 5m `at+jwt`."""
        with self._telemetry.span(
            "aegis.oauth.token_exchange",
            {"aegis.agent_id": req.agent_id, "aegis.token_type": req.subject_token_type},
        ):
            try:
                principal = self._idp.verify_subject_token(
                    req.subject_token, req.subject_token_type
                )
            except Exception as exc:
                self._audit.append(
                    tenant_id="unknown",
                    event_type=AuditEventType.TOKEN_EXCHANGE_DENIED,
                    human_subject="unverified",
                    actor_id=req.agent_id,
                    jti=None,
                    decision="DENY",
                    detail={"reason": f"upstream_auth_failed:{exc}"},
                )
                raise DelegationPolicyError(
                    "invalid_grant",
                    f"Upstream IdP credential rejected: {exc}",
                    status_code=401,
                ) from exc

            agent = self._agents.get_agent(req.agent_id)
            if agent is None or not agent.active:
                self._audit.append(
                    tenant_id=principal.tenant_id,
                    event_type=AuditEventType.TOKEN_EXCHANGE_DENIED,
                    human_subject=principal.subject_id,
                    actor_id=req.agent_id,
                    jti=None,
                    decision="DENY",
                    detail={"reason": "unregistered_or_disabled_agent"},
                )
                raise DelegationPolicyError(
                    "unauthorized_client",
                    f"Agent {req.agent_id!r} is unregistered or disabled",
                    status_code=403,
                )

            revoked, rev_reason = self._revocation.is_revoked(
                "precheck", principal.subject_id, agent.agent_id
            )
            if revoked:
                self._audit.append(
                    tenant_id=principal.tenant_id,
                    event_type=AuditEventType.TOKEN_EXCHANGE_DENIED,
                    human_subject=principal.subject_id,
                    actor_id=agent.spiffe_id,
                    jti=None,
                    decision="DENY",
                    detail={"reason": rev_reason or "revoked"},
                )
                raise DelegationPolicyError(
                    "invalid_grant",
                    f"Delegation blocked by active revocation: {rev_reason}",
                    status_code=403,
                )

            # Triple-intersection scope narrowing:
            # effective = requested ∩ human_entitlements ∩ agent_manifest_ceiling
            human_scope_set = set(principal.scopes)
            agent_scope_set = set(agent.allowed_scopes)
            effective_list: list[str] = []
            narrowed_out: list[str] = []
            seen: set[str] = set()
            for scope in req.requested_scopes:
                if scope in seen:
                    continue
                seen.add(scope)
                if scope in human_scope_set and scope in agent_scope_set:
                    effective_list.append(scope)
                else:
                    narrowed_out.append(scope)

            if not effective_list:
                self._audit.append(
                    tenant_id=principal.tenant_id,
                    event_type=AuditEventType.TOKEN_EXCHANGE_DENIED,
                    human_subject=principal.subject_id,
                    actor_id=agent.spiffe_id,
                    jti=None,
                    decision="DENY",
                    detail={
                        "reason": "empty_scope_intersection",
                        "requested": req.requested_scopes,
                    },
                )
                raise DelegationPolicyError(
                    "invalid_scope",
                    "Zero authorized scopes remain after intersecting human and agent boundaries",
                    status_code=403,
                )

            effective_clearance = ClearanceLevel(
                min(int(principal.clearance), int(agent.max_clearance))
            )
            effective_ttl = min(
                req.requested_ttl_seconds,
                agent.max_ttl_seconds,
                MAX_DELEGATED_TTL_SECONDS,
            )

            token, jti, exp_epoch = mint_delegated_jwt(
                signing_key=self._signing_key,
                issuer=self.issuer,
                audience=req.audience,
                principal=principal,
                agent_spiffe_id=agent.spiffe_id,
                agent_client_id=agent.agent_id,
                effective_scopes=tuple(effective_list),
                effective_clearance=effective_clearance,
                ttl_seconds=effective_ttl,
                dpop_jkt=req.dpop_jkt,
                now_epoch=now_epoch,
            )

            self._revocation.register_issued_token(
                jti=jti,
                human_subject=principal.subject_id,
                agent_id=agent.agent_id,
                exp_epoch=exp_epoch,
            )

            audit_rec = self._audit.append(
                tenant_id=principal.tenant_id,
                event_type=AuditEventType.TOKEN_EXCHANGED,
                human_subject=principal.subject_id,
                actor_id=agent.spiffe_id,
                jti=jti,
                decision="ALLOW",
                detail={
                    "auth_method": principal.auth_method,
                    "granted_scopes": effective_list,
                    "narrowed_out_scopes": narrowed_out,
                    "effective_clearance": int(effective_clearance),
                    "ttl_seconds": effective_ttl,
                },
            )

            return TokenExchangeResponse(
                access_token=token,
                token_type="DPoP" if req.dpop_jkt else "Bearer",
                expires_in=effective_ttl,
                scope=" ".join(effective_list),
                jti=jti,
                effective_clearance=effective_clearance,
                narrowed_out_scopes=narrowed_out,
                audit_entry_hash=audit_rec.entry_hash,
            )

    def verify_and_check_revocation(
        self,
        token: str,
        *,
        required_scope: str | None = None,
        now_epoch: int | None = None,
    ) -> DelegatedTokenClaims:
        """Verify cryptographic signature, TTL ceiling, JTI revocation, and required scope."""
        claims = self._verifier.verify_delegated_jwt(token, now_epoch=now_epoch)
        revoked, reason = self._revocation.is_revoked(claims.jti, claims.sub, claims.act.client_id)
        if revoked:
            raise TokenVerificationError(f"Delegated token revoked ({reason})")
        if required_scope is not None and required_scope not in claims.scopes:
            raise DelegationPolicyError(
                "insufficient_scope",
                f"Delegated token lacks required scope {required_scope!r}",
                status_code=403,
            )
        return claims

    def introspect_token(self, token: str) -> dict[str, Any]:
        """RFC 7662 OAuth 2.0 Token Introspection response."""
        try:
            claims = self.verify_and_check_revocation(token)
        except (TokenVerificationError, DelegationPolicyError):
            return {"active": False}
        return {
            "active": True,
            "iss": claims.iss,
            "sub": claims.sub,
            "jti": claims.jti,
            "exp": claims.exp,
            "iat": claims.iat,
            "tenant_id": claims.tenant_id,
            "scope": " ".join(claims.scopes),
            "clearance": int(claims.clearance),
            "act": {"sub": claims.act.sub, "client_id": claims.act.client_id},
        }

    def revoke_token_by_jti(
        self,
        *,
        jti: str,
        tenant_id: str,
        human_subject: str,
        actor_id: str,
        reason: str = "explicit_jti_revocation",
        exp_epoch: int | None = None,
    ) -> str:
        exp = exp_epoch if exp_epoch is not None else int(time.time()) + MAX_DELEGATED_TTL_SECONDS
        self._revocation.revoke_jti(jti, exp, reason)
        rec = self._audit.append(
            tenant_id=tenant_id,
            event_type=AuditEventType.TOKEN_REVOKED,
            human_subject=human_subject,
            actor_id=actor_id,
            jti=jti,
            decision="REVOKE",
            detail={"reason": reason},
        )
        return rec.entry_hash

    def killswitch_agent(self, *, tenant_id: str, agent_id: str, reason: str) -> tuple[int, str]:
        """Immediately revoke all live tokens held by an autonomous agent across all users."""
        revoked_count = self._revocation.revoke_all_for_agent(agent_id, reason)
        rec = self._audit.append(
            tenant_id=tenant_id,
            event_type=AuditEventType.AGENT_KILLSWITCH,
            human_subject="sec_ops_system",
            actor_id=agent_id,
            jti=None,
            decision="REVOKE",
            detail={"reason": reason, "revoked_active_tokens": revoked_count},
        )
        return revoked_count, rec.entry_hash
