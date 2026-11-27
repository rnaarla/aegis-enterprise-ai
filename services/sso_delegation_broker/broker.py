"""Core RFC 8693 OAuth 2.0 Token Exchange, Multi-Hop Subdelegation, RAR, DPoP & SSF Broker."""

from __future__ import annotations

import time
from typing import Any

from aegis_core.crypto import (
    MAX_DELEGATED_TTL_SECONDS,
    JWKSVerifier,
    SigningKeyPair,
    SigningKeyRing,
    TokenVerificationError,
    mint_delegated_jwt,
)
from aegis_core.models import (
    AuditEventType,
    AuthorizationDetail,
    ClearanceLevel,
    DelegatedTokenClaims,
    HumanPrincipal,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from aegis_core.ports import (
    AgentRegistryPort,
    AuditLedgerPort,
    IdentityProviderPort,
    RevocationStorePort,
)
from aegis_core.ports import (
    DelegationPolicyError as DelegationPolicyError,
)
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry
from aegis_core.telemetry import AegisTelemetry
from sso_delegation_broker.dpop_ssf import (
    DPoPProofVerifier,
    SSFSecurityEventReceiver,
    verify_mtls_cert_thumbprint,
)


def _attenuate_rar_details(
    requested: list[AuthorizationDetail],
    *,
    po_ceiling_usd: float,
    parent_details: tuple[AuthorizationDetail, ...] | None = None,
) -> tuple[AuthorizationDetail, ...]:
    """Monotonically narrow RFC 9396 `authorization_details` against principal/parent limits."""
    parent_by_type = {d.type: d for d in parent_details} if parent_details else None
    attenuated: list[AuthorizationDetail] = []
    for item in requested:
        if parent_by_type is not None and item.type not in parent_by_type:
            continue
        p_detail = parent_by_type[item.type] if parent_by_type is not None else None

        actions = item.actions
        if p_detail is not None and p_detail.actions:
            actions = tuple(a for a in item.actions if a in p_detail.actions)

        max_amt = item.max_amount_usd
        if item.type == "sap_po":
            cap = po_ceiling_usd
            if p_detail is not None and p_detail.max_amount_usd is not None:
                cap = min(cap, p_detail.max_amount_usd)
            max_amt = cap if max_amt is None else min(max_amt, cap)

        cost_centers = item.allowed_cost_centers
        if p_detail is not None and p_detail.allowed_cost_centers:
            cost_centers = tuple(
                cc for cc in item.allowed_cost_centers if cc in p_detail.allowed_cost_centers
            )

        sources = item.allowed_sources
        if p_detail is not None and p_detail.allowed_sources:
            sources = tuple(s for s in item.allowed_sources if s in p_detail.allowed_sources)

        attenuated.append(
            AuthorizationDetail(
                type=item.type,
                actions=actions,
                max_amount_usd=max_amt,
                allowed_cost_centers=cost_centers,
                allowed_sources=sources,
            )
        )
    return tuple(attenuated)


class SSODelegationBroker:
    """Enterprise OIDC/SAML -> 5m Scoped `at+jwt` Broker with DPoP, mTLS, RAR, SSF & Subdelegation."""

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
        trusted_ssf_jwks: dict[str, Any] | None = None,
        ssf_issuer: str = "https://idp.meridian.fin",
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self.issuer = issuer
        self.default_audience = default_audience
        self._idp = idp
        self._agents = agent_registry
        self._revocation = revocation_store
        self._audit = audit_ledger
        self._keyring = SigningKeyRing(signing_key)
        self._telemetry = telemetry or AegisTelemetry("aegis-sso-broker")
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY
        self._dpop_verifier = DPoPProofVerifier(sli_registry=self._sli)
        self._verifier = JWKSVerifier(
            issuer=self.issuer,
            expected_audience=self.default_audience,
            jwks=self.public_jwks(),
        )
        self._ssf_receiver: SSFSecurityEventReceiver | None = None
        if trusted_ssf_jwks is not None:
            self.configure_ssf_receiver(trusted_idp_jwks=trusted_ssf_jwks, ssf_issuer=ssf_issuer)

    def configure_ssf_receiver(
        self,
        *,
        trusted_idp_jwks: dict[str, Any],
        ssf_issuer: str = "https://idp.meridian.fin",
    ) -> None:
        self._ssf_receiver = SSFSecurityEventReceiver(
            trusted_idp_jwks=trusted_idp_jwks,
            expected_issuer=ssf_issuer,
            expected_audience=self.issuer,
            revocation_store=self._revocation,
            audit_ledger=self._audit,
            sli_registry=self._sli,
        )

    def public_jwks(self) -> dict[str, Any]:
        """Publish RFC 7517 JWKS containing active signing key + retained rollover grace keys."""
        return self._keyring.public_jwks()

    def rotate_signing_key(self, *, tenant_id: str = "system") -> str:
        """Zero-downtime signing key rollover; existing tokens remain verifiable via JWKS ring."""
        new_key = self._keyring.rotate()
        self._verifier.reload_jwks(self.public_jwks())
        self._sli.inc_counter("aegis_keyring_rotations_total", 1.0)
        self._audit.append(
            tenant_id=tenant_id,
            event_type=AuditEventType.KEYRING_ROTATED,
            human_subject="kms_rotation_daemon",
            actor_id="sso-delegation-broker",
            jti=None,
            decision="ALLOW",
            detail={"new_active_kid": new_key.kid, "retained_keys": len(self.public_jwks()["keys"])},
        )
        return new_key.kid

    def exchange_token(
        self,
        req: TokenExchangeRequest,
        *,
        dpop_proof_jwt: str | None = None,
        http_method: str = "POST",
        http_url: str = "https://auth.aegis.meridian.fin/v1/oauth/token",
        now_epoch: int | None = None,
    ) -> TokenExchangeResponse:
        """Validate upstream human token, optional DPoP proof, RAR, and issue 5m `at+jwt`."""
        with self._telemetry.span(
            "aegis.oauth.token_exchange",
            {"aegis.agent_id": req.agent_id, "aegis.token_type": req.subject_token_type},
        ):
            if dpop_proof_jwt is not None:
                if not req.dpop_jkt:
                    raise DelegationPolicyError(
                        "invalid_dpop_proof",
                        "dpop_jkt thumbprint required when presenting DPoP proof header",
                        status_code=400,
                    )
                try:
                    self._dpop_verifier.verify_proof(
                        dpop_proof_jwt,
                        expected_htm=http_method,
                        expected_htu=http_url,
                        expected_jkt=req.dpop_jkt,
                        now_epoch=now_epoch,
                    )
                except TokenVerificationError as exc:
                    raise DelegationPolicyError(
                        "invalid_dpop_proof", str(exc), status_code=401
                    ) from exc

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
                    detail={"reason": "empty_scope_intersection", "requested": req.requested_scopes},
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
            attenuated_rar = _attenuate_rar_details(
                req.authorization_details,
                po_ceiling_usd=float(principal.po_approval_limit_usd),
            )

            token, jti, exp_epoch = mint_delegated_jwt(
                signing_key=self._keyring.active_key,
                issuer=self.issuer,
                audience=req.audience,
                principal=principal,
                agent_spiffe_id=agent.spiffe_id,
                agent_client_id=agent.agent_id,
                effective_scopes=tuple(effective_list),
                effective_clearance=effective_clearance,
                ttl_seconds=effective_ttl,
                dpop_jkt=req.dpop_jkt,
                mtls_cert_thumbprint_s256=req.mtls_cert_thumbprint_s256,
                authorization_details=attenuated_rar,
                now_epoch=now_epoch,
            )

            self._revocation.register_issued_token(
                jti=jti,
                human_subject=principal.subject_id,
                agent_id=agent.agent_id,
                exp_epoch=exp_epoch,
            )
            self._sli.inc_counter(
                "aegis_tokens_minted_total",
                1.0,
                {"grant": "human_to_agent", "token_type": "DPoP" if req.dpop_jkt else "Bearer"},
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
                    "dpop_bound": bool(req.dpop_jkt),
                    "mtls_bound": bool(req.mtls_cert_thumbprint_s256),
                    "rar_count": len(attenuated_rar),
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
                authorization_details=list(attenuated_rar),
                delegation_depth=1,
            )

    def exchange_agent_to_agent(
        self,
        *,
        parent_agent_token: str,
        target_subagent_id: str,
        requested_scopes: list[str],
        requested_ttl_seconds: int = 120,
        authorization_details: list[AuthorizationDetail] | None = None,
        dpop_jkt: str | None = None,
        now_epoch: int | None = None,
    ) -> TokenExchangeResponse:
        """Multi-hop RFC 8693 `act`-chain subdelegation with strict monotonic attenuation."""
        try:
            parent_claims = self.verify_and_check_revocation(
                parent_agent_token, now_epoch=now_epoch
            )
        except (TokenVerificationError, DelegationPolicyError) as exc:
            raise DelegationPolicyError(
                "invalid_grant", f"Parent agent token invalid: {exc}", status_code=401
            ) from exc

        subagent = self._agents.get_agent(target_subagent_id)
        if subagent is None or not subagent.active:
            raise DelegationPolicyError(
                "unauthorized_client",
                f"Subagent {target_subagent_id!r} unregistered or inactive",
                status_code=403,
            )

        if subagent.spiffe_id in parent_claims.act.chain_spiffe_ids():
            raise DelegationPolicyError(
                "invalid_request",
                f"Delegation cycle blocked: {subagent.spiffe_id} is already in act chain",
                status_code=400,
            )

        parent_scope_set = set(parent_claims.scopes)
        subagent_scope_set = set(subagent.allowed_scopes)
        effective_list = [
            s for s in dict.fromkeys(requested_scopes) if s in parent_scope_set and s in subagent_scope_set
        ]
        narrowed_out = [s for s in dict.fromkeys(requested_scopes) if s not in effective_list]
        if not effective_list:
            raise DelegationPolicyError(
                "invalid_scope",
                "Zero scopes remain after monotonic parent-to-subagent attenuation",
                status_code=403,
            )

        effective_clearance = ClearanceLevel(
            min(int(parent_claims.clearance), int(subagent.max_clearance))
        )
        now = now_epoch if now_epoch is not None else int(time.time())
        remaining_parent_ttl = max(0, parent_claims.exp - now)
        if remaining_parent_ttl < 1:
            raise DelegationPolicyError("invalid_grant", "Parent token expired", status_code=401)
        effective_ttl = min(
            requested_ttl_seconds,
            subagent.max_ttl_seconds,
            remaining_parent_ttl,
            MAX_DELEGATED_TTL_SECONDS,
        )

        synthetic_principal = HumanPrincipal(
            tenant_id=parent_claims.tenant_id,
            subject_id=parent_claims.sub,
            email=parent_claims.email,
            display_name=parent_claims.sub,
            department=parent_claims.department,
            groups=parent_claims.groups,
            scopes=parent_claims.scopes,
            clearance=effective_clearance,
            po_approval_limit_usd=parent_claims.po_approval_limit_usd,
            auth_method="oidc",
            upstream_session_id=f"subdel-{parent_claims.jti[:12]}",
        )
        attenuated_rar = _attenuate_rar_details(
            authorization_details if authorization_details is not None else list(parent_claims.authorization_details),
            po_ceiling_usd=float(parent_claims.po_approval_limit_usd),
            parent_details=parent_claims.authorization_details or None,
        )

        try:
            token, jti, exp_epoch = mint_delegated_jwt(
                signing_key=self._keyring.active_key,
                issuer=self.issuer,
                audience=parent_claims.aud[0],
                principal=synthetic_principal,
                agent_spiffe_id=subagent.spiffe_id,
                agent_client_id=subagent.agent_id,
                effective_scopes=tuple(effective_list),
                effective_clearance=effective_clearance,
                ttl_seconds=effective_ttl,
                dpop_jkt=dpop_jkt,
                authorization_details=attenuated_rar,
                parent_actor=parent_claims.act,
                max_exp_epoch=parent_claims.exp,
                now_epoch=now_epoch,
            )
        except ValueError as exc:
            raise DelegationPolicyError("invalid_request", str(exc), status_code=400) from exc

        self._revocation.register_issued_token(
            jti=jti,
            human_subject=parent_claims.sub,
            agent_id=subagent.agent_id,
            exp_epoch=exp_epoch,
        )
        new_depth = parent_claims.delegation_depth + 1
        self._sli.inc_counter(
            "aegis_tokens_minted_total",
            1.0,
            {"grant": "agent_subdelegation", "token_type": "DPoP" if dpop_jkt else "Bearer"},
        )
        rec = self._audit.append(
            tenant_id=parent_claims.tenant_id,
            event_type=AuditEventType.AGENT_SUBDELEGATED,
            human_subject=parent_claims.sub,
            actor_id=subagent.spiffe_id,
            jti=jti,
            decision="ALLOW",
            detail={
                "parent_actor": parent_claims.act.sub,
                "delegation_depth": new_depth,
                "granted_scopes": effective_list,
                "ttl_seconds": exp_epoch - now,
            },
        )
        return TokenExchangeResponse(
            access_token=token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=exp_epoch - now,
            scope=" ".join(effective_list),
            jti=jti,
            effective_clearance=effective_clearance,
            narrowed_out_scopes=narrowed_out,
            audit_entry_hash=rec.entry_hash,
            authorization_details=list(attenuated_rar),
            delegation_depth=new_depth,
        )

    def verify_and_check_revocation(
        self,
        token: str,
        *,
        required_scope: str | None = None,
        dpop_proof_jwt: str | None = None,
        expected_htm: str | None = None,
        expected_htu: str | None = None,
        presented_mtls_x5t_s256: str | None = None,
        now_epoch: int | None = None,
    ) -> DelegatedTokenClaims:
        """Verify JWT signature, revocation across all actors in `act` chain, DPoP, & mTLS."""
        claims = self._verifier.verify_delegated_jwt(token, now_epoch=now_epoch)
        # Check revocation for every agent in a multi-hop delegation chain!
        curr_act = claims.act
        while True:
            revoked, reason = self._revocation.is_revoked(
                claims.jti, claims.sub, curr_act.client_id
            )
            if revoked:
                raise TokenVerificationError(f"Delegated token revoked ({reason})")
            if curr_act.act is None:
                break
            curr_act = curr_act.act

        if claims.cnf_jkt is not None and expected_htm is not None and expected_htu is not None:
            if not dpop_proof_jwt:
                raise TokenVerificationError("Sender-constrained token requires DPoP proof header")
            self._dpop_verifier.verify_proof(
                dpop_proof_jwt,
                expected_htm=expected_htm,
                expected_htu=expected_htu,
                expected_jkt=claims.cnf_jkt,
                access_token=token,
                now_epoch=now_epoch,
            )

        verify_mtls_cert_thumbprint(claims.cnf_x5t_s256, presented_mtls_x5t_s256)

        if required_scope is not None and required_scope not in claims.scopes:
            raise DelegationPolicyError(
                "insufficient_scope",
                f"Delegated token lacks required scope {required_scope!r}",
                status_code=403,
            )
        return claims

    def ingest_ssf_security_event(self, set_jwt: str) -> dict[str, Any]:
        if self._ssf_receiver is None:
            raise DelegationPolicyError(
                "server_error", "SSF receiver not configured", status_code=501
            )
        try:
            return self._ssf_receiver.ingest_set_token(set_jwt)
        except TokenVerificationError as exc:
            raise DelegationPolicyError("invalid_token", str(exc), status_code=401) from exc

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
            "delegation_depth": claims.delegation_depth,
            "act": claims.act.model_dump(exclude_none=True),
            "authorization_details": [
                d.model_dump(exclude_none=True) for d in claims.authorization_details
            ],
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
