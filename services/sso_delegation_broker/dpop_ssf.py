"""RFC 9449 DPoP Proof Verifier, RFC 8705 mTLS Binding & OpenID SSF/CAEP Push Receiver."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

import jwt

from aegis_core.crypto import (
    SigningKeyPair,
    TokenVerificationError,
    compute_jwk_thumbprint_from_public_jwk,
)
from aegis_core.dsa import BoundedLRUTTLCache
from aegis_core.models import AuditEventType
from aegis_core.ports import AuditLedgerPort, RevocationStorePort
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry


def _compute_ath(access_token: str) -> str:
    """Compute RFC 9449 Section 4.2 `ath` base64url-encoded SHA-256 hash of ASCII access token."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _normalize_htu(uri: str) -> str:
    """Normalize HTTP URI per RFC 9449 Section 4.2 (strip query and fragment components)."""
    return uri.split("?", 1)[0].split("#", 1)[0]


def mint_dpop_proof(
    *,
    holder_key: SigningKeyPair,
    htm: str,
    htu: str,
    access_token: str | None = None,
    jti: str | None = None,
    iat_epoch: int | None = None,
) -> str:
    """Mint a client/agent RFC 9449 `dpop+jwt` proof signed by the holder's private key."""
    now = iat_epoch if iat_epoch is not None else int(time.time())
    payload: dict[str, Any] = {
        "jti": jti or str(uuid.uuid4()),
        "htm": htm.upper(),
        "htu": _normalize_htu(htu),
        "iat": now,
    }
    if access_token is not None:
        payload["ath"] = _compute_ath(access_token)
    pub_jwk = {
        k: v for k, v in holder_key.public_jwk.items() if k in ("kty", "crv", "x", "y", "n", "e")
    }
    return jwt.encode(
        payload=payload,
        key=holder_key.private_pem,
        algorithm=holder_key.algorithm,
        headers={"typ": "dpop+jwt", "alg": holder_key.algorithm, "jwk": pub_jwk},
    )


class DPoPProofVerifier:
    """Verifies RFC 9449 DPoP sender-constrained proofs with `O(1)` bounded `jti` anti-replay."""

    def __init__(
        self,
        *,
        max_clock_skew_seconds: int = 120,
        replay_cache_size: int = 100_000,
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self._skew = max_clock_skew_seconds
        self._replay_cache: BoundedLRUTTLCache[str, bool] = BoundedLRUTTLCache(
            max_size=replay_cache_size,
            default_ttl_seconds=float(max_clock_skew_seconds * 2),
        )
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY

    def verify_proof(
        self,
        proof_jwt: str,
        *,
        expected_htm: str,
        expected_htu: str,
        expected_jkt: str,
        access_token: str | None = None,
        now_epoch: int | None = None,
    ) -> str:
        """Validate DPoP proof signature, `jkt` binding, `htm`/`htu`, `ath`, and single-use `jti`."""
        try:
            header = jwt.get_unverified_header(proof_jwt)
        except jwt.PyJWTError as exc:
            self._sli.inc_counter("aegis_dpop_verifications_total", 1.0, {"outcome": "bad_header"})
            raise TokenVerificationError(f"Malformed DPoP header: {exc}") from exc

        if header.get("typ") != "dpop+jwt":
            self._sli.inc_counter("aegis_dpop_verifications_total", 1.0, {"outcome": "bad_typ"})
            raise TokenVerificationError("DPoP header typ must be 'dpop+jwt'")

        alg = str(header.get("alg", ""))
        jwk_raw = header.get("jwk")
        if alg not in ("ES256", "RS256") or not isinstance(jwk_raw, dict):
            self._sli.inc_counter("aegis_dpop_verifications_total", 1.0, {"outcome": "bad_jwk"})
            raise TokenVerificationError("DPoP header requires asymmetric ES256/RS256 public 'jwk'")

        if "d" in jwk_raw or "p" in jwk_raw:
            raise TokenVerificationError("DPoP header MUST NOT contain private key material")

        computed_jkt = compute_jwk_thumbprint_from_public_jwk(jwk_raw)
        if not hmac.compare_digest(computed_jkt, expected_jkt):
            self._sli.inc_counter(
                "aegis_dpop_verifications_total", 1.0, {"outcome": "jkt_mismatch"}
            )
            raise TokenVerificationError("DPoP proof public key thumbprint does not match cnf.jkt")

        jwk_json = json.dumps(jwk_raw)
        pub_key: Any = (
            jwt.algorithms.ECAlgorithm.from_jwk(jwk_json)
            if alg == "ES256"
            else jwt.algorithms.RSAAlgorithm.from_jwk(jwk_json)
        )
        try:
            claims: dict[str, Any] = jwt.decode(
                proof_jwt,
                key=pub_key,
                algorithms=[alg],
                options={"require": ["jti", "htm", "htu", "iat"], "verify_iat": False},
            )
        except jwt.PyJWTError as exc:
            self._sli.inc_counter("aegis_dpop_verifications_total", 1.0, {"outcome": "bad_sig"})
            raise TokenVerificationError(f"DPoP signature invalid: {exc}") from exc

        now = now_epoch if now_epoch is not None else int(time.time())
        iat = int(claims["iat"])
        if abs(now - iat) > self._skew:
            self._sli.inc_counter("aegis_dpop_verifications_total", 1.0, {"outcome": "stale_iat"})
            raise TokenVerificationError("DPoP proof iat outside freshness window")

        if str(claims["htm"]).upper() != expected_htm.upper():
            raise TokenVerificationError("DPoP htm mismatch")
        if _normalize_htu(str(claims["htu"])) != _normalize_htu(expected_htu):
            raise TokenVerificationError("DPoP htu mismatch")

        if access_token is not None:
            ath = str(claims.get("ath", ""))
            if not hmac.compare_digest(ath, _compute_ath(access_token)):
                self._sli.inc_counter(
                    "aegis_dpop_verifications_total", 1.0, {"outcome": "ath_mismatch"}
                )
                raise TokenVerificationError("DPoP ath does not match presented access token")

        proof_jti = f"{computed_jkt}:{claims['jti']}"
        if self._replay_cache.get(proof_jti) is not None:
            self._sli.inc_counter("aegis_dpop_verifications_total", 1.0, {"outcome": "replayed"})
            raise TokenVerificationError("DPoP proof replay detected (duplicate jti)")
        self._replay_cache.put(proof_jti, True)
        self._sli.inc_counter("aegis_dpop_verifications_total", 1.0, {"outcome": "verified"})
        return computed_jkt


def verify_mtls_cert_thumbprint(
    expected_x5t_s256: str | None,
    presented_x5t_s256: str | None,
) -> None:
    """Enforce RFC 8705 mutual-TLS X.509 certificate-bound token verification (`cnf.x5t#S256`)."""
    if expected_x5t_s256 is None:
        return
    if not presented_x5t_s256 or not hmac.compare_digest(expected_x5t_s256, presented_x5t_s256):
        raise TokenVerificationError(
            "RFC 8705 mTLS peer certificate thumbprint mismatch or missing client cert"
        )


CAEP_SESSION_REVOKED_URI = (
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
)
CAEP_CREDENTIAL_CHANGE_URI = (
    "https://schemas.openid.net/secevent/caep/event-type/credential-change"
)
RISC_ACCOUNT_DISABLED_URI = (
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
)

SUPPORTED_SSF_REVOKE_URIS: frozenset[str] = frozenset(
    {CAEP_SESSION_REVOKED_URI, CAEP_CREDENTIAL_CHANGE_URI, RISC_ACCOUNT_DISABLED_URI}
)


def mint_ssf_security_event_token(
    *,
    idp_signing_key: SigningKeyPair,
    issuer: str,
    audience: str,
    tenant_id: str,
    subject_id: str,
    event_uri: str = CAEP_SESSION_REVOKED_URI,
    reason: str = "idp_risk_elevation",
    now_epoch: int | None = None,
) -> str:
    """Mint an RFC 8417 / OpenID SSF CAEP `secevent+jwt` push notification token."""
    now = now_epoch if now_epoch is not None else int(time.time())
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "jti": f"set-{uuid.uuid4().hex}",
        "sub_id": {"format": "opaque", "id": subject_id, "tenant_id": tenant_id},
        "events": {event_uri: {"event_timestamp": now, "reason_admin": reason}},
    }
    return jwt.encode(
        payload=payload,
        key=idp_signing_key.private_pem,
        algorithm=idp_signing_key.algorithm,
        headers={"typ": "secevent+jwt", "kid": idp_signing_key.kid},
    )


class SSFSecurityEventReceiver:
    """Ingests signed OpenID SSF / CAEP Security Event Tokens and cascades revocations in <5ms."""

    def __init__(
        self,
        *,
        trusted_idp_jwks: dict[str, Any],
        expected_issuer: str,
        expected_audience: str,
        revocation_store: RevocationStorePort,
        audit_ledger: AuditLedgerPort,
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self._issuer = expected_issuer
        self._audience = expected_audience
        self._revocation = revocation_store
        self._audit = audit_ledger
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY
        self._dedup: BoundedLRUTTLCache[str, bool] = BoundedLRUTTLCache(
            max_size=50_000, default_ttl_seconds=3600.0
        )
        self._keys_by_kid: dict[str, tuple[Any, str]] = {}
        for item in trusted_idp_jwks.get("keys", []):
            kid = str(item.get("kid", ""))
            alg = str(item.get("alg", ""))
            if alg == "RS256":
                self._keys_by_kid[kid] = (
                    jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(item)),
                    alg,
                )
            elif alg == "ES256":
                self._keys_by_kid[kid] = (
                    jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(item)),
                    alg,
                )

    def ingest_set_token(self, set_jwt: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(set_jwt)
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"Malformed SSF SET header: {exc}") from exc

        if header.get("typ") != "secevent+jwt":
            raise TokenVerificationError("SSF token must carry typ='secevent+jwt'")
        kid = str(header.get("kid", ""))
        key_entry = self._keys_by_kid.get(kid)
        if key_entry is None:
            raise TokenVerificationError(f"Untrusted IdP SET kid: {kid!r}")
        pub_key, alg = key_entry

        try:
            claims: dict[str, Any] = jwt.decode(
                set_jwt,
                key=pub_key,
                algorithms=[alg],
                issuer=self._issuer,
                audience=self._audience,
                options={"require": ["iss", "aud", "iat", "jti", "events", "sub_id"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"SSF SET verification failed: {exc}") from exc

        set_jti = str(claims["jti"])
        if self._dedup.get(set_jti) is not None:
            return {"status": "idempotent_duplicate", "jti": set_jti, "revoked_tokens": 0}

        sub_obj = claims.get("sub_id", {})
        subject_id = str(sub_obj.get("id", ""))
        tenant_id = str(sub_obj.get("tenant_id", "unknown"))
        events_map = claims.get("events", {})
        if not subject_id or not isinstance(events_map, dict):
            raise TokenVerificationError("SSF SET missing subject_id or events object")

        matched_events = [uri for uri in events_map if uri in SUPPORTED_SSF_REVOKE_URIS]
        revoked_total = 0
        if matched_events:
            revoked_total = self._revocation.revoke_all_for_subject(
                subject_id, f"ssf_caep:{matched_events[0].rsplit('/', 1)[-1]}"
            )
        self._dedup.put(set_jti, True)
        self._sli.inc_counter(
            "aegis_ssf_events_processed_total",
            1.0,
            {"matched": str(bool(matched_events)).lower()},
        )
        rec = self._audit.append(
            tenant_id=tenant_id,
            event_type=AuditEventType.SSF_SECURITY_EVENT_PROCESSED,
            human_subject=subject_id,
            actor_id="openid_ssf_receiver",
            jti=set_jti,
            decision="REVOKE",
            detail={
                "matched_events": matched_events,
                "revoked_delegated_tokens": revoked_total,
            },
        )
        return {
            "status": "processed",
            "jti": set_jti,
            "subject_id": subject_id,
            "revoked_tokens": revoked_total,
            "audit_entry_hash": rec.entry_hash,
        }
