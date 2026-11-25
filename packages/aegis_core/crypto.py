"""RFC 8693 JWT & RFC 7517/7638 JWKS cryptographic engine (ES256 & RS256)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from aegis_core.models import (
    ActorClaim,
    ClearanceLevel,
    DelegatedTokenClaims,
    HumanPrincipal,
)

MAX_DELEGATED_TTL_SECONDS = 300


class TokenVerificationError(Exception):
    """Raised when a JWT fails signature, expiry, audience, or RFC 8693 structure checks."""


def _b64url_uint(val: int, length: int) -> str:
    raw = val.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _compute_jwk_thumbprint(jwk_core: dict[str, str]) -> str:
    """Compute RFC 7638 SHA-256 JWK thumbprint for deterministic `kid`."""
    canonical = json.dumps(jwk_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SigningKeyPair:
    """Asymmetric keypair (ES256 or RS256) with RFC 7517 public JWK export."""

    kid: str
    algorithm: str
    private_pem: bytes
    public_pem: bytes
    public_jwk: dict[str, Any]

    @classmethod
    def generate_es256(cls) -> SigningKeyPair:
        """Generate an ECDSA P-256 (ES256) signing keypair for fast, compact agent JWTs."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()
        x_b64 = _b64url_uint(numbers.x, 32)
        y_b64 = _b64url_uint(numbers.y, 32)
        kid = _compute_jwk_thumbprint({"crv": "P-256", "kty": "EC", "x": x_b64, "y": y_b64})

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        jwk: dict[str, Any] = {
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
            "x": x_b64,
            "y": y_b64,
        }
        return cls(
            kid=kid,
            algorithm="ES256",
            private_pem=private_pem,
            public_pem=public_pem,
            public_jwk=jwk,
        )

    @classmethod
    def generate_rs256(cls) -> SigningKeyPair:
        """Generate an RSA-2048 (RS256) signing keypair (standard enterprise OIDC IdP format)."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()
        n_len = (numbers.n.bit_length() + 7) // 8
        e_len = (numbers.e.bit_length() + 7) // 8
        n_b64 = _b64url_uint(numbers.n, n_len)
        e_b64 = _b64url_uint(numbers.e, e_len)
        kid = _compute_jwk_thumbprint({"e": e_b64, "kty": "RSA", "n": n_b64})

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        jwk: dict[str, Any] = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n_b64,
            "e": e_b64,
        }
        return cls(
            kid=kid,
            algorithm="RS256",
            private_pem=private_pem,
            public_pem=public_pem,
            public_jwk=jwk,
        )


class JWKSVerifier:
    """Verifies RFC 8693 delegated tokens against a set of trusted public JWKs."""

    def __init__(self, *, issuer: str, expected_audience: str, jwks: dict[str, Any]) -> None:
        self._issuer = issuer
        self._expected_audience = expected_audience
        self._keys_by_kid: dict[str, tuple[Any, str]] = {}
        self.reload_jwks(jwks)

    def reload_jwks(self, jwks: dict[str, Any]) -> None:
        raw_keys = jwks.get("keys", [])
        if not isinstance(raw_keys, list):
            raise ValueError("Invalid JWKS payload: 'keys' must be a list")
        parsed: dict[str, tuple[Any, str]] = {}
        for item in raw_keys:
            if not isinstance(item, dict):
                continue
            kid = str(item.get("kid", ""))
            alg = str(item.get("alg", ""))
            jwk_json = json.dumps(item)
            if alg == "ES256":
                pub_key: Any = jwt.algorithms.ECAlgorithm.from_jwk(jwk_json)
            elif alg == "RS256":
                pub_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_json)
            else:
                continue
            if kid:
                parsed[kid] = (pub_key, alg)
        self._keys_by_kid = parsed

    def verify_delegated_jwt(
        self, token: str, *, now_epoch: int | None = None
    ) -> DelegatedTokenClaims:
        """Cryptographically verify signature, TTL ceiling, audience, and RFC 8693 `act` claim."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"Malformed JWT header: {exc}") from exc

        kid = str(header.get("kid", ""))
        if kid not in self._keys_by_kid:
            raise TokenVerificationError(f"Unknown signing key id: {kid!r}")

        if header.get("typ") != "at+jwt":
            raise TokenVerificationError("Invalid JWT typ header; expected RFC 9068 'at+jwt'")

        pub_key, alg = self._keys_by_kid[kid]
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                key=pub_key,
                algorithms=[alg],
                issuer=self._issuer,
                audience=self._expected_audience,
                options={
                    "require": ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "act"],
                    "verify_exp": now_epoch is None,
                    "verify_nbf": now_epoch is None,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"JWT cryptographic validation failed: {exc}") from exc

        check_ts = now_epoch if now_epoch is not None else int(time.time())
        exp = int(payload["exp"])
        iat = int(payload["iat"])
        nbf = int(payload["nbf"])

        if check_ts >= exp:
            raise TokenVerificationError("Delegated JWT has expired")
        if check_ts < nbf - 5:
            raise TokenVerificationError("Delegated JWT is not yet valid (nbf)")
        if (exp - iat) > MAX_DELEGATED_TTL_SECONDS:
            raise TokenVerificationError(
                f"Delegated token TTL ({exp - iat}s) violates 300s enterprise ceiling"
            )

        raw_aud = payload["aud"]
        aud_tuple = (raw_aud,) if isinstance(raw_aud, str) else tuple(str(x) for x in raw_aud)

        raw_act = payload.get("act")
        if not isinstance(raw_act, dict) or "sub" not in raw_act or "client_id" not in raw_act:
            raise TokenVerificationError("Missing or malformed RFC 8693 'act' claim")

        scope_str = str(payload.get("scope", "")).strip()
        scopes = tuple(s for s in scope_str.split(" ") if s)
        raw_groups = payload.get("groups", [])
        groups = tuple(str(g) for g in raw_groups) if isinstance(raw_groups, list) else ()

        cnf_jkt: str | None = None
        if isinstance(payload.get("cnf"), dict):
            jkt_val = payload["cnf"].get("jkt")
            if isinstance(jkt_val, str):
                cnf_jkt = jkt_val

        return DelegatedTokenClaims(
            iss=str(payload["iss"]),
            sub=str(payload["sub"]),
            aud=aud_tuple,
            exp=exp,
            iat=iat,
            nbf=nbf,
            jti=str(payload["jti"]),
            tenant_id=str(payload["tenant_id"]),
            email=str(payload["email"]),
            department=str(payload["department"]),
            groups=groups,
            scopes=scopes,
            clearance=ClearanceLevel(int(payload["clearance"])),
            po_approval_limit_usd=int(payload.get("po_approval_limit_usd", 0)),
            act=ActorClaim(sub=str(raw_act["sub"]), client_id=str(raw_act["client_id"])),
            cnf_jkt=cnf_jkt,
        )


def mint_delegated_jwt(
    *,
    signing_key: SigningKeyPair,
    issuer: str,
    audience: str,
    principal: HumanPrincipal,
    agent_spiffe_id: str,
    agent_client_id: str,
    effective_scopes: tuple[str, ...],
    effective_clearance: ClearanceLevel,
    ttl_seconds: int,
    dpop_jkt: str | None = None,
    now_epoch: int | None = None,
) -> tuple[str, str, int]:
    """Mint an RFC 8693 + RFC 9068 (`at+jwt`) short-lived delegated agent token.

    Returns `(signed_jwt, jti, exp_epoch)`.
    """
    if ttl_seconds < 1 or ttl_seconds > MAX_DELEGATED_TTL_SECONDS:
        raise ValueError(f"TTL must be between 1 and {MAX_DELEGATED_TTL_SECONDS} seconds")

    iat = now_epoch if now_epoch is not None else int(time.time())
    exp = iat + ttl_seconds
    jti = str(uuid.uuid4())

    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": principal.subject_id,
        "aud": [audience],
        "iat": iat,
        "nbf": iat,
        "exp": exp,
        "jti": jti,
        "tenant_id": principal.tenant_id,
        "email": principal.email,
        "department": principal.department,
        "groups": list(principal.groups),
        "scope": " ".join(effective_scopes),
        "clearance": int(effective_clearance),
        "po_approval_limit_usd": principal.po_approval_limit_usd,
        "act": {
            "sub": agent_spiffe_id,
            "client_id": agent_client_id,
        },
    }
    if dpop_jkt:
        claims["cnf"] = {"jkt": dpop_jkt}

    encoded = jwt.encode(
        payload=claims,
        key=signing_key.private_pem,
        algorithm=signing_key.algorithm,
        headers={"kid": signing_key.kid, "typ": "at+jwt"},
    )
    return encoded, jti, exp
