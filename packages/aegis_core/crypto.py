"""RFC 8693 JWT, RFC 7517/7638 JWKS, Nested `act` Chains, RAR & Dual-Key Rotation Engine."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from aegis_core.models import (
    ActorClaim,
    AuthorizationDetail,
    ClearanceLevel,
    DelegatedTokenClaims,
    HumanPrincipal,
)

MAX_DELEGATED_TTL_SECONDS = 300
MAX_DELEGATION_DEPTH = 3


class TokenVerificationError(Exception):
    """Raised when a JWT fails signature, expiry, audience, or RFC 8693 structure checks."""


def _b64url_uint(val: int, length: int) -> str:
    raw = val.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def compute_jwk_thumbprint(jwk_core: dict[str, str]) -> str:
    """Compute RFC 7638 SHA-256 JWK thumbprint for deterministic `kid` and `cnf.jkt`."""
    canonical = json.dumps(jwk_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def compute_jwk_thumbprint_from_public_jwk(jwk: dict[str, Any]) -> str:
    """Extract canonical RFC 7638 members from an EC or RSA public JWK and hash."""
    kty = str(jwk.get("kty", ""))
    if kty == "EC":
        return compute_jwk_thumbprint(
            {"crv": str(jwk["crv"]), "kty": "EC", "x": str(jwk["x"]), "y": str(jwk["y"])}
        )
    if kty == "RSA":
        return compute_jwk_thumbprint(
            {"e": str(jwk["e"]), "kty": "RSA", "n": str(jwk["n"])}
        )
    raise ValueError(f"Unsupported JWK kty for RFC 7638 thumbprint: {kty!r}")


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
        kid = compute_jwk_thumbprint({"crv": "P-256", "kty": "EC", "x": x_b64, "y": y_b64})

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
        kid = compute_jwk_thumbprint({"e": e_b64, "kty": "RSA", "n": n_b64})

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


class SigningKeyRing:
    """Zero-downtime dual/multi-key ring supporting seamless `kid` rotation with JWKS grace window."""

    def __init__(
        self,
        initial_key: SigningKeyPair | None = None,
        *,
        max_retained_keys: int = 3,
    ) -> None:
        self._lock = threading.RLock()
        first = initial_key or SigningKeyPair.generate_es256()
        self._keys: deque[SigningKeyPair] = deque([first], maxlen=max(2, max_retained_keys))

    @property
    def active_key(self) -> SigningKeyPair:
        with self._lock:
            return self._keys[0]

    def rotate(self, new_key: SigningKeyPair | None = None) -> SigningKeyPair:
        """Promote a new signing key while retaining previous public keys for verification."""
        nxt = new_key or SigningKeyPair.generate_es256()
        with self._lock:
            self._keys.appendleft(nxt)
            return nxt

    def public_jwks(self) -> dict[str, Any]:
        with self._lock:
            return {"keys": [k.public_jwk for k in self._keys]}


def _parse_actor_claim(raw_act: Any, depth: int = 1) -> tuple[ActorClaim, int]:
    if depth > MAX_DELEGATION_DEPTH:
        raise TokenVerificationError(
            f"Delegation chain depth exceeds enterprise ceiling ({MAX_DELEGATION_DEPTH})"
        )
    if not isinstance(raw_act, dict) or "sub" not in raw_act or "client_id" not in raw_act:
        raise TokenVerificationError("Missing or malformed RFC 8693 'act' claim")
    nested_raw = raw_act.get("act")
    if nested_raw is not None:
        parent_claim, max_d = _parse_actor_claim(nested_raw, depth + 1)
        return (
            ActorClaim(
                sub=str(raw_act["sub"]),
                client_id=str(raw_act["client_id"]),
                act=parent_claim,
            ),
            max_d,
        )
    return ActorClaim(sub=str(raw_act["sub"]), client_id=str(raw_act["client_id"])), depth


def _serialize_actor_claim(act: ActorClaim) -> dict[str, Any]:
    out: dict[str, Any] = {"sub": act.sub, "client_id": act.client_id}
    if act.act is not None:
        out["act"] = _serialize_actor_claim(act.act)
    return out


class JWKSVerifier:
    """Verifies RFC 8693 delegated tokens against a set of trusted public JWKs."""

    def __init__(self, *, issuer: str, expected_audience: str, jwks: dict[str, Any]) -> None:
        self._issuer = issuer
        self._expected_audience = expected_audience
        self._lock = threading.RLock()
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
        with self._lock:
            self._keys_by_kid = parsed

    def verify_delegated_jwt(
        self, token: str, *, now_epoch: int | None = None
    ) -> DelegatedTokenClaims:
        """Cryptographically verify signature, TTL ceiling, audience, RAR, and nested `act`."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenVerificationError(f"Malformed JWT header: {exc}") from exc

        kid = str(header.get("kid", ""))
        with self._lock:
            key_entry = self._keys_by_kid.get(kid)
        if key_entry is None:
            raise TokenVerificationError(f"Unknown signing key id: {kid!r}")

        if header.get("typ") != "at+jwt":
            raise TokenVerificationError("Invalid JWT typ header; expected RFC 9068 'at+jwt'")

        pub_key, alg = key_entry
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

        actor_claim, depth = _parse_actor_claim(payload.get("act"))
        chain_ids = actor_claim.chain_spiffe_ids()
        if len(set(chain_ids)) != len(chain_ids):
            raise TokenVerificationError("Delegation cycle detected in nested RFC 8693 'act' chain")

        scope_str = str(payload.get("scope", "")).strip()
        scopes = tuple(s for s in scope_str.split(" ") if s)
        raw_groups = payload.get("groups", [])
        groups = tuple(str(g) for g in raw_groups) if isinstance(raw_groups, list) else ()

        cnf_jkt: str | None = None
        cnf_x5t: str | None = None
        if isinstance(payload.get("cnf"), dict):
            jkt_val = payload["cnf"].get("jkt")
            if isinstance(jkt_val, str):
                cnf_jkt = jkt_val
            x5t_val = payload["cnf"].get("x5t#S256")
            if isinstance(x5t_val, str):
                cnf_x5t = x5t_val

        raw_rar = payload.get("authorization_details", [])
        rar_details: tuple[AuthorizationDetail, ...] = ()
        if isinstance(raw_rar, list):
            rar_details = tuple(AuthorizationDetail.model_validate(item) for item in raw_rar)

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
            act=actor_claim,
            cnf_jkt=cnf_jkt,
            cnf_x5t_s256=cnf_x5t,
            authorization_details=rar_details,
            delegation_depth=depth,
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
    mtls_cert_thumbprint_s256: str | None = None,
    authorization_details: tuple[AuthorizationDetail, ...] = (),
    parent_actor: ActorClaim | None = None,
    max_exp_epoch: int | None = None,
    now_epoch: int | None = None,
) -> tuple[str, str, int]:
    """Mint an RFC 8693 + RFC 9068 (`at+jwt`) short-lived delegated agent token."""
    if ttl_seconds < 1 or ttl_seconds > MAX_DELEGATED_TTL_SECONDS:
        raise ValueError(f"TTL must be between 1 and {MAX_DELEGATED_TTL_SECONDS} seconds")

    iat = now_epoch if now_epoch is not None else int(time.time())
    exp = iat + ttl_seconds
    if max_exp_epoch is not None:
        exp = min(exp, max_exp_epoch)
    if exp <= iat:
        raise ValueError("Parent token already expired; cannot subdelegate")

    actor = ActorClaim(sub=agent_spiffe_id, client_id=agent_client_id, act=parent_actor)
    chain = actor.chain_spiffe_ids()
    if len(chain) > MAX_DELEGATION_DEPTH:
        raise ValueError(f"Subdelegation exceeds max depth ({MAX_DELEGATION_DEPTH})")
    if len(set(chain)) != len(chain):
        raise ValueError("Subdelegation cycle forbidden: agent already present in act chain")

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
        "act": _serialize_actor_claim(actor),
    }
    cnf: dict[str, str] = {}
    if dpop_jkt:
        cnf["jkt"] = dpop_jkt
    if mtls_cert_thumbprint_s256:
        cnf["x5t#S256"] = mtls_cert_thumbprint_s256
    if cnf:
        claims["cnf"] = cnf
    if authorization_details:
        claims["authorization_details"] = [d.model_dump(exclude_none=True) for d in authorization_details]

    encoded = jwt.encode(
        payload=claims,
        key=signing_key.private_pem,
        algorithm=signing_key.algorithm,
        headers={"kid": signing_key.kid, "typ": "at+jwt"},
    )
    return encoded, jti, exp
