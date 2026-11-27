"""Unit tests for ES256/RS256 RFC 8693 cryptography and SHA-256 hash-chained audit ledger."""

from __future__ import annotations

import jwt
import pytest
from enterprise_twin.idp_seed.meridian_idp import MERIDIAN_PERSONAS

from aegis_core.audit import InMemoryAuditLedger, verify_records_chain
from aegis_core.crypto import (
    JWKSVerifier,
    SigningKeyPair,
    TokenVerificationError,
    mint_delegated_jwt,
)
from aegis_core.models import AuditEventType, AuditRecord, ClearanceLevel

pytestmark = pytest.mark.unit


def test_es256_and_rs256_rfc8693_roundtrip_and_key_rotation() -> None:
    es_key = SigningKeyPair.generate_es256()
    rs_key = SigningKeyPair.generate_rs256()
    verifier = JWKSVerifier(
        issuer="https://auth.meridian.fin",
        expected_audience="aegis-data-plane",
        jwks={"keys": [es_key.public_jwk, rs_key.public_jwk]},
    )

    principal = MERIDIAN_PERSONAS["elena.vance"]
    for key in (es_key, rs_key):
        tok, jti, _ = mint_delegated_jwt(
            signing_key=key,
            issuer="https://auth.meridian.fin",
            audience="aegis-data-plane",
            principal=principal,
            agent_spiffe_id="spiffe://meridian.fin/agent/meridian-ma-copilot",
            agent_client_id="meridian-ma-copilot",
            effective_scopes=("rag:read", "ma:valuation:read"),
            effective_clearance=ClearanceLevel.TOP_SECRET_MA,
            ttl_seconds=300,
            dpop_jkt="thumbprint-xyz",
            now_epoch=1_760_000_000,
        )
        claims = verifier.verify_delegated_jwt(tok, now_epoch=1_760_000_120)
        assert claims.jti == jti
        assert claims.sub == "elena.vance"
        assert claims.act.sub == "spiffe://meridian.fin/agent/meridian-ma-copilot"
        assert claims.clearance == ClearanceLevel.TOP_SECRET_MA
        assert claims.cnf_jkt == "thumbprint-xyz"


def test_rejects_excessive_ttl_and_expired_jwt() -> None:
    key = SigningKeyPair.generate_es256()
    principal = MERIDIAN_PERSONAS["marcus.chen"]

    with pytest.raises(ValueError, match="TTL must be between"):
        mint_delegated_jwt(
            signing_key=key,
            issuer="https://auth.meridian.fin",
            audience="aegis-data-plane",
            principal=principal,
            agent_spiffe_id="spiffe://meridian.fin/agent/meridian-ma-copilot",
            agent_client_id="meridian-ma-copilot",
            effective_scopes=("rag:read",),
            effective_clearance=ClearanceLevel.INTERNAL,
            ttl_seconds=301,
        )

    # Craft a forged 3600s token signed with the real key to verify JWKSVerifier also enforces <=300s
    forged_long_lived = jwt.encode(
        payload={
            "iss": "https://auth.meridian.fin",
            "sub": "marcus.chen",
            "aud": ["aegis-data-plane"],
            "iat": 1_760_000_000,
            "nbf": 1_760_000_000,
            "exp": 1_760_003_600,
            "jti": "forged-1",
            "tenant_id": "meridian-fin",
            "email": "marcus.chen@meridian.fin",
            "department": "EQUITY_RESEARCH",
            "groups": ["all-employees"],
            "scope": "rag:read",
            "clearance": 10,
            "act": {"sub": "spiffe://meridian.fin/agent/bot", "client_id": "bot"},
        },
        key=key.private_pem,
        algorithm="ES256",
        headers={"kid": key.kid, "typ": "at+jwt"},
    )
    verifier = JWKSVerifier(
        issuer="https://auth.meridian.fin",
        expected_audience="aegis-data-plane",
        jwks={"keys": [key.public_jwk]},
    )
    with pytest.raises(TokenVerificationError, match="violates 300s enterprise ceiling"):
        verifier.verify_delegated_jwt(forged_long_lived, now_epoch=1_760_000_010)


def test_audit_hash_chain_detects_payload_modification_and_deletion() -> None:
    ledger = InMemoryAuditLedger()
    for idx in range(3):
        ledger.append(
            tenant_id="meridian-fin",
            event_type=AuditEventType.TOKEN_EXCHANGED,
            human_subject=f"user-{idx}",
            actor_id="spiffe://meridian.fin/agent/meridian-ma-copilot",
            jti=f"jti-{idx}",
            decision="ALLOW",
            detail={"step": idx},
        )
    valid, _ = ledger.verify_integrity()
    assert valid is True

    records = ledger.list_records()
    tampered_middle = AuditRecord(
        sequence_id=records[1].sequence_id,
        occurred_at=records[1].occurred_at,
        tenant_id=records[1].tenant_id,
        event_type=records[1].event_type,
        human_subject="attacker-modified",
        actor_id=records[1].actor_id,
        jti=records[1].jti,
        decision=records[1].decision,
        detail=records[1].detail,
        prev_hash=records[1].prev_hash,
        entry_hash=records[1].entry_hash,
    )
    ok_tampered, msg_tampered = verify_records_chain([records[0], tampered_middle, records[2]])
    assert ok_tampered is False
    assert "hash mismatch" in msg_tampered

    ok_deleted, msg_deleted = verify_records_chain([records[0], records[2]])
    assert ok_deleted is False
    assert "Sequence gap" in msg_deleted
