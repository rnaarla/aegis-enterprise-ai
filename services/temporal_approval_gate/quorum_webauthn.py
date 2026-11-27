"""Project 7 V2: WebAuthn/FIDO2 Passkey Step-Up, Zero-Knowledge Temporal Codec & Teams Cards."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from collections.abc import Sequence
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict
from temporalio.api.common.v1 import Payload
from temporalio.converter import PayloadCodec

WEBAUTHN_FLAG_UP = 0x01  # User Present
WEBAUTHN_FLAG_UV = 0x04  # User Verified (Hardware Biometric / PIN)


class WebAuthnStepUpAssertion(BaseModel):
    """W3C WebAuthn `AuthenticatorAssertionResponse` payload bound to an ERP approval."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    credential_id: str
    authenticator_data_b64: str
    client_data_json_b64: str
    signature_b64: str


def compute_approval_challenge(workflow_id: str, payload_hash: str, snapshot_etag: str) -> str:
    """Compute canonical base64url challenge binding passkey assertion to exact ERP state."""
    digest = hashlib.sha256(
        f"{workflow_id}|{payload_hash}|{snapshot_etag}".encode()
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def mint_webauthn_stepup_assertion(
    *,
    private_key_pem: bytes,
    credential_id: str,
    rp_id: str,
    origin: str,
    workflow_id: str,
    payload_hash: str,
    snapshot_etag: str,
    sign_count: int = 1,
    user_verified: bool = True,
) -> WebAuthnStepUpAssertion:
    """Generate a standards-compliant W3C WebAuthn ES256 assertion (for tests & hardware twins)."""
    challenge = compute_approval_challenge(workflow_id, payload_hash, snapshot_etag)
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": challenge, "origin": origin},
        separators=(",", ":"),
    ).encode("utf-8")
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = WEBAUTHN_FLAG_UP | (WEBAUTHN_FLAG_UV if user_verified else 0)
    auth_data = rp_id_hash + struct.pack(">BI", flags, sign_count)

    signed_payload = auth_data + hashlib.sha256(client_data).digest()
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey):
        raise TypeError("WebAuthn ES256 requires P-256 private key")
    sig = priv.sign(signed_payload, ec.ECDSA(hashes.SHA256()))

    return WebAuthnStepUpAssertion(
        credential_id=credential_id,
        authenticator_data_b64=base64.urlsafe_b64encode(auth_data).rstrip(b"=").decode("ascii"),
        client_data_json_b64=base64.urlsafe_b64encode(client_data).rstrip(b"=").decode("ascii"),
        signature_b64=base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii"),
    )


def _b64url_decode(val: str) -> bytes:
    pad = "=" * ((4 - len(val) % 4) % 4)
    return base64.urlsafe_b64decode(val + pad)


def verify_webauthn_stepup_assertion(
    assertion: WebAuthnStepUpAssertion,
    *,
    public_key_pem: bytes,
    expected_rp_id: str,
    expected_origin: str,
    workflow_id: str,
    payload_hash: str,
    snapshot_etag: str,
) -> None:
    """Verify W3C WebAuthn ES256 signature, `rpIdHash`, `UV=1` biometric flag, and challenge."""
    auth_data = _b64url_decode(assertion.authenticator_data_b64)
    if len(auth_data) < 37:
        raise PermissionError("Malformed WebAuthn authenticatorData (< 37 bytes)")

    expected_rp_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
    if auth_data[:32] != expected_rp_hash:
        raise PermissionError("WebAuthn rpIdHash mismatch")

    flags = auth_data[32]
    if not (flags & WEBAUTHN_FLAG_UP) or not (flags & WEBAUTHN_FLAG_UV):
        raise PermissionError("WebAuthn hardware UserVerification (UV=1) biometric flag required")

    client_bytes = _b64url_decode(assertion.client_data_json_b64)
    client_obj: dict[str, Any] = json.loads(client_bytes.decode("utf-8"))
    if client_obj.get("type") != "webauthn.get":
        raise PermissionError("Invalid WebAuthn ceremony type")
    if client_obj.get("origin") != expected_origin:
        raise PermissionError("WebAuthn origin mismatch")

    expected_chal = compute_approval_challenge(workflow_id, payload_hash, snapshot_etag)
    if client_obj.get("challenge") != expected_chal:
        raise PermissionError("WebAuthn challenge does not match workflow payload/ETag digest")

    pub = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise PermissionError("Registered passkey is not ECDSA P-256")
    sig = _b64url_decode(assertion.signature_b64)
    signed_bytes = auth_data + hashlib.sha256(client_bytes).digest()
    try:
        pub.verify(sig, signed_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise PermissionError("WebAuthn FIDO2 signature verification failed") from exc


class AESGCMPayloadCodec(PayloadCodec):
    """Zero-Knowledge Temporal `PayloadCodec` encrypting workflow histories via AES-256-GCM."""

    ENCODING = b"binary/aegis-aes256gcm"

    def __init__(self, key: bytes, *, key_id: str = "kms-kek-v1") -> None:
        if len(key) != 32:
            raise ValueError("AESGCMPayloadCodec requires a 32-byte key")
        self._aead = AESGCM(key)
        self._key_id = key_id.encode("utf-8")

    async def encode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out: list[Payload] = []
        for p in payloads:
            raw = p.SerializeToString()
            nonce = os.urandom(12)
            ct = self._aead.encrypt(nonce, raw, self._key_id)
            out.append(
                Payload(
                    metadata={"encoding": self.ENCODING, "key_id": self._key_id},
                    data=nonce + ct,
                )
            )
        return out

    async def decode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out: list[Payload] = []
        for p in payloads:
            if p.metadata.get("encoding") != self.ENCODING:
                out.append(p)
                continue
            key_id = p.metadata.get("key_id", b"")
            nonce, ct = p.data[:12], p.data[12:]
            pt = self._aead.decrypt(nonce, ct, key_id)
            restored = Payload()
            restored.ParseFromString(pt)
            out.append(restored)
        return out


def build_teams_adaptive_card(
    *,
    workflow_id: str,
    requester_sub: str,
    vendor_id: str,
    amount_usd: float,
    required_quorum: int,
) -> dict[str, Any]:
    """Build Microsoft Teams Adaptive Card v1.5 payload for omnichannel enterprise sign-off."""
    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.5",
        "body": [
            {
                "type": "TextBlock",
                "size": "Large",
                "weight": "Bolder",
                "text": f"SAP PO Approval Required: USD {amount_usd:,.2f} ({required_quorum}-of-N Quorum)",
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Workflow ID", "value": workflow_id},
                    {"title": "Requester", "value": requester_sub},
                    {"title": "SAP Vendor", "value": vendor_id},
                ],
            },
        ],
        "actions": [
            {"type": "Action.Submit", "title": "Approve (FIDO2)", "data": {"wf": workflow_id, "act": "approve"}},
            {"type": "Action.Submit", "title": "Reject", "data": {"wf": workflow_id, "act": "reject"}},
        ],
    }
