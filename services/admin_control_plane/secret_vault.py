"""AES-256-GCM Envelope-Encrypted Connector Secret Store (Single Responsibility)."""

from __future__ import annotations

import hashlib
import os
import threading
from datetime import UTC, datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict


class MaskedConnectorSecret(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    connector_name: str
    masked_preview: str
    ciphertext_sha256: str
    updated_by: str
    updated_at: datetime


class EnvelopeConnectorSecretStore:
    """Encrypts SAP/IdP connector credentials under KMS KEK and exposes ONLY masked views."""

    def __init__(self, master_kek: bytes | None = None) -> None:
        self._kek = master_kek if master_kek is not None else os.urandom(32)
        if len(self._kek) != 32:
            raise ValueError("Master KEK must be 32 bytes (256 bits)")
        self._lock = threading.RLock()
        self._store: dict[str, tuple[bytes, bytes, MaskedConnectorSecret]] = {}

    def rotate(
        self,
        *,
        tenant_id: str,
        connector_name: str,
        raw_secret: str,
        updated_by: str,
    ) -> MaskedConnectorSecret:
        nonce = os.urandom(12)
        aad = f"{tenant_id}|{connector_name}".encode()
        ct = AESGCM(self._kek).encrypt(nonce, raw_secret.encode("utf-8"), aad)
        ct_hash = hashlib.sha256(ct).hexdigest()
        masked = f"••••••••{raw_secret[-4:]}" if len(raw_secret) >= 8 else "••••••••"
        meta = MaskedConnectorSecret(
            connector_name=connector_name,
            masked_preview=masked,
            ciphertext_sha256=ct_hash,
            updated_by=updated_by,
            updated_at=datetime.now(tz=UTC),
        )
        with self._lock:
            self._store[connector_name] = (nonce, ct, meta)
        return meta
