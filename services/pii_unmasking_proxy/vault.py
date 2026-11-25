"""HKDF-SHA256 + AES-256-GCM envelope-encrypted deterministic PII vault ($O(S_{\\max})$ space)."""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aegis_core.dsa import BoundedLRUTTLCache


@dataclass(frozen=True)
class EncryptedVaultEntry:
    surrogate_tag: str
    entity_type: str
    nonce: bytes
    ciphertext: bytes


@dataclass
class _SessionVaultBucket:
    dek: bytes
    counters: dict[str, int] = field(default_factory=dict)
    hmac_to_tag: dict[str, str] = field(default_factory=dict)
    tag_to_entry: dict[str, EncryptedVaultEntry] = field(default_factory=dict)
    surname_to_tag: dict[str, str] = field(default_factory=dict)


class EnvelopeEncryptedPIIVault:
    """Bounded-memory AES-256-GCM session vault with $O(1)$ lookup & LRU+TTL session eviction."""

    def __init__(
        self,
        master_kek: bytes | None = None,
        *,
        max_sessions: int = 10_000,
        session_ttl_seconds: float = 3_600.0,
    ) -> None:
        self._kek = master_kek if master_kek is not None else os.urandom(32)
        if len(self._kek) != 32:
            raise ValueError("Master KEK must be 256 bits (32 bytes)")
        self._lock = threading.RLock()
        self._sessions: BoundedLRUTTLCache[str, _SessionVaultBucket] = BoundedLRUTTLCache(
            max_size=max_sessions,
            default_ttl_seconds=session_ttl_seconds,
        )

    def _get_or_create_bucket_locked(self, session_id: str) -> _SessionVaultBucket:
        bucket = self._sessions.get(session_id)
        if bucket is not None:
            return bucket
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"aegis-pii-vault-v1",
            info=f"session:{session_id}".encode(),
        )
        bucket = _SessionVaultBucket(dek=hkdf.derive(self._kek))
        self._sessions.put(session_id, bucket)
        return bucket

    def mask_entity(self, *, session_id: str, entity_type: str, raw_value: str) -> str:
        """Allocate or reuse `<TYPE_NNN>` in $O(1)$ time with AES-256-GCM AAD encryption."""
        normalized = raw_value.strip()
        with self._lock:
            bucket = self._get_or_create_bucket_locked(session_id)

            if entity_type == "PERSON":
                parts = normalized.replace(".", "").split()
                if len(parts) == 2 and parts[0].lower() in ("mr", "ms", "mrs", "dr"):
                    surname = parts[1].lower()
                    if surname in bucket.surname_to_tag:
                        return bucket.surname_to_tag[surname]

            lookup_mac = hmac.new(
                bucket.dek,
                f"{entity_type}:{normalized}".encode(),
                hashlib.sha256,
            ).hexdigest()
            existing = bucket.hmac_to_tag.get(lookup_mac)
            if existing is not None:
                return existing

            idx = bucket.counters.get(entity_type, 0) + 1
            bucket.counters[entity_type] = idx
            tag = f"<{entity_type}_{idx:03d}>"

            nonce = os.urandom(12)
            aad = f"{session_id}|{tag}|{entity_type}".encode()
            ciphertext = AESGCM(bucket.dek).encrypt(nonce, normalized.encode("utf-8"), aad)

            bucket.hmac_to_tag[lookup_mac] = tag
            bucket.tag_to_entry[tag] = EncryptedVaultEntry(
                surrogate_tag=tag,
                entity_type=entity_type,
                nonce=nonce,
                ciphertext=ciphertext,
            )

            if entity_type == "PERSON":
                words = normalized.split()
                if len(words) >= 2 and words[0].rstrip(".").lower() not in ("mr", "ms", "mrs", "dr"):
                    bucket.surname_to_tag[words[-1].lower()] = tag

            return tag

    def unmask_tag(self, *, session_id: str, surrogate_tag: str) -> str | None:
        """Decrypt `<TYPE_NNN>` in $O(1)$ time using session DEK + AAD verification."""
        with self._lock:
            bucket = self._sessions.get(session_id)
            if bucket is None:
                return None
            entry = bucket.tag_to_entry.get(surrogate_tag)
            if entry is None:
                return None
            dek = bucket.dek

        aad = f"{session_id}|{entry.surrogate_tag}|{entry.entity_type}".encode()
        plaintext = AESGCM(dek).decrypt(entry.nonce, entry.ciphertext, aad)
        return plaintext.decode("utf-8")

    def inspect_raw_ciphertext(self, *, session_id: str, surrogate_tag: str) -> bytes | None:
        with self._lock:
            bucket = self._sessions.get(session_id)
            if bucket is None:
                return None
            entry = bucket.tag_to_entry.get(surrogate_tag)
            return entry.ciphertext if entry is not None else None
