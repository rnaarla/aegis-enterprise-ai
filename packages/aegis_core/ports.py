"""Hexagonal enterprise port interfaces enabling zero-code Day-1 production cutover."""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from aegis_core.models import (
    AgentManifest,
    AuditEventType,
    AuditRecord,
    DelegatedTokenClaims,
    DocumentChunk,
    HumanPrincipal,
    ReBACTuple,
    ScoredChunk,
)


@runtime_checkable
class IdentityProviderPort(Protocol):
    """Port for validating upstream OIDC JWTs or SAML 2.0 assertions (Keycloak/Okta/Entra)."""

    def verify_subject_token(
        self,
        subject_token: str,
        token_type: Literal[
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:id_token",
            "urn:ietf:params:oauth:token-type:saml2",
        ],
    ) -> HumanPrincipal:
        """Cryptographically validate upstream IdP credential and extract HumanPrincipal."""
        ...


@runtime_checkable
class AgentRegistryPort(Protocol):
    """Port for resolving registered non-human agent manifests and capability ceilings."""

    def get_agent(self, agent_id: str) -> AgentManifest | None:
        """Fetch agent manifest by client ID."""
        ...


@runtime_checkable
class RevocationStorePort(Protocol):
    """Port for sub-millisecond JTI revocation, human session logout, and agent kill-switches."""

    def register_issued_token(
        self,
        jti: str,
        human_subject: str,
        agent_id: str,
        exp_epoch: int,
    ) -> None:
        """Track active delegated token metadata until natural expiration."""
        ...

    def revoke_jti(self, jti: str, exp_epoch: int, reason: str) -> None:
        """Immediately revoke a single delegated JWT by JTI."""
        ...

    def revoke_all_for_subject(self, human_subject: str, reason: str) -> int:
        """Revoke every active delegated token acting on behalf of `human_subject`."""
        ...

    def revoke_all_for_agent(self, agent_id: str, reason: str) -> int:
        """Emergency kill-switch: revoke every active token held by `agent_id`."""
        ...

    def is_revoked(self, jti: str, human_subject: str, agent_id: str) -> tuple[bool, str | None]:
        """Return `(True, reason)` if JTI, human principal, or agent is revoked."""
        ...


@runtime_checkable
class AuditLedgerPort(Protocol):
    """Port for append-only, SHA-256 hash-chained compliance audit logging."""

    def append(
        self,
        *,
        tenant_id: str,
        event_type: AuditEventType,
        human_subject: str,
        actor_id: str,
        jti: str | None,
        decision: Literal["ALLOW", "DENY", "REVOKE"],
        detail: dict[str, str | int | float | bool | list[str]],
    ) -> AuditRecord:
        """Atomically compute `SHA256(prev_hash || payload)` and persist record."""
        ...

    def list_records(self, tenant_id: str | None = None) -> list[AuditRecord]:
        """Return ordered audit records for verification and export."""
        ...

    def verify_integrity(self) -> tuple[bool, str]:
        """Recompute entire SHA-256 chain from genesis to detect tampering or gaps."""
        ...


@runtime_checkable
class EmbeddingProviderPort(Protocol):
    """Port for dense vector embedding generation (in-VPC vLLM, Azure OpenAI, or deterministic)."""

    @property
    def dimension(self) -> int:
        """Vector dimensionality."""
        ...

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Generate L2-normalized dense embeddings for a batch of texts."""
        ...


@runtime_checkable
class RetrievalStorePort(Protocol):
    """Port for kernel-enforced row-level secure hybrid retrieval."""

    def ingest_chunks(
        self,
        chunks: list[DocumentChunk],
        rebac_tuples: list[ReBACTuple],
    ) -> int:
        """Persist chunks and ReBAC access tuples into the underlying store."""
        ...

    def retrieve_authorized(
        self,
        claims: DelegatedTokenClaims,
        query: str,
        top_k: int,
    ) -> tuple[list[ScoredChunk], str, bool]:
        """Execute hybrid search bound strictly to `claims` inside an RLS transaction.

        Returns `(scored_chunks, db_role_used, rls_forced)`.
        """
        ...
