"""Hexagonal enterprise port interfaces & domain boundary errors (Dependency Inversion).

Every microservice in `services/` programs strictly against these `Protocol` interfaces
rather than concrete peer service implementations (`Program to an Interface, not an Implementation`).
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from aegis_core.models import (
    AgentManifest,
    AuditEventType,
    AuditRecord,
    DelegatedTokenClaims,
    DocumentChunk,
    HumanPrincipal,
    JSONRPCRequest,
    ReBACTuple,
    ScoredChunk,
    TokenExchangeRequest,
    TokenExchangeResponse,
)


class DelegationPolicyError(Exception):
    """RFC 6749 / RFC 8693 compliant OAuth/policy boundary error with HTTP status mapping."""

    def __init__(self, oauth_error: str, description: str, status_code: int = 400) -> None:
        super().__init__(description)
        self.oauth_error = oauth_error
        self.description = description
        self.status_code = status_code


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
        ...


@runtime_checkable
class AgentRegistryPort(Protocol):
    """Port for resolving registered non-human agent manifests and capability ceilings."""

    def get_agent(self, agent_id: str) -> AgentManifest | None:
        ...


@runtime_checkable
class TokenVerifierPort(Protocol):
    """Inbound verification port consumed by downstream resource servers (RAG, MCP, PII, Admin)."""

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
        ...


@runtime_checkable
class TokenBrokerPort(TokenVerifierPort, Protocol):
    """Full token exchange + verification port used by orchestrators (e.g. Temporal Gate)."""

    def exchange_token(
        self,
        req: TokenExchangeRequest,
        *,
        dpop_proof_jwt: str | None = None,
        http_method: str = "POST",
        http_url: str = "https://auth.aegis.meridian.fin/v1/oauth/token",
        now_epoch: int | None = None,
    ) -> TokenExchangeResponse:
        ...


@runtime_checkable
class MCPToolCallerPort(Protocol):
    """Port decoupling workflow coordinators (P7) from concrete MCP server implementations (P5)."""

    def handle_jsonrpc(
        self,
        rpc: JSONRPCRequest,
        *,
        bearer_token: str | None,
    ) -> dict[str, Any]:
        ...


@runtime_checkable
class SOAPEnvelopeHandlerPort(Protocol):
    """Port decoupling in-process SOAP test transports from `enterprise_twin` concrete classes."""

    def handle_soap_envelope(self, raw_xml: bytes) -> tuple[int, bytes]:
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
        ...

    def revoke_jti(self, jti: str, exp_epoch: int, reason: str) -> None:
        ...

    def revoke_all_for_subject(self, human_subject: str, reason: str) -> int:
        ...

    def revoke_all_for_agent(self, agent_id: str, reason: str) -> int:
        ...

    def is_revoked(self, jti: str, human_subject: str, agent_id: str) -> tuple[bool, str | None]:
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
        ...

    def verify_integrity(self) -> tuple[bool, str]:
        ...

    def list_records(self) -> list[AuditRecord]:
        ...


@runtime_checkable
class EmbeddingProviderPort(Protocol):
    """Port for deterministic air-gapped or local GPU (`vLLM`/`Infinity`) dense embeddings."""

    @property
    def dimension(self) -> int:
        ...

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        ...


@runtime_checkable
class RetrievalStorePort(Protocol):
    """Port for PostgreSQL `FORCE ROW LEVEL SECURITY` hybrid dense + lexical search."""

    def ingest_chunks(
        self,
        chunks: list[DocumentChunk],
        rebac_tuples: list[ReBACTuple],
    ) -> int:
        ...

    def retrieve_authorized(
        self,
        claims: DelegatedTokenClaims,
        query: str,
        top_k: int,
    ) -> tuple[list[ScoredChunk], str, bool]:
        ...
