"""Strictly typed domain models for Aegis Enterprise AI Control & Data Plane."""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ClearanceLevel(IntEnum):
    """Mandatory Access Control (MAC) hierarchical security clearance levels."""

    PUBLIC = 0
    INTERNAL = 10
    CONFIDENTIAL = 20
    RESTRICTED = 30
    TOP_SECRET_MA = 40


class DocumentClassification(StrEnum):
    """Human-readable classification labels mapped deterministically to ClearanceLevel."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TOP_SECRET_MA = "TOP_SECRET_MA"  # noqa: S105

    def to_clearance(self) -> ClearanceLevel:
        return ClearanceLevel[self.value]


class AuditEventType(StrEnum):
    """Canonical security and operational audit event taxonomy."""

    TOKEN_EXCHANGED = "oauth.token_exchange.issued"  # noqa: S105
    TOKEN_EXCHANGE_DENIED = "oauth.token_exchange.denied"  # noqa: S105
    TOKEN_REVOKED = "oauth.token.revoked"  # noqa: S105
    AGENT_SUBDELEGATED = "oauth.token_exchange.subdelegated"
    AGENT_KILLSWITCH = "oauth.agent.killswitch"
    SSF_SECURITY_EVENT_PROCESSED = "oauth.ssf.security_event"
    KEYRING_ROTATED = "oauth.keyring.rotated"
    RAG_RETRIEVAL_EXECUTED = "rag.retrieval.executed"
    RAG_RETRIEVAL_DENIED = "rag.retrieval.denied"
    PII_MASKED = "pii.proxy.masked"
    PII_UNMASKED = "pii.proxy.unmasked"
    PII_EXFILTRATION_BLOCKED = "pii.proxy.exfiltration_blocked"
    TEMPORAL_GATE_PAUSED = "temporal.approval.paused"
    TEMPORAL_GATE_DECIDED = "temporal.approval.decided"
    LEGACY_BATCH_INGESTED = "ingestor.legacy.completed"
    EDGE_TRIAGE_ROUTED = "edge.triage.routed"
    PROMPT_VERSION_PROMOTED = "control_plane.prompt.promoted"
    CANARY_AUTO_ROLLED_BACK = "control_plane.canary.rolled_back"
    DUAL_CONTROL_APPROVED = "control_plane.dual_control.approved"


class AuthorizationDetail(BaseModel):
    """RFC 9396 Rich Authorization Request (RAR) structured fine-grained permission object."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: Literal["sap_po", "rag_corpus", "admin_mutation"]
    actions: tuple[str, ...] = ()
    max_amount_usd: float | None = Field(default=None, ge=0.0)
    allowed_cost_centers: tuple[str, ...] = ()
    allowed_sources: tuple[str, ...] = ()


class HumanPrincipal(BaseModel):
    """Verified upstream human identity resolved from OIDC or SAML 2.0 assertion."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str = Field(min_length=2, max_length=64)
    subject_id: str = Field(min_length=2, max_length=128)
    email: str = Field(min_length=3, max_length=256)
    display_name: str = Field(min_length=1, max_length=128)
    department: str = Field(min_length=1, max_length=64)
    groups: tuple[str, ...]
    scopes: tuple[str, ...]
    clearance: ClearanceLevel
    po_approval_limit_usd: int = Field(ge=0)
    auth_method: Literal["oidc", "saml2"]
    upstream_session_id: str = Field(min_length=4, max_length=128)


class AgentManifest(BaseModel):
    """Registered non-human agent identity & maximum capability boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str = Field(min_length=3, max_length=128)
    spiffe_id: str = Field(pattern=r"^spiffe://[a-z0-9.-]+/agent/[a-z0-9-]+$")
    display_name: str = Field(min_length=2, max_length=128)
    allowed_scopes: tuple[str, ...]
    max_clearance: ClearanceLevel
    max_ttl_seconds: int = Field(ge=30, le=300, default=300)
    owner_team: str = Field(min_length=2, max_length=64)
    active: bool = True


class ActorClaim(BaseModel):
    """RFC 8693 Section 4.1 `act` (Actor) claim supporting nested multi-hop delegation chains."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sub: str = Field(description="SPIFFE ID of the acting non-human agent")
    client_id: str = Field(description="Registered agent client identifier")
    act: ActorClaim | None = Field(
        default=None,
        description="Optional parent actor chain when an orchestrator delegates to a subagent",
    )

    def chain_spiffe_ids(self) -> tuple[str, ...]:
        """Return ordered `(current_actor, parent_actor, ...)` SPIFFE IDs for cycle checks."""
        if self.act is None:
            return (self.sub,)
        return (self.sub, *self.act.chain_spiffe_ids())


ActorClaim.model_rebuild()


class DelegatedTokenClaims(BaseModel):
    """Verified claims extracted from an Aegis RFC 8693 delegated agent JWT."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iss: str
    sub: str
    aud: tuple[str, ...]
    exp: int
    iat: int
    nbf: int
    jti: str
    tenant_id: str
    email: str
    department: str
    groups: tuple[str, ...]
    scopes: tuple[str, ...]
    clearance: ClearanceLevel
    po_approval_limit_usd: int = Field(ge=0)
    act: ActorClaim
    cnf_jkt: str | None = None
    cnf_x5t_s256: str | None = None
    authorization_details: tuple[AuthorizationDetail, ...] = ()
    delegation_depth: int = Field(default=1, ge=1, le=3)


class TokenExchangeRequest(BaseModel):
    """OAuth 2.0 Token Exchange (RFC 8693) + RFC 9396 RAR + RFC 8705 mTLS request payload."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    grant_type: Literal["urn:ietf:params:oauth:grant-type:token-exchange"] = (
        "urn:ietf:params:oauth:grant-type:token-exchange"
    )
    subject_token: str = Field(min_length=16)
    subject_token_type: Literal[
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:saml2",
    ]
    agent_id: str = Field(min_length=3, max_length=128)
    audience: str = Field(default="aegis-data-plane", min_length=3, max_length=128)
    requested_scopes: list[str] = Field(min_length=1)
    requested_ttl_seconds: int = Field(default=300, ge=30, le=300)
    dpop_jkt: str | None = Field(default=None, max_length=128)
    mtls_cert_thumbprint_s256: str | None = Field(default=None, max_length=128)
    authorization_details: list[AuthorizationDetail] = Field(default_factory=list)


class TokenExchangeResponse(BaseModel):
    """OAuth 2.0 Token Exchange (RFC 8693 Section 2.2.1) response payload."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    access_token: str
    issued_token_type: Literal["urn:ietf:params:oauth:token-type:access_token"] = (
        "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105
    )
    token_type: Literal["Bearer", "DPoP"] = "Bearer"  # noqa: S105
    expires_in: int = Field(ge=1, le=300)
    scope: str
    jti: str
    effective_clearance: ClearanceLevel
    narrowed_out_scopes: list[str]
    audit_entry_hash: str
    authorization_details: list[AuthorizationDetail] = Field(default_factory=list)
    delegation_depth: int = Field(default=1, ge=1, le=3)


class ReBACTuple(BaseModel):
    """Zanzibar-style Relationship-Based Access Control tuple with explicit DENY support."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    object_id: str
    relation: Literal["viewer", "editor", "owner", "ethical_wall_deny"]
    subject_type: Literal["user", "group"]
    subject_id: str


class ReBACGroupHierarchyEdge(BaseModel):
    """Transitive Zanzibar group/deal-room hierarchy edge (`parent_group` includes `child_id`)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    parent_group: str = Field(min_length=2, max_length=128)
    child_type: Literal["user", "group"]
    child_id: str = Field(min_length=2, max_length=128)


class DocumentChunk(BaseModel):
    """Normalized, access-controlled document chunk stored in PostgreSQL RLS store."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    chunk_id: str
    document_id: str
    tenant_id: str
    title: str
    source_uri: str
    source_system: Literal[
        "sharepoint_ma",
        "cobol_core_banking",
        "sap_procurement",
        "policy_kb",
        "swift_iso20022",
    ]
    page_or_record_ref: str
    classification: DocumentClassification
    clearance_required: ClearanceLevel
    content: str
    department_owner: str


class ScoredChunk(BaseModel):
    """Authorized chunk returned from kernel-enforced hybrid search with provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    chunk_id: str
    document_id: str
    title: str
    source_uri: str
    source_system: str
    page_or_record_ref: str
    classification: DocumentClassification
    content: str
    dense_score: float
    lexical_score: float
    rrf_score: float
    rerank_score: float | None = None


class SecurityReceipt(BaseModel):
    """Cryptographic & database-level proof of how a retrieval request was enforced."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    jti: str
    human_subject: str
    actor_spiffe_id: str
    tenant_id: str
    effective_clearance: ClearanceLevel
    db_execution_role: str
    rls_forced: bool
    audit_entry_hash: str
    evaluated_at: datetime


class RetrievalQuery(BaseModel):
    """RAG query payload. Note: NO user_id or clearance fields accepted from client body!"""

    model_config = ConfigDict(frozen=True, extra="forbid")

    query: str = Field(min_length=2, max_length=2000)
    top_k: int = Field(default=5, ge=1, le=25)
    enable_reranker: bool = True


class RetrievalResponse(BaseModel):
    """RAG retrieval response carrying authorized chunks and cryptographic security receipt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    query: str
    results: list[ScoredChunk]
    security_receipt: SecurityReceipt


class AuditRecord(BaseModel):
    """Immutable hash-chained audit ledger entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence_id: int
    occurred_at: datetime
    tenant_id: str
    event_type: AuditEventType
    human_subject: str
    actor_id: str
    jti: str | None
    decision: Literal["ALLOW", "DENY", "REVOKE"]
    detail: dict[str, str | int | float | bool | list[str]]
    prev_hash: str
    entry_hash: str
