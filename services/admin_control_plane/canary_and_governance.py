"""Project 12 V2: Canary Auto-Rollback, Two-Person Rule, SCIM 2.0, Policy Explain & WORM SIEM."""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import jwt
from pydantic import BaseModel, ConfigDict, Field

from aegis_core.crypto import SigningKeyPair
from aegis_core.models import (
    AuditRecord,
    ClearanceLevel,
    ReBACGroupHierarchyEdge,
    ReBACTuple,
)


class CanaryStatusView(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    baseline_version_id: str
    canary_version_id: str | None
    canary_weight_pct: int = Field(ge=0, le=100)
    observed_samples: int
    observed_errors: int
    observed_error_rate: float
    auto_rolled_back: bool
    last_rollback_reason: str | None = None


class CanaryRolloutController:
    """Deterministic `0..99` bucket canary splitter with sub-millisecond SLO auto-rollback."""

    def __init__(
        self,
        *,
        baseline_version_id: str = "prompt-v1",
        max_error_rate_slo: float = 0.05,
        min_samples_before_eval: int = 10,
    ) -> None:
        self._lock = threading.RLock()
        self._baseline = baseline_version_id
        self._canary: str | None = None
        self._weight_pct = 0
        self._max_err = max_error_rate_slo
        self._min_n = min_samples_before_eval
        self._samples = 0
        self._errors = 0
        self._auto_rolled_back = False
        self._rollback_reason: str | None = None

    def set_baseline(self, version_id: str) -> None:
        with self._lock:
            self._baseline = version_id
            self._canary = None
            self._weight_pct = 0

    def configure_canary(self, *, canary_version_id: str, weight_pct: int) -> CanaryStatusView:
        if weight_pct not in (0, 1, 10, 25, 50, 100):
            raise ValueError("Canary rollout stage weight_pct must be in {0, 1, 10, 25, 50, 100}")
        with self._lock:
            if weight_pct == 100:
                self._baseline = canary_version_id
                self._canary = None
                self._weight_pct = 0
            else:
                self._canary = canary_version_id
                self._weight_pct = weight_pct
            self._samples = 0
            self._errors = 0
            self._auto_rolled_back = False
            self._rollback_reason = None
            return self.status()

    def route_version(self, tenant_id: str, subject_id: str) -> str:
        with self._lock:
            if self._canary is None or self._weight_pct <= 0:
                return self._baseline
            bucket = (
                int.from_bytes(
                    hashlib.sha256(f"{tenant_id}:{subject_id}".encode()).digest()[:4],
                    "big",
                )
                % 100
            )
            return self._canary if bucket < self._weight_pct else self._baseline

    def record_canary_outcome(self, *, is_error: bool, latency_ms: float) -> tuple[bool, CanaryStatusView]:
        """Record live canary SLI sample; returns `(triggered_rollback, status_view)`."""
        with self._lock:
            if self._canary is None or self._weight_pct <= 0:
                return False, self.status()
            self._samples += 1
            if is_error or latency_ms > 2000.0:
                self._errors += 1

            err_rate = self._errors / self._samples
            if self._samples >= self._min_n and err_rate > self._max_err:
                failed_ver = self._canary
                self._canary = None
                self._weight_pct = 0
                self._auto_rolled_back = True
                self._rollback_reason = (
                    f"Canary {failed_ver} breached error-budget SLO "
                    f"({err_rate:.1%} > {self._max_err:.1%} over {self._samples} requests)"
                )
                return True, self.status()
            return False, self.status()

    def status(self) -> CanaryStatusView:
        with self._lock:
            rate = round(self._errors / self._samples, 4) if self._samples > 0 else 0.0
            return CanaryStatusView(
                baseline_version_id=self._baseline,
                canary_version_id=self._canary,
                canary_weight_pct=self._weight_pct,
                observed_samples=self._samples,
                observed_errors=self._errors,
                observed_error_rate=rate,
                auto_rolled_back=self._auto_rolled_back,
                last_rollback_reason=self._rollback_reason,
            )


class DualControlProposal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal_id: str
    action_type: Literal["ROTATE_PROD_KMS_SECRET", "EMERGENCY_POLICY_OVERRIDE"]
    target_resource: str
    proposer_sub: str
    status: Literal["PENDING_SECOND_ADMIN", "APPROVED_EXECUTED"]
    co_signer_sub: str | None = None
    created_at: datetime


class DualControlGovernanceRegistry:
    """Enforces Two-Person Rule (`proposer_sub != co_signer_sub`) for high-blast-radius changes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proposals: dict[str, tuple[DualControlProposal, str]] = {}

    def propose(
        self,
        *,
        action_type: Literal["ROTATE_PROD_KMS_SECRET", "EMERGENCY_POLICY_OVERRIDE"],
        target_resource: str,
        secret_or_payload: str,
        proposer_sub: str,
    ) -> DualControlProposal:
        pid = f"dc-{uuid.uuid4().hex[:12]}"
        prop = DualControlProposal(
            proposal_id=pid,
            action_type=action_type,
            target_resource=target_resource,
            proposer_sub=proposer_sub,
            status="PENDING_SECOND_ADMIN",
            created_at=datetime.now(tz=UTC),
        )
        with self._lock:
            self._proposals[pid] = (prop, secret_or_payload)
        return prop

    def approve_and_release(self, *, proposal_id: str, co_signer_sub: str) -> tuple[DualControlProposal, str]:
        with self._lock:
            entry = self._proposals.get(proposal_id)
            if entry is None:
                raise KeyError(f"Unknown dual-control proposal_id: {proposal_id!r}")
            prop, payload = entry
            if prop.proposer_sub == co_signer_sub:
                raise PermissionError(
                    "Two-Person Rule violation: proposer cannot co-sign their own change request"
                )
            approved = prop.model_copy(
                update={"status": "APPROVED_EXECUTED", "co_signer_sub": co_signer_sub}
            )
            self._proposals[proposal_id] = (approved, "")
            return approved, payload


class PolicyExplainStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    gate_name: str
    passed: bool
    explanation: str


class PolicyExplainPlanResult(BaseModel):
    """Zero-plaintext diagnostic trace explaining exact ReBAC / MAC / Ethical-Wall outcomes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: Literal["ALLOW", "DENY"]
    subject_id: str
    document_id: str
    effective_groups: list[str]
    steps: list[PolicyExplainStep]


def explain_zero_plaintext_policy_access(
    *,
    tenant_id: str,
    subject_id: str,
    direct_groups: list[str],
    subject_clearance: ClearanceLevel,
    document_id: str,
    document_tenant_id: str,
    document_clearance_required: ClearanceLevel,
    rebac_tuples: list[ReBACTuple],
    hierarchy_edges: list[ReBACGroupHierarchyEdge],
) -> PolicyExplainPlanResult:
    """Compute step-by-step Zanzibar + MAC + Ethical-Wall explain plan without reading plaintext."""
    # Compute transitive closure up to 8 hops
    eff_groups: set[str] = set(direct_groups)
    for e in hierarchy_edges:
        if e.tenant_id == tenant_id and e.child_type == "user" and e.child_id == subject_id:
            eff_groups.add(e.parent_group)
    for _ in range(8):
        added = False
        for e in hierarchy_edges:
            if (
                e.tenant_id == tenant_id
                and e.child_type == "group"
                and e.child_id in eff_groups
                and e.parent_group not in eff_groups
            ):
                eff_groups.add(e.parent_group)
                added = True
        if not added:
            break

    steps: list[PolicyExplainStep] = []
    t_ok = tenant_id == document_tenant_id
    steps.append(
        PolicyExplainStep(
            gate_name="RESTRICTIVE_TENANT_ISOLATION",
            passed=t_ok,
            explanation=f"Caller tenant={tenant_id!r} vs document tenant={document_tenant_id!r}",
        )
    )

    c_ok = int(subject_clearance) >= int(document_clearance_required)
    steps.append(
        PolicyExplainStep(
            gate_name="RESTRICTIVE_MAC_CLEARANCE_CEILING",
            passed=c_ok,
            explanation=(
                f"Caller clearance={int(subject_clearance)} vs required={int(document_clearance_required)}"
            ),
        )
    )

    grant_ok = any(
        t.tenant_id == document_tenant_id
        and t.object_id == document_id
        and t.relation in ("viewer", "editor", "owner")
        and (
            (t.subject_type == "user" and t.subject_id == subject_id)
            or (t.subject_type == "group" and t.subject_id in eff_groups)
        )
        for t in rebac_tuples
    )
    steps.append(
        PolicyExplainStep(
            gate_name="PERMISSIVE_TRANSITIVE_ZANZIBAR_GRANT",
            passed=grant_ok,
            explanation=(
                "Matched viewer/editor/owner tuple via direct or transitive group"
                if grant_ok
                else "No matching positive ReBAC tuple found"
            ),
        )
    )

    ethical_wall_hit = any(
        t.tenant_id == document_tenant_id
        and t.object_id == document_id
        and t.relation == "ethical_wall_deny"
        and (
            (t.subject_type == "user" and t.subject_id == subject_id)
            or (t.subject_type == "group" and t.subject_id in eff_groups)
        )
        for t in rebac_tuples
    )
    steps.append(
        PolicyExplainStep(
            gate_name="RESTRICTIVE_ETHICAL_WALL_BARRIER",
            passed=not ethical_wall_hit,
            explanation=(
                "BLOCKED by active ethical_wall_deny conflict-of-interest barrier"
                if ethical_wall_hit
                else "Clear of ethical-wall deny barriers"
            ),
        )
    )

    final_allow = all(s.passed for s in steps)
    return PolicyExplainPlanResult(
        decision="ALLOW" if final_allow else "DENY",
        subject_id=subject_id,
        document_id=document_id,
        effective_groups=sorted(eff_groups),
        steps=steps,
    )


def sync_scim2_group_payload(
    *,
    tenant_id: str,
    scim_group: dict[str, Any],
    granted_document_ids: list[str] | None = None,
) -> tuple[list[ReBACGroupHierarchyEdge], list[ReBACTuple]]:
    """Translate RFC 7644 SCIM 2.0 Group resource into Zanzibar hierarchy edges & ReBAC tuples."""
    schemas = scim_group.get("schemas", [])
    if "urn:ietf:params:scim:schemas:core:2.0:Group" not in schemas:
        raise ValueError("Invalid SCIM 2.0 Group schema URI")
    group_name = str(scim_group.get("displayName", "")).strip()
    if not group_name:
        raise ValueError("SCIM Group missing displayName")

    edges: list[ReBACGroupHierarchyEdge] = []
    for member in scim_group.get("members", []):
        m_val = str(member.get("value", "")).strip()
        m_type_raw = str(member.get("type", "User")).lower()
        c_type: Literal["user", "group"] = "group" if m_type_raw == "group" else "user"
        if m_val:
            edges.append(
                ReBACGroupHierarchyEdge(
                    tenant_id=tenant_id,
                    parent_group=group_name,
                    child_type=c_type,
                    child_id=m_val,
                )
            )

    tuples = [
        ReBACTuple(
            tenant_id=tenant_id,
            object_id=doc_id,
            relation="viewer",
            subject_type="group",
            subject_id=group_name,
        )
        for doc_id in (granted_document_ids or [])
    ]
    return edges, tuples


def export_signed_worm_audit_bundle(
    *,
    signing_key: SigningKeyPair,
    tenant_id: str,
    records: list[AuditRecord],
    retention_days: int = 2555,  # 7-year SEC Rule 17a-4 / SOX WORM retention
) -> dict[str, Any]:
    """Export ES256 JWS-signed WORM (`OBJECT_LOCK_COMPLIANCE`) SIEM bundle for SOC2/SEC auditors."""
    now = datetime.now(tz=UTC)
    retain_until = (now + timedelta(days=retention_days)).isoformat()
    chain_tip = records[-1].entry_hash if records else "0" * 64
    claims: dict[str, Any] = {
        "tenant_id": tenant_id,
        "exported_at": now.isoformat(),
        "worm_mode": "COMPLIANCE",
        "worm_retain_until": retain_until,
        "record_count": len(records),
        "chain_tip_sha256": chain_tip,
    }
    jws = jwt.encode(
        payload=claims,
        key=signing_key.private_pem,
        algorithm=signing_key.algorithm,
        headers={"kid": signing_key.kid, "typ": "worm-audit+jwt"},
    )
    return {
        "tenant_id": tenant_id,
        "worm_mode": "COMPLIANCE",
        "worm_retain_until": retain_until,
        "record_count": len(records),
        "chain_tip_sha256": chain_tip,
        "jws_attestation": jws,
    }
