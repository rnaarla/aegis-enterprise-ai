"""Domain Service for Project 12 Admin Control Plane (Canary, Two-Person Rule, SCIM & Explain)."""

from __future__ import annotations

import difflib
import threading
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from admin_control_plane.app import create_admin_control_plane_app
from admin_control_plane.canary_and_governance import (
    CanaryRolloutController,
    CanaryStatusView,
    DualControlGovernanceRegistry,
    DualControlProposal,
    PolicyExplainPlanResult,
    explain_zero_plaintext_policy_access,
    export_signed_worm_audit_bundle,
    sync_scim2_group_payload,
)
from admin_control_plane.secret_vault import (
    EnvelopeConnectorSecretStore,
    MaskedConnectorSecret,
)
from aegis_core.crypto import SigningKeyPair
from aegis_core.models import (
    AuditEventType,
    ClearanceLevel,
    HistoricalSupportTicket,
    ReBACGroupHierarchyEdge,
    ReBACTuple,
)
from aegis_core.ports import AuditLedgerPort, TokenVerifierPort
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry
from aegis_core.telemetry import AegisTelemetry
from finops_telemetry.engine import DepartmentROIReport, FinOpsTelemetryEngine
from shadow_replay_harness.harness import (
    PolicyGuidedShadowAgent,
    ShadowReplayHarness,
    ShadowReplaySummary,
)


class PromptPromotionError(Exception):
    """Raised when a candidate prompt fails Project 10's 500-ticket shadow replay gate."""

    def __init__(self, message: str, replay_summary: ShadowReplaySummary) -> None:
        super().__init__(message)
        self.message = message
        self.replay_summary = replay_summary


class PromptVersionRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version_id: str
    version_number: int
    system_prompt: str
    author_sub: str
    created_at: datetime
    is_active_production: bool
    diff_from_previous: str
    last_shadow_replay: ShadowReplaySummary | None = None


class TraceSpanSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    duration_ms: float
    attributes: dict[str, str | int | float | bool]


DEFAULT_PRODUCTION_SYSTEM_PROMPT = (
    "You are the Meridian Enterprise AI Assistant. "
    "1. Enforce strict MNPI clearance boundaries; never disclose restricted deal terms. "
    "2. Refuse blocked SAP vendors (SPERR=X). "
    "3. Route any SAP Purchase Order exceeding USD 50,000 through the Temporal Approval Gate."
)


class ControlPlaneService:
    """Governs prompt rollouts, canary SLOs, Two-Person Rule KMS, SCIM 2.0, Explain & WORM SIEM."""

    def __init__(
        self,
        *,
        broker: TokenVerifierPort,
        replay_harness: ShadowReplayHarness,
        golden_tickets: list[HistoricalSupportTicket],
        finops_engine: FinOpsTelemetryEngine,
        telemetry: AegisTelemetry,
        audit_ledger: AuditLedgerPort,
        kms_master_key: bytes | None = None,
        worm_signing_key: SigningKeyPair | None = None,
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self._broker = broker
        self._replay = replay_harness
        self._tickets = golden_tickets
        self._finops = finops_engine
        self._telemetry = telemetry
        self._audit = audit_ledger
        self._secrets = EnvelopeConnectorSecretStore(kms_master_key)
        self._worm_key = worm_signing_key or SigningKeyPair.generate_es256()
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY
        self.canary = CanaryRolloutController(baseline_version_id="prompt-v1")
        self.dual_control = DualControlGovernanceRegistry()
        self._lock = threading.RLock()
        self._rebac_tuples: list[ReBACTuple] = []
        self._hierarchy_edges: list[ReBACGroupHierarchyEdge] = []
        self._prompts: list[PromptVersionRecord] = [
            PromptVersionRecord(
                version_id="prompt-v1",
                version_number=1,
                system_prompt=DEFAULT_PRODUCTION_SYSTEM_PROMPT,
                author_sub="bootstrap_system",
                created_at=datetime.now(tz=UTC),
                is_active_production=True,
                diff_from_previous="(initial baseline)",
                last_shadow_replay=None,
            )
        ]

    def create_prompt_draft(
        self,
        *,
        bearer_token: str,
        system_prompt: str,
    ) -> PromptVersionRecord:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:prompts:write"
        )
        with self._lock:
            prev = self._prompts[-1]
            ver_num = prev.version_number + 1
            ver_id = f"prompt-v{ver_num}"
            diff = "\n".join(
                difflib.unified_diff(
                    prev.system_prompt.splitlines(),
                    system_prompt.splitlines(),
                    fromfile=prev.version_id,
                    tofile=ver_id,
                    lineterm="",
                )
            )
            rec = PromptVersionRecord(
                version_id=ver_id,
                version_number=ver_num,
                system_prompt=system_prompt,
                author_sub=claims.sub,
                created_at=datetime.now(tz=UTC),
                is_active_production=False,
                diff_from_previous=diff,
                last_shadow_replay=None,
            )
            self._prompts.append(rec)
            return rec

    def promote_prompt_version(
        self,
        *,
        bearer_token: str,
        version_id: str,
    ) -> PromptVersionRecord:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:prompts:write"
        )
        with self._lock:
            candidate = next((p for p in self._prompts if p.version_id == version_id), None)
            if candidate is None:
                raise KeyError(f"Unknown prompt version_id: {version_id!r}")

        summary = self._replay.run_suite(
            prompt_version_id=candidate.version_id,
            system_prompt=candidate.system_prompt,
            tickets=self._tickets,
            agent=PolicyGuidedShadowAgent(),
        )

        if not summary.release_gate_passed:
            self._audit.append(
                tenant_id=claims.tenant_id,
                event_type=AuditEventType.PROMPT_VERSION_PROMOTED,
                human_subject=claims.sub,
                actor_id=claims.act.sub,
                jti=claims.jti,
                decision="DENY",
                detail={
                    "version_id": version_id,
                    "accuracy": summary.trajectory_accuracy,
                    "policy_violations": summary.policy_violations,
                },
            )
            raise PromptPromotionError(
                f"Promotion blocked by Shadow Replay Gate: accuracy={summary.trajectory_accuracy:.2%}, "
                f"policy_violations={summary.policy_violations}",
                replay_summary=summary,
            )

        with self._lock:
            promoted_record: PromptVersionRecord | None = None
            updated_list: list[PromptVersionRecord] = []
            for p in self._prompts:
                is_target = p.version_id == version_id
                updated = PromptVersionRecord(
                    version_id=p.version_id,
                    version_number=p.version_number,
                    system_prompt=p.system_prompt,
                    author_sub=p.author_sub,
                    created_at=p.created_at,
                    is_active_production=is_target,
                    diff_from_previous=p.diff_from_previous,
                    last_shadow_replay=summary if is_target else p.last_shadow_replay,
                )
                if is_target:
                    promoted_record = updated
                updated_list.append(updated)
            self._prompts = updated_list

        self.canary.set_baseline(version_id)
        self._audit.append(
            tenant_id=claims.tenant_id,
            event_type=AuditEventType.PROMPT_VERSION_PROMOTED,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
            decision="ALLOW",
            detail={
                "version_id": version_id,
                "accuracy": summary.trajectory_accuracy,
                "ci99_lower": summary.accuracy_ci99_lower,
                "tickets_tested": summary.total_tickets,
            },
        )
        assert promoted_record is not None
        return promoted_record

    def configure_canary_stage(
        self,
        *,
        bearer_token: str,
        canary_version_id: str,
        weight_pct: int,
    ) -> CanaryStatusView:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:prompts:write"
        )
        with self._lock:
            candidate = next((p for p in self._prompts if p.version_id == canary_version_id), None)
            if candidate is None:
                raise KeyError(f"Unknown canary version_id: {canary_version_id!r}")

        summary = self._replay.run_suite(
            prompt_version_id=candidate.version_id,
            system_prompt=candidate.system_prompt,
            tickets=self._tickets,
            agent=PolicyGuidedShadowAgent(),
        )
        if not summary.release_gate_passed:
            raise PromptPromotionError(
                f"Canary stage blocked by Shadow Replay Gate ({summary.trajectory_accuracy:.2%})",
                replay_summary=summary,
            )
        view = self.canary.configure_canary(
            canary_version_id=canary_version_id, weight_pct=weight_pct
        )
        self._sli.set_gauge(
            "aegis_canary_traffic_weight_pct",
            float(view.canary_weight_pct),
            {"tenant": claims.tenant_id},
        )
        return view

    def record_canary_sample(
        self,
        *,
        tenant_id: str,
        is_error: bool,
        latency_ms: float,
    ) -> CanaryStatusView:
        rolled_back, view = self.canary.record_canary_outcome(
            is_error=is_error, latency_ms=latency_ms
        )
        if rolled_back:
            self._sli.inc_counter("aegis_canary_auto_rollbacks_total", 1.0, {"tenant": tenant_id})
            self._audit.append(
                tenant_id=tenant_id,
                event_type=AuditEventType.CANARY_AUTO_ROLLED_BACK,
                human_subject="sre_slo_watchdog",
                actor_id="admin-control-plane",
                jti=None,
                decision="REVOKE",
                detail={"reason": view.last_rollback_reason or "slo_breach"},
            )
        return view

    def rotate_connector_secret(
        self,
        *,
        bearer_token: str,
        connector_name: str,
        raw_secret: str,
    ) -> MaskedConnectorSecret:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:control_plane"
        )
        return self._secrets.rotate(
            tenant_id=claims.tenant_id,
            connector_name=connector_name,
            raw_secret=raw_secret,
            updated_by=claims.sub,
        )

    def propose_dual_control_secret_rotation(
        self,
        *,
        bearer_token: str,
        connector_name: str,
        raw_secret: str,
    ) -> DualControlProposal:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:control_plane"
        )
        return self.dual_control.propose(
            action_type="ROTATE_PROD_KMS_SECRET",
            target_resource=connector_name,
            secret_or_payload=raw_secret,
            proposer_sub=claims.sub,
        )

    def approve_dual_control_secret_rotation(
        self,
        *,
        bearer_token: str,
        proposal_id: str,
    ) -> tuple[DualControlProposal, MaskedConnectorSecret]:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:control_plane"
        )
        approved, raw_secret = self.dual_control.approve_and_release(
            proposal_id=proposal_id, co_signer_sub=claims.sub
        )
        masked = self._secrets.rotate(
            tenant_id=claims.tenant_id,
            connector_name=approved.target_resource,
            raw_secret=raw_secret,
            updated_by=f"{approved.proposer_sub}+{claims.sub}",
        )
        self._audit.append(
            tenant_id=claims.tenant_id,
            event_type=AuditEventType.DUAL_CONTROL_APPROVED,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
            decision="ALLOW",
            detail={
                "proposal_id": proposal_id,
                "proposer": approved.proposer_sub,
                "co_signer": claims.sub,
                "connector": approved.target_resource,
            },
        )
        return approved, masked

    def sync_scim2_group(
        self,
        *,
        bearer_token: str,
        scim_group: dict[str, Any],
        granted_document_ids: list[str] | None = None,
    ) -> dict[str, int]:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:control_plane"
        )
        edges, tuples = sync_scim2_group_payload(
            tenant_id=claims.tenant_id,
            scim_group=scim_group,
            granted_document_ids=granted_document_ids,
        )
        with self._lock:
            self._hierarchy_edges.extend(edges)
            self._rebac_tuples.extend(tuples)
        return {"hierarchy_edges_synced": len(edges), "rebac_tuples_synced": len(tuples)}

    def register_policy_metadata_for_explain(
        self,
        *,
        tuples: list[ReBACTuple],
        edges: list[ReBACGroupHierarchyEdge] | None = None,
    ) -> None:
        with self._lock:
            self._rebac_tuples.extend(tuples)
            if edges:
                self._hierarchy_edges.extend(edges)

    def explain_policy_access(
        self,
        *,
        bearer_token: str,
        subject_id: str,
        direct_groups: list[str],
        subject_clearance: ClearanceLevel,
        document_id: str,
        document_clearance_required: ClearanceLevel,
    ) -> PolicyExplainPlanResult:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:control_plane"
        )
        with self._lock:
            tuples = list(self._rebac_tuples)
            edges = list(self._hierarchy_edges)
        return explain_zero_plaintext_policy_access(
            tenant_id=claims.tenant_id,
            subject_id=subject_id,
            direct_groups=direct_groups,
            subject_clearance=subject_clearance,
            document_id=document_id,
            document_tenant_id=claims.tenant_id,
            document_clearance_required=document_clearance_required,
            rebac_tuples=tuples,
            hierarchy_edges=edges,
        )

    def export_worm_audit_bundle(self, *, bearer_token: str) -> dict[str, Any]:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:control_plane"
        )
        records = [r for r in self._audit.list_records() if r.tenant_id == claims.tenant_id]
        return export_signed_worm_audit_bundle(
            signing_key=self._worm_key,
            tenant_id=claims.tenant_id,
            records=records,
        )

    def canary_status(self) -> CanaryStatusView:
        """Tell-Don't-Ask facade returning current canary rollout state."""
        return self.canary.status()

    def route_prompt_version(self, tenant_id: str, subject_id: str) -> str:
        """Tell-Don't-Ask facade resolving active prompt version for `(tenant_id, subject_id)`."""
        return self.canary.route_version(tenant_id, subject_id)

    def inspect_otel_traces(self, *, bearer_token: str) -> list[TraceSpanSummary]:
        self._broker.verify_and_check_revocation(bearer_token, required_scope="admin:traces:read")
        spans = self._telemetry.finished_spans()
        summaries: list[TraceSpanSummary] = []
        for sp in spans:
            ctx = sp.get_span_context()
            trace_hex = f"{ctx.trace_id:032x}" if ctx is not None else "0" * 32
            span_hex = f"{ctx.span_id:016x}" if ctx is not None else "0" * 16
            parent_hex = f"{sp.parent.span_id:016x}" if sp.parent is not None else None
            dur_ms = (
                round((sp.end_time - sp.start_time) / 1_000_000.0, 3)
                if sp.end_time is not None and sp.start_time is not None
                else 0.0
            )
            attrs: dict[str, str | int | float | bool] = {}
            if sp.attributes:
                for k, v in sp.attributes.items():
                    if isinstance(v, (str, int, float, bool)):
                        attrs[k] = v
            summaries.append(
                TraceSpanSummary(
                    trace_id=trace_hex,
                    span_id=span_hex,
                    parent_span_id=parent_hex,
                    name=sp.name,
                    duration_ms=dur_ms,
                    attributes=attrs,
                )
            )
        return summaries

    def get_finops_dashboard(self, *, bearer_token: str) -> list[DepartmentROIReport]:
        claims = self._broker.verify_and_check_revocation(
            bearer_token, required_scope="admin:control_plane"
        )
        return self._finops.department_roi_reports(claims.tenant_id)


__all__ = [
    "CanaryStatusView",
    "ControlPlaneService",
    "DualControlProposal",
    "MaskedConnectorSecret",
    "PolicyExplainPlanResult",
    "PromptPromotionError",
    "PromptVersionRecord",
    "TraceSpanSummary",
    "create_admin_control_plane_app",
]
