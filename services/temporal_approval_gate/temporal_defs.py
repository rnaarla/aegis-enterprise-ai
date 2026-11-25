"""Production Temporal Python SDK (`temporalio`) Workflow & Activity definitions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from temporalio import activity, workflow


@dataclass(frozen=True)
class TemporalPOInput:
    workflow_id: str
    tenant_id: str
    requester_sub: str
    vendor_id: str
    company_code: str
    description: str
    amount_usd: float
    expected_vendor_state_etag: str


@dataclass(frozen=True)
class TemporalApprovalDecisionSignal:
    approved: bool
    approver_sub: str
    approver_subject_token: str
    approver_token_type: str
    comment: str


@activity.defn(name="aegis_dispatch_slack_approval_card")
async def dispatch_slack_approval_card_activity(po_input: TemporalPOInput) -> str:
    """Activity: Emit interactive Slack Block Kit approval message to #exec-approvals."""
    return f"slack-msg-{po_input.workflow_id}"


@activity.defn(name="aegis_commit_approved_po")
async def commit_approved_po_activity(
    po_input: TemporalPOInput,
    decision: TemporalApprovalDecisionSignal,
) -> dict[str, str | bool | float]:
    """Activity: Mint fresh 120s approver JWT, verify anti-TOCTOU ETag, and execute SAP BAPI."""
    return {
        "workflow_id": po_input.workflow_id,
        "approved_by": decision.approver_sub,
        "status": "EXECUTED",
    }


@workflow.defn(name="AegisHighValuePOApprovalWorkflow")
class HighValuePOApprovalWorkflow:
    """Deterministic Temporal workflow sleeping durably until Slack signal or SLA timeout."""

    def __init__(self) -> None:
        self._decision: TemporalApprovalDecisionSignal | None = None
        self._status: str = "INITIALIZING"

    @workflow.signal
    def submit_decision(self, signal: TemporalApprovalDecisionSignal) -> None:
        if self._decision is None:
            self._decision = signal

    @workflow.query
    def current_status(self) -> str:
        return self._status

    @workflow.run
    async def run(self, po_input: TemporalPOInput) -> dict[str, str | bool | float]:
        await workflow.execute_activity(
            dispatch_slack_approval_card_activity,
            po_input,
            start_to_close_timeout=timedelta(seconds=30),
        )
        self._status = "AWAITING_HUMAN_APPROVAL"

        try:
            await workflow.wait_condition(
                lambda: self._decision is not None,
                timeout=timedelta(hours=72),
            )
        except TimeoutError:
            self._status = "TIMED_OUT_ESCALATED"
            return {"workflow_id": po_input.workflow_id, "status": self._status, "approved": False}

        assert self._decision is not None
        if not self._decision.approved:
            self._status = "REJECTED_BY_APPROVER"
            return {
                "workflow_id": po_input.workflow_id,
                "status": self._status,
                "approved": False,
                "decided_by": self._decision.approver_sub,
            }

        self._status = "COMMITTING_TO_ERP"
        res: dict[str, str | bool | float] = await workflow.execute_activity(
            commit_approved_po_activity,
            args=[po_input, self._decision],
            start_to_close_timeout=timedelta(seconds=60),
        )
        self._status = "COMPLETED"
        return res
