"""Domain Coordinator for Project 7 Async Temporal Approval Gate."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from aegis_core.models import AuditEventType, TokenExchangeRequest
from aegis_core.ports import AuditLedgerPort
from mcp_erp_bridge.bridge import JSONRPCRequest, MCPERPBridgeServer
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker
from temporal_approval_gate.app import SlackDecisionPayload, create_approval_gate_app
from temporal_approval_gate.slack_signature import (
    SlackWebhookVerificationError,
    sign_slack_webhook_payload,
    verify_slack_webhook_signature,
)
from temporal_approval_gate.wal_repository import (
    ApprovalGateRequest,
    ApprovalWorkflowRecord,
    WalApprovalRepository,
)


class DurableApprovalGate:
    """Domain state machine orchestrating dry-run ETag capture, Slack approval, & SAP commit."""

    def __init__(
        self,
        *,
        db_path: Path,
        broker: SSODelegationBroker,
        mcp_bridge: MCPERPBridgeServer,
        audit_ledger: AuditLedgerPort,
        slack_hmac_key: str = "meridian_slack_hmac_key_v1",
    ) -> None:
        self._repo = WalApprovalRepository(db_path)
        self._broker = broker
        self._mcp = mcp_bridge
        self._audit = audit_ledger
        self.slack_signing_secret = slack_hmac_key

    def submit_high_stakes_po(
        self,
        *,
        requester_bearer_token: str,
        req: ApprovalGateRequest,
    ) -> ApprovalWorkflowRecord:
        claims = self._broker.verify_and_check_revocation(
            requester_bearer_token, required_scope="erp:po:create"
        )

        sim_rpc = self._mcp.handle_jsonrpc(
            JSONRPCRequest(
                id="sim-1",
                method="tools/call",
                params={
                    "name": "sap_simulate_purchase_order",
                    "arguments": {
                        "vendor_id": req.vendor_id,
                        "company_code": req.company_code,
                        "description": req.description,
                        "amount_usd": req.amount_usd,
                    },
                },
            ),
            bearer_token=requester_bearer_token,
        )
        sim_res = sim_rpc.get("result", {})
        structured = sim_res.get("structuredContent", {})
        if sim_res.get("isError", True):
            msg = structured.get("sap_return", {}).get("message", "SAP simulation failed")
            raise ValueError(f"SAP pre-approval simulation rejected PO: {msg}")

        snapshot_etag = str(structured.get("vendor_state_etag", ""))
        wf_id = f"wf-po-{uuid.uuid4().hex[:12]}"
        payload_hash = hashlib.sha256(
            json.dumps(
                {
                    "vendor_id": req.vendor_id,
                    "company_code": req.company_code,
                    "description": req.description,
                    "amount_usd": round(req.amount_usd, 2),
                    "snapshot_etag": snapshot_etag,
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

        slack_card: dict[str, Any] = {
            "channel": "#meridian-exec-po-approvals",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"High-Value SAP PO Approval Required: USD {req.amount_usd:,.2f}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Requester:* `{claims.sub}` via `{claims.act.client_id}`\n"
                            f"*Vendor:* `{req.vendor_id}` | *Description:* {req.description}\n"
                            f"*Snapshot ETag:* `{snapshot_etag[:16]}...`"
                        ),
                    },
                },
                {
                    "type": "actions",
                    "block_id": wf_id,
                    "elements": [
                        {"type": "button", "action_id": "approve", "value": wf_id},
                        {"type": "button", "action_id": "reject", "value": wf_id},
                    ],
                },
            ],
        }

        self._repo.insert_pending(
            workflow_id=wf_id,
            tenant_id=claims.tenant_id,
            requester_sub=claims.sub,
            vendor_id=req.vendor_id,
            company_code=req.company_code,
            description=req.description,
            amount_usd=req.amount_usd,
            snapshot_etag=snapshot_etag,
            payload_hash=payload_hash,
            slack_card=slack_card,
        )

        self._audit.append(
            tenant_id=claims.tenant_id,
            event_type=AuditEventType.TEMPORAL_GATE_PAUSED,
            human_subject=claims.sub,
            actor_id=claims.act.sub,
            jti=claims.jti,
            decision="ALLOW",
            detail={
                "workflow_id": wf_id,
                "amount_usd": round(req.amount_usd, 2),
                "vendor_id": req.vendor_id,
                "snapshot_etag": snapshot_etag,
            },
        )
        return self._repo.get(wf_id)

    def get_workflow(self, workflow_id: str) -> ApprovalWorkflowRecord:
        return self._repo.get(workflow_id)

    def process_slack_decision(self, decision: SlackDecisionPayload) -> ApprovalWorkflowRecord:
        wf = self._repo.get(decision.workflow_id)
        if wf.status != "AWAITING_APPROVAL":
            return wf

        approver_exchange = self._broker.exchange_token(
            TokenExchangeRequest(
                subject_token=decision.approver_subject_token,
                subject_token_type=decision.approver_token_type,
                agent_id="meridian-temporal-approver",
                requested_scopes=["erp:po:create", "erp:po:approve"],
                requested_ttl_seconds=120,
            )
        )
        approver_claims = self._broker.verify_and_check_revocation(approver_exchange.access_token)

        if decision.action == "reject":
            self._repo.update_resolution(
                wf.workflow_id,
                status="REJECTED",
                approver_sub=approver_claims.sub,
                sap_po_number=None,
                failure_reason=decision.comment or "Rejected by approver in Slack",
            )
            self._audit.append(
                tenant_id=wf.tenant_id,
                event_type=AuditEventType.TEMPORAL_GATE_DECIDED,
                human_subject=approver_claims.sub,
                actor_id=approver_claims.act.sub,
                jti=approver_claims.jti,
                decision="DENY",
                detail={"workflow_id": wf.workflow_id, "action": "reject"},
            )
            return self._repo.get(wf.workflow_id)

        if "erp:po:approve" not in approver_claims.scopes or (
            wf.amount_usd > approver_claims.po_approval_limit_usd
        ):
            raise DelegationPolicyError(
                "insufficient_approval_limit",
                (
                    f"Approver {approver_claims.sub!r} limit "
                    f"(USD {approver_claims.po_approval_limit_usd:,}) cannot approve "
                    f"USD {wf.amount_usd:,.2f}"
                ),
                status_code=403,
            )

        commit_rpc = self._mcp.handle_jsonrpc(
            JSONRPCRequest(
                id=f"commit-{wf.workflow_id}",
                method="tools/call",
                params={
                    "name": "sap_create_purchase_order",
                    "arguments": {
                        "vendor_id": wf.vendor_id,
                        "company_code": wf.company_code,
                        "description": wf.description,
                        "amount_usd": wf.amount_usd,
                        "idempotency_key": wf.workflow_id,
                        "expected_vendor_state_etag": wf.snapshot_vendor_etag,
                    },
                },
            ),
            bearer_token=approver_exchange.access_token,
        )
        res = commit_rpc.get("result", {})
        structured = res.get("structuredContent", {})

        if res.get("isError", True):
            err_code = str(structured.get("error", "sap_error"))
            new_status = (
                "ABORTED_TOCTOU_DRIFT"
                if err_code == "toctou_erp_state_drift"
                else "FAILED_SAP_ERROR"
            )
            reason = str(structured.get("message", err_code))
            self._repo.update_resolution(
                wf.workflow_id,
                status=new_status,
                approver_sub=approver_claims.sub,
                sap_po_number=None,
                failure_reason=reason,
            )
            self._audit.append(
                tenant_id=wf.tenant_id,
                event_type=AuditEventType.TEMPORAL_GATE_DECIDED,
                human_subject=approver_claims.sub,
                actor_id=approver_claims.act.sub,
                jti=approver_claims.jti,
                decision="DENY",
                detail={"workflow_id": wf.workflow_id, "error": err_code, "reason": reason},
            )
            return self._repo.get(wf.workflow_id)

        po_num = str(structured.get("po_number", ""))
        self._repo.update_resolution(
            wf.workflow_id,
            status="APPROVED_EXECUTED",
            approver_sub=approver_claims.sub,
            sap_po_number=po_num,
            failure_reason=None,
        )
        self._audit.append(
            tenant_id=wf.tenant_id,
            event_type=AuditEventType.TEMPORAL_GATE_DECIDED,
            human_subject=approver_claims.sub,
            actor_id=approver_claims.act.sub,
            jti=approver_claims.jti,
            decision="ALLOW",
            detail={
                "workflow_id": wf.workflow_id,
                "sap_po_number": po_num,
                "original_requester": wf.requester_sub,
                "amount_usd": wf.amount_usd,
            },
        )
        return self._repo.get(wf.workflow_id)


__all__ = [
    "ApprovalGateRequest",
    "ApprovalWorkflowRecord",
    "DurableApprovalGate",
    "SlackDecisionPayload",
    "SlackWebhookVerificationError",
    "create_approval_gate_app",
    "sign_slack_webhook_payload",
    "verify_slack_webhook_signature",
]
