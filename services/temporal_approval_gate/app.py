"""FastAPI HTTP transport for Project 7 Async Temporal Approval Gate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from aegis_core.http_middleware import (
    MissingBearerTokenError,
    extract_bearer_token,
    install_aegis_http_layer,
)
from sso_delegation_broker.broker import DelegationPolicyError
from temporal_approval_gate.slack_signature import (
    SlackWebhookVerificationError,
    verify_slack_webhook_signature,
)
from temporal_approval_gate.wal_repository import ApprovalGateRequest, ApprovalWorkflowRecord

if TYPE_CHECKING:
    from temporal_approval_gate.gate import DurableApprovalGate


class SlackDecisionPayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    workflow_id: str
    action: Literal["approve", "reject"]
    approver_subject_token: str
    approver_token_type: Literal[
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:saml2",
    ] = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105
    comment: str = ""


def create_approval_gate_app(gate: DurableApprovalGate) -> FastAPI:
    """Expose PO submission, status query, and HMAC-verified Slack interactive webhook."""
    app = FastAPI(title="Aegis Async Temporal Approval Gate", version="0.2.0")
    install_aegis_http_layer(app, service_name="temporal-approval-gate")

    @app.post("/v1/approvals/po", response_model=ApprovalWorkflowRecord)
    def submit_po(
        req: ApprovalGateRequest,
        authorization: str | None = Header(default=None),
    ) -> ApprovalWorkflowRecord | JSONResponse:
        try:
            token = extract_bearer_token(authorization)
            return gate.submit_high_stakes_po(requester_bearer_token=token, req=req)
        except MissingBearerTokenError as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})
        except Exception as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

    @app.post("/v1/webhooks/slack/interactive", response_model=ApprovalWorkflowRecord)
    async def slack_interactive_webhook(
        request: Request,
        x_slack_request_timestamp: str | None = Header(default=None),
        x_slack_signature: str | None = Header(default=None),
    ) -> ApprovalWorkflowRecord | JSONResponse:
        raw_body = await request.body()
        if not x_slack_request_timestamp or not x_slack_signature:
            return JSONResponse(status_code=401, content={"error": "missing_slack_hmac_headers"})
        try:
            verify_slack_webhook_signature(
                signing_secret=gate.slack_signing_secret,
                timestamp_header=x_slack_request_timestamp,
                signature_header=x_slack_signature,
                raw_body=raw_body,
            )
            payload = SlackDecisionPayload.model_validate_json(raw_body)
            return gate.process_slack_decision(payload)
        except SlackWebhookVerificationError as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})
        except DelegationPolicyError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": exc.oauth_error, "error_description": exc.description},
            )

    @app.get("/v1/approvals/{workflow_id}", response_model=ApprovalWorkflowRecord)
    def get_status(workflow_id: str) -> ApprovalWorkflowRecord | JSONResponse:
        try:
            return gate.get_workflow(workflow_id)
        except KeyError as exc:
            return JSONResponse(status_code=404, content={"error": str(exc)})

    return app
