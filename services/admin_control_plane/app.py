"""Streamlined FastAPI HTTP & Browser UI Transport for Project 12 Admin Control Plane.

Uses centralized boundary exception handlers (`install_aegis_http_layer`) and FastAPI
`Depends(require_bearer_token)` (`DRY` + `Fail Fast` + `Single Responsibility`), eliminating
repetitive per-route `try/except` auth boilerplate.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from admin_control_plane.canary_and_governance import (
    CanaryStatusView,
    DualControlProposal,
    PolicyExplainPlanResult,
)
from admin_control_plane.secret_vault import MaskedConnectorSecret
from aegis_core.http_middleware import install_aegis_http_layer, require_bearer_token
from aegis_core.models import ClearanceLevel
from finops_telemetry.engine import DepartmentROIReport

if TYPE_CHECKING:
    from admin_control_plane.portal_api import (
        ControlPlaneService,
        PromptVersionRecord,
        TraceSpanSummary,
    )

_PORTAL_HTML_PATH = (
    Path(__file__).resolve().parents[2] / "apps" / "admin_portal" / "public" / "index.html"
)


class CreatePromptDraftRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    system_prompt: str = Field(min_length=20, max_length=16_000)


class ConfigureCanaryRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    canary_version_id: str
    weight_pct: int = Field(ge=0, le=100)


class RotateConnectorSecretRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    connector_name: str = Field(min_length=3, max_length=64)
    raw_secret_value: str = Field(min_length=8, max_length=1024)


class SCIMGroupSyncRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scim_group: dict[str, Any]
    granted_document_ids: list[str] = Field(default_factory=list)


class PolicyExplainRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_id: str
    direct_groups: list[str] = Field(default_factory=list)
    subject_clearance: ClearanceLevel
    document_id: str
    document_clearance_required: ClearanceLevel


def create_admin_control_plane_app(svc: ControlPlaneService) -> FastAPI:
    """Create observable FastAPI app serving Admin REST APIs & Self-Contained `/ui` Portal."""
    from admin_control_plane.portal_api import PromptPromotionError

    app = FastAPI(title="Aegis Self-Serve Customer Admin Control Plane", version="0.3.0")
    install_aegis_http_layer(
        app,
        service_name="admin-control-plane",
        token_error_status_code=403,
    )

    @app.exception_handler(PromptPromotionError)
    async def _handle_promotion_gate(_req: Request, exc: PromptPromotionError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "shadow_replay_gate_failed",
                "message": exc.message,
                "replay_summary": exc.replay_summary.model_dump(),
            },
        )

    @app.exception_handler(ValueError)
    async def _handle_bad_input(_req: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    @app.exception_handler(PermissionError)
    async def _handle_dual_control_denied(_req: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"error": str(exc)})

    @app.get("/ui", response_class=HTMLResponse)
    def render_portal_ui() -> HTMLResponse:
        return HTMLResponse(content=_PORTAL_HTML_PATH.read_text(encoding="utf-8"), status_code=200)

    @app.post("/v1/admin/prompts", response_model=None)
    def draft_prompt(
        req: CreatePromptDraftRequest,
        tok: str = Depends(require_bearer_token),
    ) -> PromptVersionRecord:
        return svc.create_prompt_draft(bearer_token=tok, system_prompt=req.system_prompt)

    @app.post("/v1/admin/prompts/{version_id}/promote", response_model=None)
    def promote_prompt(
        version_id: str,
        tok: str = Depends(require_bearer_token),
    ) -> PromptVersionRecord:
        return svc.promote_prompt_version(bearer_token=tok, version_id=version_id)

    @app.post("/v1/admin/canary", response_model=None)
    def configure_canary(
        req: ConfigureCanaryRequest,
        tok: str = Depends(require_bearer_token),
    ) -> CanaryStatusView:
        return svc.configure_canary_stage(
            bearer_token=tok,
            canary_version_id=req.canary_version_id,
            weight_pct=req.weight_pct,
        )

    @app.post("/v1/admin/secrets", response_model=None)
    def rotate_secret(
        req: RotateConnectorSecretRequest,
        tok: str = Depends(require_bearer_token),
    ) -> MaskedConnectorSecret:
        return svc.rotate_connector_secret(
            bearer_token=tok,
            connector_name=req.connector_name,
            raw_secret=req.raw_secret_value,
        )

    @app.post("/v1/admin/dual-control/secrets", response_model=None)
    def propose_dual_control(
        req: RotateConnectorSecretRequest,
        tok: str = Depends(require_bearer_token),
    ) -> DualControlProposal:
        return svc.propose_dual_control_secret_rotation(
            bearer_token=tok,
            connector_name=req.connector_name,
            raw_secret=req.raw_secret_value,
        )

    @app.post("/v1/admin/dual-control/{proposal_id}/approve", response_model=None)
    def approve_dual_control(
        proposal_id: str,
        tok: str = Depends(require_bearer_token),
    ) -> dict[str, Any]:
        prop, masked = svc.approve_dual_control_secret_rotation(
            bearer_token=tok, proposal_id=proposal_id
        )
        return {
            "proposal": prop.model_dump(mode="json"),
            "rotated_secret": masked.model_dump(mode="json"),
        }

    @app.post("/scim/v2/Groups", response_model=None)
    def scim_sync_group(
        req: SCIMGroupSyncRequest,
        tok: str = Depends(require_bearer_token),
    ) -> dict[str, int]:
        return svc.sync_scim2_group(
            bearer_token=tok,
            scim_group=req.scim_group,
            granted_document_ids=req.granted_document_ids,
        )

    @app.post("/v1/admin/policy/explain", response_model=None)
    def explain_policy(
        req: PolicyExplainRequest,
        tok: str = Depends(require_bearer_token),
    ) -> PolicyExplainPlanResult:
        return svc.explain_policy_access(
            bearer_token=tok,
            subject_id=req.subject_id,
            direct_groups=req.direct_groups,
            subject_clearance=req.subject_clearance,
            document_id=req.document_id,
            document_clearance_required=req.document_clearance_required,
        )

    @app.get("/v1/admin/audit/worm-export", response_model=None)
    def worm_export(tok: str = Depends(require_bearer_token)) -> dict[str, Any]:
        return svc.export_worm_audit_bundle(bearer_token=tok)

    @app.get("/v1/admin/traces", response_model=None)
    def list_traces(tok: str = Depends(require_bearer_token)) -> list[TraceSpanSummary]:
        return svc.inspect_otel_traces(bearer_token=tok)

    @app.get("/v1/admin/finops", response_model=None)
    def finops_dashboard(tok: str = Depends(require_bearer_token)) -> list[DepartmentROIReport]:
        return svc.get_finops_dashboard(bearer_token=tok)

    return app
