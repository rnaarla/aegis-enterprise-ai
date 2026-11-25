"""FastAPI HTTP & Interactive Browser UI transport for Project 12 Admin Control Plane."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, Header
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from admin_control_plane.secret_vault import MaskedConnectorSecret
from aegis_core.crypto import TokenVerificationError
from aegis_core.http_middleware import (
    MissingBearerTokenError,
    extract_bearer_token,
    install_aegis_http_layer,
)
from finops_telemetry.engine import DepartmentROIReport
from sso_delegation_broker.broker import DelegationPolicyError

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


class RotateConnectorSecretRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    connector_name: str = Field(min_length=3, max_length=64)
    raw_secret_value: str = Field(min_length=8, max_length=1024)


def create_admin_control_plane_app(svc: ControlPlaneService) -> FastAPI:
    """Create observable FastAPI app serving Admin REST APIs & Self-Contained `/ui` Portal."""
    from admin_control_plane.portal_api import PromptPromotionError

    app = FastAPI(title="Aegis Self-Serve Customer Admin Control Plane", version="0.2.0")
    install_aegis_http_layer(app, service_name="admin-control-plane")

    @app.get("/ui", response_class=HTMLResponse)
    def render_portal_ui() -> HTMLResponse:
        html = _PORTAL_HTML_PATH.read_text(encoding="utf-8")
        return HTMLResponse(content=html, status_code=200)

    @app.post("/v1/admin/prompts", response_model=None)
    def draft_prompt(
        req: CreatePromptDraftRequest,
        authorization: str | None = Header(default=None),
    ) -> PromptVersionRecord | JSONResponse:
        try:
            tok = extract_bearer_token(authorization)
            return svc.create_prompt_draft(bearer_token=tok, system_prompt=req.system_prompt)
        except MissingBearerTokenError as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return JSONResponse(status_code=403, content={"error": str(exc)})

    @app.post("/v1/admin/prompts/{version_id}/promote", response_model=None)
    def promote_prompt(
        version_id: str,
        authorization: str | None = Header(default=None),
    ) -> PromptVersionRecord | JSONResponse:
        try:
            tok = extract_bearer_token(authorization)
            return svc.promote_prompt_version(bearer_token=tok, version_id=version_id)
        except MissingBearerTokenError as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})
        except PromptPromotionError as exc:
            return JSONResponse(
                status_code=422,
                content={
                    "error": "shadow_replay_gate_failed",
                    "message": exc.message,
                    "replay_summary": exc.replay_summary.model_dump(),
                },
            )
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return JSONResponse(status_code=403, content={"error": str(exc)})

    @app.post("/v1/admin/secrets", response_model=None)
    def rotate_secret(
        req: RotateConnectorSecretRequest,
        authorization: str | None = Header(default=None),
    ) -> MaskedConnectorSecret | JSONResponse:
        try:
            tok = extract_bearer_token(authorization)
            return svc.rotate_connector_secret(
                bearer_token=tok,
                connector_name=req.connector_name,
                raw_secret=req.raw_secret_value,
            )
        except MissingBearerTokenError as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return JSONResponse(status_code=403, content={"error": str(exc)})

    @app.get("/v1/admin/traces", response_model=None)
    def list_traces(
        authorization: str | None = Header(default=None),
    ) -> list[TraceSpanSummary] | JSONResponse:
        try:
            tok = extract_bearer_token(authorization)
            return svc.inspect_otel_traces(bearer_token=tok)
        except MissingBearerTokenError as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return JSONResponse(status_code=403, content={"error": str(exc)})

    @app.get("/v1/admin/finops", response_model=None)
    def finops_dashboard(
        authorization: str | None = Header(default=None),
    ) -> list[DepartmentROIReport] | JSONResponse:
        try:
            tok = extract_bearer_token(authorization)
            return svc.get_finops_dashboard(bearer_token=tok)
        except MissingBearerTokenError as exc:
            return JSONResponse(status_code=401, content={"error": str(exc)})
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return JSONResponse(status_code=403, content={"error": str(exc)})

    return app
