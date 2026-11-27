"""Shared FastAPI SRE Observability Middleware, DRY Auth Dependencies & Exception Handlers."""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from aegis_core.crypto import TokenVerificationError
from aegis_core.ports import DelegationPolicyError
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry

logger = logging.getLogger("aegis.sre")


class MissingBearerTokenError(PermissionError):
    """Raised when an endpoint requires an RFC 8693 `Authorization: Bearer/DPoP <jwt>` header."""


def extract_bearer_token(authorization: str | None) -> str:
    """Extract `Bearer` or `DPoP` token cleanly without duplicating header parsing."""
    if not authorization:
        raise MissingBearerTokenError("JWT required in Authorization header")
    if authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    elif authorization.startswith("DPoP "):
        token = authorization.removeprefix("DPoP ").strip()
    else:
        raise MissingBearerTokenError("Authorization scheme must be Bearer or DPoP")
    if not token:
        raise MissingBearerTokenError("Empty authorization token")
    return token


def require_bearer_token(authorization: str | None = Header(default=None)) -> str:
    """Reusable FastAPI `Depends(require_bearer_token)` failing fast at the HTTP boundary."""
    return extract_bearer_token(authorization)


class ServiceLifecycleState:
    """Tracks graceful shutdown/drain state for zero-drop Kubernetes rolling deployments."""

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self._lock = threading.Lock()
        self._draining = False
        self._inflight = 0

    @property
    def is_draining(self) -> bool:
        with self._lock:
            return self._draining

    @property
    def inflight_requests(self) -> int:
        with self._lock:
            return self._inflight

    def begin_drain(self) -> None:
        """Flip `/readyz` to `503 draining` so K8s Endpoints stop sending new requests."""
        with self._lock:
            self._draining = True

    def resume_traffic(self) -> None:
        with self._lock:
            self._draining = False

    def on_request_start(self) -> None:
        with self._lock:
            self._inflight += 1

    def on_request_end(self) -> None:
        with self._lock:
            self._inflight = max(0, self._inflight - 1)


def emit_structured_sre_log(
    *,
    service: str,
    event: str,
    request_id: str,
    traceparent: str,
    status_code: int,
    duration_ms: float,
    runbook_ref: str | None = None,
) -> str:
    """Format PII-free structured JSON operational log record for OTLP / FluentBit ingestion."""
    payload: dict[str, Any] = {
        "service": service,
        "event": event,
        "request_id": request_id,
        "traceparent": traceparent,
        "status_code": status_code,
        "duration_ms": round(duration_ms, 3),
    }
    if runbook_ref:
        payload["runbook_ref"] = runbook_ref
    encoded = json.dumps(payload, sort_keys=True)
    logger.debug(encoded)
    return encoded


def install_aegis_http_layer(
    app: FastAPI,
    *,
    service_name: str,
    readiness_check: Callable[[], bool] | None = None,
    dependency_checks: dict[str, Callable[[], bool]] | None = None,
    sli_registry: SLIRegistry | None = None,
    token_error_status_code: int = 401,
) -> ServiceLifecycleState:
    """Install Golden Signal SLIs, boundary exception handlers, `/metrics`, `/readyz` & drain."""
    registry = sli_registry if sli_registry is not None else GLOBAL_SLI_REGISTRY
    lifecycle = ServiceLifecycleState(service_name)
    app.state.aegis_lifecycle = lifecycle
    app.state.aegis_sli_registry = registry

    @app.exception_handler(MissingBearerTokenError)
    async def _handle_missing_bearer(_req: Request, exc: MissingBearerTokenError) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"error": "missing_bearer_token", "error_description": str(exc)},
        )

    @app.exception_handler(TokenVerificationError)
    async def _handle_bad_token(_req: Request, exc: TokenVerificationError) -> JSONResponse:
        return JSONResponse(
            status_code=token_error_status_code,
            content={"error": "invalid_token", "error_description": str(exc)},
        )

    @app.exception_handler(DelegationPolicyError)
    async def _handle_policy_error(_req: Request, exc: DelegationPolicyError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.oauth_error, "error_description": exc.description},
        )

    @app.middleware("http")
    async def _sre_observability_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        req_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:16]}"
        traceparent = (
            request.headers.get("traceparent")
            or f"00-{uuid.uuid4().hex}-{uuid.uuid4().hex[:16]}-01"
        )
        t0 = time.perf_counter()
        lifecycle.on_request_start()
        registry.add_gauge("aegis_http_in_flight_requests", 1.0, {"service": service_name})
        try:
            response = await call_next(request)
        finally:
            dur_s = max(0.0, time.perf_counter() - t0)
            lifecycle.on_request_end()
            registry.add_gauge("aegis_http_in_flight_requests", -1.0, {"service": service_name})

        route_path = request.url.path
        if route_path not in ("/healthz", "/readyz", "/metrics"):
            registry.record_sli_request(
                service_name=service_name,
                method=request.method,
                route=route_path,
                status_code=response.status_code,
                duration_seconds=dur_s,
            )
            runbook = (
                f"https://runbooks.aegis.internal/{service_name}#http-{response.status_code}"
                if response.status_code >= 500
                else None
            )
            emit_structured_sre_log(
                service=service_name,
                event="http.request.completed",
                request_id=req_id,
                traceparent=traceparent,
                status_code=response.status_code,
                duration_ms=dur_s * 1000.0,
                runbook_ref=runbook,
            )

        response.headers["X-Request-ID"] = req_id
        response.headers["traceparent"] = traceparent
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": service_name,
            "inflight_requests": lifecycle.inflight_requests,
        }

    @app.get("/readyz", response_model=None)
    def readyz() -> dict[str, Any] | JSONResponse:
        if lifecycle.is_draining:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "draining",
                    "service": service_name,
                    "inflight_requests": lifecycle.inflight_requests,
                    "runbook_ref": f"https://runbooks.aegis.internal/{service_name}#sigterm-drain",
                },
            )
        dep_results: dict[str, bool] = {}
        if dependency_checks:
            for dep_name, probe_fn in dependency_checks.items():
                try:
                    dep_results[dep_name] = bool(probe_fn())
                except Exception:
                    dep_results[dep_name] = False
        primary_ok = True if readiness_check is None else bool(readiness_check())
        all_ok = primary_ok and all(dep_results.values())
        if not all_ok:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "service": service_name,
                    "dependencies": dep_results,
                    "runbook_ref": f"https://runbooks.aegis.internal/{service_name}#dependency-down",
                },
            )
        return {"status": "ready", "service": service_name, "dependencies": dep_results}

    @app.post("/v1/ops/drain")
    def trigger_graceful_drain() -> dict[str, Any]:
        """Kubernetes `preStop` lifecycle hook endpoint initiating zero-drop drain."""
        lifecycle.begin_drain()
        return {
            "status": "draining",
            "service": service_name,
            "inflight_requests": lifecycle.inflight_requests,
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    def prometheus_metrics() -> PlainTextResponse:
        return PlainTextResponse(
            content=registry.render_prometheus_text(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/v1/sli/summary")
    def sli_summary() -> dict[str, Any]:
        slo = registry.evaluate_slo(service_name)
        lat = registry.histogram_snapshot("aegis_http_request_duration_seconds")
        return {
            "service": service_name,
            "slo": {
                "target_availability": slo.target_availability,
                "observed_availability": slo.observed_availability,
                "total_requests": slo.total_requests,
                "error_requests": slo.error_requests,
                "error_budget_remaining_ratio": slo.error_budget_remaining_ratio,
                "burn_rate_short_window": slo.burn_rate_short_window,
                "burn_rate_long_window": slo.burn_rate_long_window,
                "page_alert_fast_burn_14_4x": slo.page_alert_fast_burn_14_4x,
                "ticket_alert_slow_burn_6x": slo.ticket_alert_slow_burn_6x,
            },
            "latency_seconds": {
                "count": lat.count,
                "p50": lat.p50_seconds,
                "p95": lat.p95_seconds,
                "p99": lat.p99_seconds,
            },
        }

    return lifecycle
