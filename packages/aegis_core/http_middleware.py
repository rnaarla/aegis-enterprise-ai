"""Shared FastAPI observability middleware, `/readyz` probes, and DRY Bearer extraction."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


class MissingBearerTokenError(PermissionError):
    """Raised when an endpoint requires an RFC 8693 `Authorization: Bearer <jwt>` header."""


def extract_bearer_token(authorization: str | None) -> str:
    """Extract Bearer token cleanly without duplicating header parsing across services."""
    if not authorization or not authorization.startswith("Bearer "):
        raise MissingBearerTokenError("Bearer JWT required in Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise MissingBearerTokenError("Empty Bearer token")
    return token


def install_aegis_http_layer(
    app: FastAPI,
    *,
    service_name: str,
    readiness_check: Callable[[], bool] | None = None,
) -> None:
    """Install `X-Request-ID` / W3C `traceparent` correlation headers + `/healthz` & `/readyz`."""

    @app.middleware("http")
    async def _correlation_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        req_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:16]}"
        traceparent = (
            request.headers.get("traceparent")
            or f"00-{uuid.uuid4().hex}-{uuid.uuid4().hex[:16]}-01"
        )
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        response.headers["traceparent"] = traceparent
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": service_name}

    @app.get("/readyz", response_model=None)
    def readyz() -> dict[str, str] | JSONResponse:
        if readiness_check is not None and not readiness_check():
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "service": service_name},
            )
        return {"status": "ready", "service": service_name}
