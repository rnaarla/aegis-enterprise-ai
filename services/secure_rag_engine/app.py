"""FastAPI HTTP service for Project 4: Row-Level Secure RAG Engine."""

from __future__ import annotations

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

from aegis_core.http_middleware import (
    MissingBearerTokenError,
    extract_bearer_token,
    install_aegis_http_layer,
)
from aegis_core.models import RetrievalQuery, RetrievalResponse
from secure_rag_engine.engine import RetrievalAuthorizationError, SecureRAGEngine


def create_rag_app(engine: SecureRAGEngine) -> FastAPI:
    """Create observable FastAPI application for zero-trust RLS hybrid retrieval."""
    app = FastAPI(
        title="Aegis Row-Level Secure RAG Engine",
        version="0.2.0",
        docs_url="/docs",
    )
    install_aegis_http_layer(app, service_name="secure-rag-engine")

    @app.post("/v1/retrieve", response_model=RetrievalResponse)
    def retrieve(
        req: RetrievalQuery,
        authorization: str | None = Header(default=None),
    ) -> RetrievalResponse | JSONResponse:
        try:
            token = extract_bearer_token(authorization)
            return engine.retrieve(bearer_token=token, request=req)
        except MissingBearerTokenError as exc:
            return JSONResponse(
                status_code=401,
                content={"error": "missing_token", "error_description": str(exc)},
            )
        except RetrievalAuthorizationError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": "unauthorized", "error_description": exc.message},
            )

    return app
