"""FastAPI HTTP service for Project 4: Row-Level Secure RAG Engine (Streamlined)."""

from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis_core.http_middleware import install_aegis_http_layer, require_bearer_token
from aegis_core.models import RetrievalQuery, RetrievalResponse, ScoredChunk
from secure_rag_engine.engine import RetrievalAuthorizationError, SecureRAGEngine
from secure_rag_engine.reranker_grounding import CitationVerificationResult


class VerifyCitationsRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    answer_text: str = Field(min_length=2, max_length=16_000)
    authorized_chunks: list[ScoredChunk]


def create_rag_app(engine: SecureRAGEngine) -> FastAPI:
    """Create observable FastAPI application for zero-trust RLS hybrid retrieval & grounding."""
    app = FastAPI(
        title="Aegis Row-Level Secure RAG Engine",
        version="0.3.0",
        docs_url="/docs",
    )
    install_aegis_http_layer(app, service_name="secure-rag-engine")

    @app.post("/v1/retrieve", response_model=RetrievalResponse)
    def retrieve(
        req: RetrievalQuery,
        token: str = Depends(require_bearer_token),
    ) -> RetrievalResponse | JSONResponse:
        try:
            return engine.retrieve(bearer_token=token, request=req)
        except RetrievalAuthorizationError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": "unauthorized", "error_description": exc.message},
            )

    @app.post("/v1/verify-citations", response_model=CitationVerificationResult)
    def verify_citations_endpoint(req: VerifyCitationsRequest) -> CitationVerificationResult:
        return engine.verify_citations(
            answer_text=req.answer_text,
            authorized_chunks=req.authorized_chunks,
        )

    return app
