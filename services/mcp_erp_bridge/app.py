"""FastAPI Streamable HTTP JSON-RPC 2.0 transport for Project 5 MCP-to-ERP Bridge."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from aegis_core.http_middleware import install_aegis_http_layer

if TYPE_CHECKING:
    from mcp_erp_bridge.bridge import MCPERPBridgeServer


class JSONRPCRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] | None = None


def create_mcp_erp_app(mcp_server: MCPERPBridgeServer) -> FastAPI:
    """Create observable HTTP JSON-RPC 2.0 transport for the MCP-to-SAP SOAP Bridge."""
    app = FastAPI(title="Aegis MCP-to-SAP SOAP Bridge", version="0.2.0")
    install_aegis_http_layer(app, service_name="mcp-erp-bridge")

    @app.post("/mcp")
    def post_mcp(
        rpc: JSONRPCRequest,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        token: str | None = None
        if authorization and authorization.startswith("Bearer "):
            token = authorization.removeprefix("Bearer ").strip()
        resp = mcp_server.handle_jsonrpc(rpc, bearer_token=token)
        return JSONResponse(status_code=200, content=resp)

    return app
