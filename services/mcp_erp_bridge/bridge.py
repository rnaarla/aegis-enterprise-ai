"""Domain MCP JSON-RPC 2.0 Dispatcher with $O(1)$ Bounded LRU-TTL Write Idempotency."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from aegis_core.crypto import TokenVerificationError
from aegis_core.dsa import BoundedLRUTTLCache
from aegis_core.models import AuditEventType, DelegatedTokenClaims
from aegis_core.ports import AuditLedgerPort
from aegis_core.telemetry import AegisTelemetry
from mcp_erp_bridge.app import JSONRPCRequest, create_mcp_erp_app
from mcp_erp_bridge.soap_client import (
    DirectInProcessSOAPTransport,
    HttpSOAPTransport,
    SOAPTransportPort,
    build_wsse_soap_envelope,
    parse_sap_bapiret2_response,
)
from sso_delegation_broker.broker import DelegationPolicyError, SSODelegationBroker

PO_EXECUTIVE_GATE_USD = 50_000.0


class MCPERPBridgeServer:
    """Standards-compliant JSON-RPC 2.0 MCP Server bridging AI agents to SAP BAPI SOAP."""

    def __init__(
        self,
        *,
        broker: SSODelegationBroker,
        soap_transport: SOAPTransportPort,
        audit_ledger: AuditLedgerPort,
        wsse_username: str = "SVC_AEGIS_RFC",
        wsse_credential: str = "sap_rfc_twin_credential",
        telemetry: AegisTelemetry | None = None,
        idempotency_max_entries: int = 50_000,
        idempotency_ttl_seconds: float = 86_400.0,
    ) -> None:
        self._broker = broker
        self._soap = soap_transport
        self._audit = audit_ledger
        self._wsse_user = wsse_username
        self._wsse_pass = wsse_credential
        self._telemetry = telemetry or AegisTelemetry("aegis-mcp-erp-bridge")
        # Bounded $O(1)$ LRU-TTL cache prevents unbounded memory growth over multi-week uptime
        self._idempotency_cache: BoundedLRUTTLCache[str, tuple[str, dict[str, Any]]] = (
            BoundedLRUTTLCache(
                max_size=idempotency_max_entries,
                default_ttl_seconds=idempotency_ttl_seconds,
            )
        )

    def handle_jsonrpc(
        self,
        rpc: JSONRPCRequest,
        *,
        bearer_token: str | None,
    ) -> dict[str, Any]:
        if rpc.jsonrpc != "2.0":
            return self._rpc_error(rpc.id, -32600, "Invalid JSON-RPC version; expected '2.0'")

        if rpc.method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": rpc.id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "aegis-sap-erp-mcp", "version": "0.2.0"},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            }

        if rpc.method == "tools/list":
            return {"jsonrpc": "2.0", "id": rpc.id, "result": {"tools": self._tool_definitions()}}

        if rpc.method == "tools/call":
            if not bearer_token:
                return self._rpc_error(rpc.id, -32001, "Missing RFC 8693 Bearer token")
            params = rpc.params or {}
            tool_name = str(params.get("name", ""))
            raw_args = params.get("arguments", {})
            arguments = raw_args if isinstance(raw_args, dict) else {}
            return self._dispatch_tool_call(rpc.id, tool_name, arguments, bearer_token)

        return self._rpc_error(rpc.id, -32601, f"Unsupported MCP method: {rpc.method!r}")

    def _dispatch_tool_call(
        self,
        rpc_id: int | str | None,
        tool_name: str,
        args: dict[str, Any],
        bearer_token: str,
    ) -> dict[str, Any]:
        required_scope = "rag:read" if tool_name == "sap_get_vendor_status" else "erp:po:create"
        try:
            claims = self._broker.verify_and_check_revocation(
                bearer_token, required_scope=required_scope
            )
        except (TokenVerificationError, DelegationPolicyError) as exc:
            return self._rpc_error(rpc_id, -32003, f"Token authorization rejected: {exc}")

        with self._telemetry.span(
            "aegis.mcp.tool_call",
            {
                "mcp.tool.name": tool_name,
                "aegis.sub": claims.sub,
                "aegis.actor_id": claims.act.sub,
                "aegis.jti": claims.jti,
            },
        ):
            if tool_name == "sap_get_vendor_status":
                return self._call_vendor_getdetail(rpc_id, claims, args)
            if tool_name == "sap_simulate_purchase_order":
                return self._call_po_create(rpc_id, claims, args, dry_run=True)
            if tool_name == "sap_create_purchase_order":
                return self._call_po_create(rpc_id, claims, args, dry_run=False)
            return self._rpc_error(rpc_id, -32602, f"Unknown ERP tool: {tool_name!r}")

    def _soap_call(self, operation: str, params: dict[str, str]) -> tuple[int, bytes]:
        env = build_wsse_soap_envelope(
            operation,
            params,
            wsse_username=self._wsse_user,
            wsse_credential=self._wsse_pass,
        )
        return self._soap.post_envelope(env)

    def _call_vendor_getdetail(
        self,
        rpc_id: int | str | None,
        claims: DelegatedTokenClaims,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        vendor_id = str(args.get("vendor_id", "")).strip()
        status, resp_bytes = self._soap_call("BAPI_VENDOR_GETDETAIL", {"LIFNR": vendor_id})
        if status != 200:
            return self._mcp_tool_result(
                rpc_id,
                is_error=True,
                payload={"error": "soap_transport_fault", "http_status": status},
            )
        fields, bapi_ret = parse_sap_bapiret2_response(resp_bytes)
        return self._mcp_tool_result(
            rpc_id,
            is_error=bapi_ret["type"] in ("E", "A"),
            payload={
                "vendor_id": fields.get("LIFNR", vendor_id),
                "vendor_name": fields.get("NAME1", ""),
                "company_code": fields.get("BUKRS", ""),
                "purchasing_blocked": fields.get("SPERR", "") == "X",
                "bank_iban": fields.get("BANKN", ""),
                "state_etag": fields.get("STATE_ETAG", ""),
                "sap_return": bapi_ret,
                "queried_by": claims.sub,
            },
        )

    def _call_po_create(
        self,
        rpc_id: int | str | None,
        claims: DelegatedTokenClaims,
        args: dict[str, Any],
        *,
        dry_run: bool,
    ) -> dict[str, Any]:
        vendor_id = str(args.get("vendor_id", "")).strip()
        company_code = str(args.get("company_code", "1000")).strip()
        description = str(args.get("description", "")).strip()
        amount_usd = round(float(args.get("amount_usd", 0.0)), 2)
        idempotency_key = str(args.get("idempotency_key", "")).strip()
        expected_state_etag = str(args.get("expected_vendor_state_etag", "")).strip()
        payload_fingerprint = ""

        if not dry_run:
            if not idempotency_key:
                return self._rpc_error(
                    rpc_id, -32602, "idempotency_key is mandatory for SAP write operations"
                )
            if amount_usd > claims.po_approval_limit_usd or (
                amount_usd > PO_EXECUTIVE_GATE_USD and "erp:po:approve" not in claims.scopes
            ):
                self._audit.append(
                    tenant_id=claims.tenant_id,
                    event_type=AuditEventType.TOKEN_EXCHANGE_DENIED,
                    human_subject=claims.sub,
                    actor_id=claims.act.sub,
                    jti=claims.jti,
                    decision="DENY",
                    detail={
                        "tool": "sap_create_purchase_order",
                        "reason": "approval_gate_required",
                        "amount_usd": amount_usd,
                        "principal_limit_usd": claims.po_approval_limit_usd,
                    },
                )
                return self._mcp_tool_result(
                    rpc_id,
                    is_error=True,
                    payload={
                        "error": "temporal_approval_required",
                        "message": (
                            f"PO amount USD {amount_usd:,.2f} exceeds autonomous authority "
                            f"(limit USD {claims.po_approval_limit_usd:,}); route via Temporal Gate."
                        ),
                    },
                )

            payload_fingerprint = hashlib.sha256(
                json.dumps(
                    {
                        "vendor_id": vendor_id,
                        "company_code": company_code,
                        "description": description,
                        "amount_usd": amount_usd,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()

            existing = self._idempotency_cache.get(idempotency_key)
            if existing is not None:
                cached_fp, cached_res = existing
                if cached_fp != payload_fingerprint:
                    return self._rpc_error(
                        rpc_id,
                        -32009,
                        "Idempotency key conflict: reused key with different PO parameters",
                    )
                replay_copy = dict(cached_res)
                replay_copy["idempotent_replay"] = True
                return self._mcp_tool_result(rpc_id, is_error=False, payload=replay_copy)

            if expected_state_etag:
                _, v_bytes = self._soap_call("BAPI_VENDOR_GETDETAIL", {"LIFNR": vendor_id})
                v_fields, _ = parse_sap_bapiret2_response(v_bytes)
                live_etag = v_fields.get("STATE_ETAG", "")
                if live_etag and live_etag != expected_state_etag:
                    return self._mcp_tool_result(
                        rpc_id,
                        is_error=True,
                        payload={
                            "error": "toctou_erp_state_drift",
                            "expected_etag": expected_state_etag,
                            "actual_etag": live_etag,
                            "message": "Aborted SAP PO commit: vendor master record changed mid-approval",
                        },
                    )

        status, resp_bytes = self._soap_call(
            "BAPI_PO_CREATE1",
            {
                "LIFNR": vendor_id,
                "BUKRS": company_code,
                "TXZ01": description,
                "NETPR": f"{amount_usd:.2f}",
                "ERNAM": claims.sub,
                "AFNAM": claims.sub if "erp:po:approve" in claims.scopes else "",
                "TESTRUN": "X" if dry_run else "",
            },
        )
        if status != 200:
            return self._mcp_tool_result(
                rpc_id,
                is_error=True,
                payload={"error": "soap_transport_fault", "http_status": status},
            )

        fields, bapi_ret = parse_sap_bapiret2_response(resp_bytes)
        is_err = bapi_ret["type"] in ("E", "A")
        result_payload: dict[str, Any] = {
            "po_number": fields.get("EBELN", ""),
            "vendor_id": vendor_id,
            "amount_usd": amount_usd,
            "dry_run": dry_run,
            "vendor_state_etag": fields.get("STATE_ETAG", ""),
            "sap_return": bapi_ret,
            "idempotent_replay": False,
        }
        if not dry_run and not is_err:
            self._idempotency_cache.put(idempotency_key, (payload_fingerprint, result_payload))
        return self._mcp_tool_result(rpc_id, is_error=is_err, payload=result_payload)

    @staticmethod
    def _mcp_tool_result(
        rpc_id: int | str | None,
        *,
        is_error: bool,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "isError": is_error,
                "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
                "structuredContent": payload,
            },
        }

    @staticmethod
    def _rpc_error(rpc_id: int | str | None, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _tool_definitions() -> list[dict[str, Any]]:
        return [
            {
                "name": "sap_get_vendor_status",
                "description": "Read SAP S/4HANA vendor master status, bank IBAN, and anti-TOCTOU state ETag.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"vendor_id": {"type": "string"}},
                    "required": ["vendor_id"],
                },
            },
            {
                "name": "sap_simulate_purchase_order",
                "description": "Execute SAP BAPI_PO_CREATE1 in TESTRUN=X simulation mode without writing records.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vendor_id": {"type": "string"},
                        "company_code": {"type": "string"},
                        "description": {"type": "string"},
                        "amount_usd": {"type": "number"},
                    },
                    "required": ["vendor_id", "description", "amount_usd"],
                },
            },
            {
                "name": "sap_create_purchase_order",
                "description": "Commit an idempotent SAP Purchase Order with BAPIRET2 & TOCTOU verification.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vendor_id": {"type": "string"},
                        "company_code": {"type": "string"},
                        "description": {"type": "string"},
                        "amount_usd": {"type": "number"},
                        "idempotency_key": {"type": "string"},
                        "expected_vendor_state_etag": {"type": "string"},
                    },
                    "required": ["vendor_id", "description", "amount_usd", "idempotency_key"],
                },
            },
        ]


__all__ = [
    "DirectInProcessSOAPTransport",
    "HttpSOAPTransport",
    "JSONRPCRequest",
    "MCPERPBridgeServer",
    "SOAPTransportPort",
    "create_mcp_erp_app",
]
