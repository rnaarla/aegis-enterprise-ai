"""Domain MCP JSON-RPC 2.0 Dispatcher with AIMD Congestion Control, Durable WAL Outbox & Saga."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from aegis_core.aimd import AIMDConcurrencyLimiter, BackpressureShedError
from aegis_core.crypto import TokenVerificationError
from aegis_core.dsa import BoundedLRUTTLCache
from aegis_core.models import AuditEventType, DelegatedTokenClaims
from aegis_core.ports import AuditLedgerPort
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry
from aegis_core.telemetry import AegisTelemetry
from mcp_erp_bridge.app import JSONRPCRequest, create_mcp_erp_app
from mcp_erp_bridge.soap_client import (
    DirectInProcessSOAPTransport,
    HttpSOAPTransport,
    SOAPTransportPort,
    build_wsse_soap_envelope,
    parse_sap_bapiret2_response,
)
from mcp_erp_bridge.wsdl_compiler import (
    DurableIdempotencyOutbox,
    MultiERPSagaCoordinator,
    compile_wsdl_to_mcp_tools,
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
        durable_outbox_path: Path | None = None,
        aimd_limiter: AIMDConcurrencyLimiter | None = None,
        enforce_preflight_testrun: bool = True,
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self._broker = broker
        self._soap = soap_transport
        self._audit = audit_ledger
        self._wsse_user = wsse_username
        self._wsse_pass = wsse_credential
        self._telemetry = telemetry or AegisTelemetry("aegis-mcp-erp-bridge")
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY
        self._aimd = aimd_limiter or AIMDConcurrencyLimiter(
            "sap-abap-dialog-pool", initial_limit=24, min_limit=2, max_limit=64
        )
        self._enforce_testrun = enforce_preflight_testrun
        self._idempotency_cache: BoundedLRUTTLCache[str, tuple[str, dict[str, Any]]] = (
            BoundedLRUTTLCache(
                max_size=idempotency_max_entries,
                default_ttl_seconds=idempotency_ttl_seconds,
            )
        )
        self._durable_outbox = (
            DurableIdempotencyOutbox(durable_outbox_path)
            if durable_outbox_path is not None
            else None
        )
        self._saga = MultiERPSagaCoordinator()

    @property
    def aimd_limiter(self) -> AIMDConcurrencyLimiter:
        return self._aimd

    def introspect_wsdl_tools(self, wsdl_xml: bytes) -> list[dict[str, Any]]:
        """Auto-compile customer WSDL XML operations into MCP tool JSON Schemas."""
        return compile_wsdl_to_mcp_tools(wsdl_xml, namespace_prefix="sap")

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
                    "serverInfo": {"name": "aegis-sap-erp-mcp", "version": "0.3.0"},
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

        try:
            with (
                self._aimd.acquire() as current_window,
                self._telemetry.span(
                    "aegis.mcp.tool_call",
                    {
                        "mcp.tool.name": tool_name,
                        "aegis.sub": claims.sub,
                        "aegis.actor_id": claims.act.sub,
                        "aegis.jti": claims.jti,
                        "aegis.aimd_limit": current_window,
                    },
                ),
            ):
                self._sli.set_gauge("aegis_mcp_aimd_concurrency_limit", float(current_window))
                if tool_name == "sap_get_vendor_status":
                    return self._call_vendor_getdetail(rpc_id, claims, args)
                if tool_name == "sap_simulate_purchase_order":
                    return self._call_po_create(rpc_id, claims, args, dry_run=True)
                if tool_name == "sap_create_purchase_order":
                    return self._call_po_create(rpc_id, claims, args, dry_run=False)
                if tool_name == "sap_cancel_purchase_order":
                    return self._call_po_cancel(rpc_id, claims, args)
                return self._rpc_error(rpc_id, -32602, f"Unknown ERP tool: {tool_name!r}")
        except BackpressureShedError as exc:
            self._sli.inc_counter("aegis_mcp_aimd_shed_total", 1.0)
            return self._rpc_error(
                rpc_id,
                -32005,
                f"SAP ABAP adaptive concurrency protection shed request: {exc}",
            )

    def _soap_call(self, operation: str, params: dict[str, str]) -> tuple[int, bytes]:
        env = build_wsse_soap_envelope(
            operation,
            params,
            wsse_username=self._wsse_user,
            wsse_credential=self._wsse_pass,
        )
        return self._soap.post_envelope(env)

    def _get_idempotent_entry(self, key: str) -> tuple[str, dict[str, Any]] | None:
        hit = self._idempotency_cache.get(key)
        if hit is not None:
            return hit
        if self._durable_outbox is not None:
            durable_hit = self._durable_outbox.get(key)
            if durable_hit is not None:
                self._idempotency_cache.put(key, durable_hit)
                return durable_hit
        return None

    def _put_idempotent_entry(
        self, key: str, fingerprint: str, payload: dict[str, Any]
    ) -> None:
        self._idempotency_cache.put(key, (fingerprint, payload))
        if self._durable_outbox is not None:
            self._durable_outbox.put(key, fingerprint, payload)

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

    def _call_po_cancel(
        self,
        rpc_id: int | str | None,
        claims: DelegatedTokenClaims,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        po_number = str(args.get("po_number", "")).strip()
        status, resp_bytes = self._soap_call("BAPI_PO_CANCEL", {"EBELN": po_number})
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
                "po_number": fields.get("EBELN", po_number),
                "cancelled": fields.get("CANCELLED", "") == "X",
                "sap_return": bapi_ret,
                "reversed_by": claims.sub,
            },
        )

    def execute_po_with_downstream_saga(
        self,
        *,
        bearer_token: str,
        po_args: dict[str, Any],
        downstream_step: Any,
    ) -> dict[str, Any]:
        """Create SAP PO and automatically compensate (`BAPI_PO_CANCEL`) if downstream step fails."""

        def _create_step() -> dict[str, Any]:
            rpc = self.handle_jsonrpc(
                JSONRPCRequest(
                    id="saga-po",
                    method="tools/call",
                    params={"name": "sap_create_purchase_order", "arguments": po_args},
                ),
                bearer_token=bearer_token,
            )
            res = dict(rpc.get("result", {}).get("structuredContent", {}))
            if rpc.get("result", {}).get("isError", True):
                raise RuntimeError(f"SAP PO step failed: {res}")
            return res

        def _compensate_po(created: dict[str, Any]) -> None:
            ebeln = str(created.get("po_number", ""))
            if ebeln:
                self.handle_jsonrpc(
                    JSONRPCRequest(
                        id="saga-cancel",
                        method="tools/call",
                        params={
                            "name": "sap_cancel_purchase_order",
                            "arguments": {"po_number": ebeln},
                        },
                    ),
                    bearer_token=bearer_token,
                )
                self._sli.inc_counter("aegis_mcp_saga_compensations_total", 1.0)

        ok, results, compensated = self._saga.execute_saga(
            [
                ("sap_po_create", _create_step, _compensate_po),
                ("downstream_partner_sync", downstream_step, lambda _r: None),
            ]
        )
        return {"saga_succeeded": ok, "step_results": results, "compensated_steps": compensated}

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

        # Enforce RFC 9396 RAR `sap_po` max_amount_usd ceiling if present on token
        rar_max_usd: float | None = None
        for detail in claims.authorization_details:
            if detail.type == "sap_po" and detail.max_amount_usd is not None:
                rar_max_usd = detail.max_amount_usd

        if not dry_run:
            if not idempotency_key:
                return self._rpc_error(
                    rpc_id, -32602, "idempotency_key is mandatory for SAP write operations"
                )
            eff_limit = (
                min(float(claims.po_approval_limit_usd), rar_max_usd)
                if rar_max_usd is not None
                else float(claims.po_approval_limit_usd)
            )
            if amount_usd > eff_limit or (
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
                        "principal_limit_usd": eff_limit,
                    },
                )
                return self._mcp_tool_result(
                    rpc_id,
                    is_error=True,
                    payload={
                        "error": "temporal_approval_required",
                        "message": (
                            f"PO amount USD {amount_usd:,.2f} exceeds autonomous authority "
                            f"(limit USD {eff_limit:,.2f}); route via Temporal Gate."
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

            existing = self._get_idempotent_entry(idempotency_key)
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

            # Mandatory SAP `TESTRUN='X'` pre-flight validation prior to live commit
            if self._enforce_testrun:
                sim_status, sim_bytes = self._soap_call(
                    "BAPI_PO_CREATE1",
                    {
                        "LIFNR": vendor_id,
                        "BUKRS": company_code,
                        "TXZ01": description,
                        "NETPR": f"{amount_usd:.2f}",
                        "ERNAM": claims.sub,
                        "AFNAM": claims.sub if "erp:po:approve" in claims.scopes else "",
                        "TESTRUN": "X",
                    },
                )
                if sim_status == 200:
                    _, sim_ret = parse_sap_bapiret2_response(sim_bytes)
                    if sim_ret["type"] in ("E", "A"):
                        return self._mcp_tool_result(
                            rpc_id,
                            is_error=True,
                            payload={
                                "po_number": "",
                                "vendor_id": vendor_id,
                                "amount_usd": amount_usd,
                                "dry_run": True,
                                "sap_return": sim_ret,
                                "idempotent_replay": False,
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
            self._put_idempotent_entry(idempotency_key, payload_fingerprint, result_payload)
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
            {
                "name": "sap_cancel_purchase_order",
                "description": "Execute compensating SAP BAPI_PO_CANCEL reversal for Saga rollback.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"po_number": {"type": "string"}},
                    "required": ["po_number"],
                },
            },
        ]


__all__ = [
    "DirectInProcessSOAPTransport",
    "DurableIdempotencyOutbox",
    "HttpSOAPTransport",
    "JSONRPCRequest",
    "MCPERPBridgeServer",
    "MultiERPSagaCoordinator",
    "SOAPTransportPort",
    "compile_wsdl_to_mcp_tools",
    "create_mcp_erp_app",
]
