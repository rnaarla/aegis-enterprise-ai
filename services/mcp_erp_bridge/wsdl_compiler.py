"""Project 5 V2: XXE-Hardened WSDL-to-MCP Compiler, Durable WAL Outbox & Saga Coordinator."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from lxml import etree

_XSD_TYPE_MAP: dict[str, str] = {
    "string": "string",
    "decimal": "number",
    "float": "number",
    "double": "number",
    "int": "integer",
    "integer": "integer",
    "long": "integer",
    "boolean": "boolean",
}


def compile_wsdl_to_mcp_tools(wsdl_xml: bytes, *, namespace_prefix: str = "sap") -> list[dict[str, Any]]:
    """Introspect raw enterprise WSDL 1.1 / XSD XML and emit strict MCP JSON Schema tool specs."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(wsdl_xml, parser=parser)

    # Index top-level XSD complexType/element sequences by name
    element_schemas: dict[str, tuple[dict[str, dict[str, str]], list[str]]] = {}
    for elem in root.xpath("//*[local-name()='schema']/*[local-name()='element']"):
        elem_name = str(elem.get("name", "")).strip()
        if not elem_name:
            continue
        props: dict[str, dict[str, str]] = {}
        req: list[str] = []
        for child in elem.xpath(".//*[local-name()='sequence']/*[local-name()='element']"):
            f_name = str(child.get("name", "")).strip()
            raw_type = str(child.get("type", "xsd:string")).split(":")[-1].lower()
            min_occurs = str(child.get("minOccurs", "1"))
            if f_name:
                props[f_name] = {"type": _XSD_TYPE_MAP.get(raw_type, "string")}
                if min_occurs != "0":
                    req.append(f_name)
        element_schemas[elem_name] = (props, req)

    tools: list[dict[str, Any]] = []
    for op in root.xpath("//*[local-name()='portType']/*[local-name()='operation']"):
        op_name = str(op.get("name", "")).strip()
        if not op_name:
            continue
        doc_nodes = op.xpath("./*[local-name()='documentation']/text()")
        doc_text = (
            str(doc_nodes[0]).strip()
            if doc_nodes
            else f"Auto-compiled WSDL operation {op_name}"
        )
        props, req = element_schemas.get(op_name, ({}, []))
        tools.append(
            {
                "name": f"{namespace_prefix}_{op_name.lower()}",
                "wsdl_operation": op_name,
                "description": doc_text,
                "inputSchema": {
                    "type": "object",
                    "properties": props,
                    "required": req,
                },
            }
        )
    if not tools:
        raise ValueError("WSDL document contains zero portType operations")
    return tools


class DurableIdempotencyOutbox:
    """Crash-safe SQLite WAL (`PRAGMA synchronous=FULL`) store for multi-day ERP idempotency keys."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._uri = str(db_path) if db_path is not None else ":memory:"
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._uri, check_same_thread=False)
        if db_path is not None:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_idempotency_outbox (
                    idempotency_key     TEXT PRIMARY KEY,
                    payload_fingerprint TEXT NOT NULL,
                    response_json       TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    def get(self, key: str) -> tuple[str, dict[str, Any]] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload_fingerprint, response_json FROM mcp_idempotency_outbox WHERE idempotency_key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return str(row[0]), dict(json.loads(str(row[1])))

    def put(self, key: str, fingerprint: str, response_payload: dict[str, Any]) -> None:
        encoded = json.dumps(response_payload, sort_keys=True)
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO mcp_idempotency_outbox (
                    idempotency_key, payload_fingerprint, response_json
                ) VALUES (?, ?, ?)
                """,
                (key, fingerprint, encoded),
            )
            self._conn.commit()


class MultiERPSagaCoordinator:
    """Executes multi-step ERP workflows and triggers reverse BAPI compensations on downstream failure."""

    def execute_saga(
        self,
        steps: list[tuple[str, Callable[[], dict[str, Any]], Callable[[dict[str, Any]], None]]],
    ) -> tuple[bool, list[dict[str, Any]], list[str]]:
        """Run `(step_name, forward_fn, compensate_fn)` in sequence; unwind in LIFO order on error."""
        completed: list[tuple[str, dict[str, Any], Callable[[dict[str, Any]], None]]] = []
        compensated_names: list[str] = []
        try:
            for step_name, forward_fn, comp_fn in steps:
                res = forward_fn()
                completed.append((step_name, res, comp_fn))
            return True, [r for _, r, _ in completed], []
        except Exception:
            for step_name, res, comp_fn in reversed(completed):
                comp_fn(res)
                compensated_names.append(step_name)
            return False, [r for _, r, _ in completed], compensated_names
