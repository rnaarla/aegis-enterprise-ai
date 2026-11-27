"""AST Architectural Fitness Suite enforcing Hexagonal Rings, Port Decoupling & Test Hygiene.

Guards against architectural erosion by statically inspecting Python AST import graphs across
`packages/`, `services/`, and `tests/`, plus verifying deterministic SQLite resource lifecycles.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from finops_telemetry.engine import FinOpsTelemetryEngine
from mcp_erp_bridge.wsdl_compiler import DurableIdempotencyOutbox

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]

DOMAIN_SERVICES: frozenset[str] = frozenset(
    {
        "sso_delegation_broker",
        "airgap_verifier",
        "legacy_ingestor",
        "secure_rag_engine",
        "mcp_erp_bridge",
        "pii_unmasking_proxy",
        "temporal_approval_gate",
        "edge_triage_router",
        "finops_telemetry",
        "shadow_replay_harness",
        "arch_scoper",
        "admin_control_plane",
    }
)


def _imported_top_level_modules(py_path: Path) -> set[str]:
    tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_aegis_core_has_zero_outward_dependencies() -> None:
    """Innermost Hexagonal Kernel (`packages/aegis_core`) must never import services or twin."""
    forbidden = DOMAIN_SERVICES | {"runtime_host", "services", "enterprise_twin"}
    violations: list[str] = []
    for py_file in sorted((REPO_ROOT / "packages" / "aegis_core").rglob("*.py")):
        bad = _imported_top_level_modules(py_file) & forbidden
        if bad:
            violations.append(f"{py_file.relative_to(REPO_ROOT)} -> {sorted(bad)}")
    assert violations == [], f"Outward kernel dependency violation: {violations}"


def test_domain_services_never_import_enterprise_twin_or_runtime_host() -> None:
    """All 12 domain services must remain 100% decoupled from `enterprise_twin` and `runtime_host`."""
    forbidden = {"enterprise_twin", "runtime_host"}
    violations: list[str] = []
    for svc in sorted(DOMAIN_SERVICES):
        for py_file in sorted((REPO_ROOT / "services" / svc).rglob("*.py")):
            bad = _imported_top_level_modules(py_file) & forbidden
            if bad:
                violations.append(f"{py_file.relative_to(REPO_ROOT)} -> {sorted(bad)}")
    assert violations == [], f"Domain service coupled to outer ring: {violations}"


def test_peer_services_program_to_aegis_core_ports_not_concrete_implementations() -> None:
    """Services must depend on `aegis_core.ports` rather than importing peer concrete services."""
    violations: list[str] = []
    for svc in sorted(DOMAIN_SERVICES):
        for py_file in sorted((REPO_ROOT / "services" / svc).rglob("*.py")):
            imports = _imported_top_level_modules(py_file)
            # 1. No peer service may import `sso_delegation_broker` (must use TokenVerifierPort/TokenBrokerPort)
            if svc != "sso_delegation_broker" and "sso_delegation_broker" in imports:
                violations.append(
                    f"{py_file.relative_to(REPO_ROOT)} imports concrete sso_delegation_broker"
                )
            # 2. `temporal_approval_gate` must use `MCPToolCallerPort`, not `mcp_erp_bridge`
            if svc != "mcp_erp_bridge" and "mcp_erp_bridge" in imports:
                violations.append(
                    f"{py_file.relative_to(REPO_ROOT)} imports concrete mcp_erp_bridge"
                )
            # 3. `edge_triage_router` and `pii_unmasking_proxy` share `aegis_core.pii_scanner`, not each other
            if svc == "edge_triage_router" and "pii_unmasking_proxy" in imports:
                violations.append(
                    f"{py_file.relative_to(REPO_ROOT)} imports concrete pii_unmasking_proxy"
                )
            if svc == "pii_unmasking_proxy" and "edge_triage_router" in imports:
                violations.append(
                    f"{py_file.relative_to(REPO_ROOT)} imports concrete edge_triage_router"
                )
    assert violations == [], f"Peer service coupling violation: {violations}"


def test_three_tier_test_directory_hygiene() -> None:
    """`tests/` root must contain zero loose `test_*.py` files; all belong in unit/integration/system."""
    loose_tests = sorted(p.name for p in (REPO_ROOT / "tests").glob("test_*.py"))
    assert loose_tests == [], f"Loose root test files found outside tier directories: {loose_tests}"


def test_deterministic_sqlite_resource_context_managers(tmp_path: Path) -> None:
    """Verify `DurableIdempotencyOutbox` and `FinOpsTelemetryEngine` close cleanly via `with`."""
    outbox_db = tmp_path / "outbox_ctx.sqlite3"
    with DurableIdempotencyOutbox(outbox_db) as outbox:
        outbox.put("idem-ctx-1", "fp-sha256", {"po_number": "4500099999"})
        assert outbox.get("idem-ctx-1") == ("fp-sha256", {"po_number": "4500099999"})

    finops_db = tmp_path / "finops_ctx.sqlite3"
    with FinOpsTelemetryEngine(db_path=finops_db) as engine:
        engine.configure_budget("meridian-fin", "SEC_OPS", 250.0)
        gate = engine.evaluate_budget_gate(
            tenant_id="meridian-fin",
            cost_center="SEC_OPS",
            requested_model_id="gpt-5-enterprise",
            estimated_cost_usd=10.0,
        )
        assert gate.decision == "ALLOW_REQUESTED_MODEL"
