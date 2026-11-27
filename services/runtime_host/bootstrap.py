"""Outer Composition Root (`IoC / Dependency Injection`) wiring ASGI services from env.

Lives in `services/runtime_host` (outer ring) rather than `packages/aegis_core` (innermost
domain ring) so `aegis_core` maintains zero outward imports of services or `enterprise_twin`.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import FastAPI

from aegis_core.audit import InMemoryAuditLedger
from aegis_core.settings import AegisServiceSettings
from aegis_core.telemetry import AegisTelemetry


def create_service_app_from_env(service_name: str | None = None) -> FastAPI:
    """Zero-argument ASGI `--factory` entrypoint used by Kubernetes / Docker `uvicorn`."""
    settings = AegisServiceSettings()
    target = (service_name or os.environ.get("AEGIS_SERVICE_NAME", "sso-broker")).strip().lower()
    telemetry = AegisTelemetry(f"aegis-{target}")
    audit_ledger = InMemoryAuditLedger()

    from enterprise_twin.idp_seed.meridian_idp import (
        MeridianAgentRegistry,
        MeridianIdentityProvider,
    )

    from sso_delegation_broker.app import create_broker_app
    from sso_delegation_broker.broker import SSODelegationBroker
    from sso_delegation_broker.revocation import InMemoryRevocationStore

    idp = MeridianIdentityProvider()
    agents = MeridianAgentRegistry()
    revocation = InMemoryRevocationStore()
    broker = SSODelegationBroker(
        issuer=settings.issuer_url,
        default_audience=settings.audience,
        idp=idp,
        agent_registry=agents,
        revocation_store=revocation,
        audit_ledger=audit_ledger,
        telemetry=telemetry,
    )

    if target == "sso-broker":
        return create_broker_app(broker, audit_ledger)

    if target == "edge-triage":
        from edge_triage_router.router import (
            DeterministicOnPremClassifierAdapter,
            LocalQuantizedTriageRouter,
            create_edge_triage_app,
        )

        router = LocalQuantizedTriageRouter(
            broker=broker,
            classifier=DeterministicOnPremClassifierAdapter(),
            audit_ledger=audit_ledger,
        )
        return create_edge_triage_app(router)

    if target == "mcp-erp":
        from enterprise_twin.soap_erp_mock.sap_soap_server import LegacySAPSoapTwin

        from mcp_erp_bridge.app import create_mcp_erp_app
        from mcp_erp_bridge.bridge import DirectInProcessSOAPTransport, MCPERPBridgeServer

        bridge = MCPERPBridgeServer(
            broker=broker,
            soap_transport=DirectInProcessSOAPTransport(LegacySAPSoapTwin()),
            audit_ledger=audit_ledger,
            telemetry=telemetry,
        )
        return create_mcp_erp_app(bridge)

    if target == "finops":
        from finops_telemetry.engine import FinOpsTelemetryEngine, create_finops_app

        return create_finops_app(FinOpsTelemetryEngine())

    if target == "temporal-gate":
        from enterprise_twin.soap_erp_mock.sap_soap_server import LegacySAPSoapTwin

        from mcp_erp_bridge.bridge import DirectInProcessSOAPTransport, MCPERPBridgeServer
        from temporal_approval_gate.app import create_approval_gate_app
        from temporal_approval_gate.gate import DurableApprovalGate

        bridge = MCPERPBridgeServer(
            broker=broker,
            soap_transport=DirectInProcessSOAPTransport(LegacySAPSoapTwin()),
            audit_ledger=audit_ledger,
            telemetry=telemetry,
        )
        wal_dir = Path(os.environ.get("AEGIS_WAL_DIR", tempfile.gettempdir()))
        gate = DurableApprovalGate(
            db_path=wal_dir / "aegis_temporal_gate.sqlite3",
            broker=broker,
            mcp_bridge=bridge,
            audit_ledger=audit_ledger,
        )
        return create_approval_gate_app(gate)

    if target == "admin-portal":
        from enterprise_twin.corpus_seed.historical_tickets import generate_500_historical_tickets

        from admin_control_plane.app import create_admin_control_plane_app
        from admin_control_plane.portal_api import ControlPlaneService
        from finops_telemetry.engine import FinOpsTelemetryEngine
        from shadow_replay_harness.harness import ShadowReplayHarness

        svc = ControlPlaneService(
            broker=broker,
            replay_harness=ShadowReplayHarness(),
            golden_tickets=generate_500_historical_tickets(),
            finops_engine=FinOpsTelemetryEngine(),
            telemetry=telemetry,
            audit_ledger=audit_ledger,
        )
        return create_admin_control_plane_app(svc)

    raise ValueError(f"Unknown AEGIS_SERVICE_NAME: {target!r}")
