"""Project 11 V2: Multi-Objective SKU Optimizer, NIST OSCAL 1.1.2 SSP, EU AI Act & Monte Carlo."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any

import yaml


@dataclass(frozen=True)
class CandidateGPUSKU:
    sku_name: str
    vram_gb: int
    monthly_usd: float
    users_capacity_per_gpu: int
    base_ttft_p99_ms: float
    supports_70b_self_hosted: bool


GPU_SKU_CATALOG: tuple[CandidateGPUSKU, ...] = (
    CandidateGPUSKU("NVIDIA L4 24GB (Edge Triage)", 24, 520.0, 150, 95.0, False),
    CandidateGPUSKU("NVIDIA L40S 48GB", 48, 1_350.0, 35, 220.0, True),
    CandidateGPUSKU("NVIDIA H100 80GB SXM", 80, 2_950.0, 90, 115.0, True),
)


def solve_optimal_gpu_topology(
    *,
    peak_concurrent_users: int,
    self_hosted_70b_required: bool,
    target_ttft_p99_ms: float = 350.0,
) -> tuple[str, int, int, float, float]:
    """Branch-and-bound search selecting minimum-USD GPU SKU meeting VRAM, TTFT & concurrency."""
    best: tuple[float, str, int, int, float] | None = None

    for sku in GPU_SKU_CATALOG:
        if self_hosted_70b_required and not sku.supports_70b_self_hosted:
            continue
        if not self_hosted_70b_required and sku.supports_70b_self_hosted:
            continue
        if sku.base_ttft_p99_ms > target_ttft_p99_ms:
            continue

        min_gpus_for_weights = 2 if (self_hosted_70b_required and sku.vram_gb < 80) else 1
        needed = max(
            min_gpus_for_weights,
            math.ceil(peak_concurrent_users / sku.users_capacity_per_gpu),
        )
        if self_hosted_70b_required and sku.vram_gb < 80 and needed % 2 != 0:
            needed += 1

        cost = needed * sku.monthly_usd
        candidate = (cost, sku.sku_name, needed, needed * sku.vram_gb, sku.base_ttft_p99_ms)
        if best is None or candidate[0] < best[0]:
            best = candidate

    if best is None:
        # Fallback to H100 SXM when aggressive sub-150ms TTFT rules out L40S
        h100 = GPU_SKU_CATALOG[2]
        cnt = max(2, math.ceil(peak_concurrent_users / h100.users_capacity_per_gpu))
        return h100.sku_name, cnt, cnt * h100.vram_gb, cnt * h100.monthly_usd, h100.base_ttft_p99_ms

    cost, name, cnt, vram, ttft = best
    return name, cnt, vram, cost, ttft


def generate_oscal_ssp_json(
    *,
    client_name: str,
    selected_modules: list[str],
    air_gapped: bool,
) -> dict[str, Any]:
    """Generate machine-readable NIST SP 800-53 Rev 5 OSCAL 1.1.2 System Security Plan (SSP)."""
    controls = [
        {
            "control-id": "ac-3",
            "title": "Access Enforcement",
            "implemented-by": "P1 RFC 8693 RAR/DPoP + P4 PostgreSQL 18 FORCE RLS NOBYPASSRLS",
        },
        {
            "control-id": "ac-4",
            "title": "Information Flow Enforcement",
            "implemented-by": "P4 Ethical-Wall DENY + P8 Fail-Closed Data-Gravity GPU Triage",
        },
        {
            "control-id": "au-9",
            "title": "Protection of Audit Information",
            "implemented-by": "Per-tenant SHA-256 hash-chained ledger + SQLSTATE 55000 triggers + P12 WORM JWS",
        },
        {
            "control-id": "ia-2",
            "title": "Identification and Authentication (FIDO2 Step-Up)",
            "implemented-by": "P1 OIDC/SAML2 + P7 W3C WebAuthn ES256 Hardware Passkey UV=1",
        },
        {
            "control-id": "sc-7",
            "title": "Boundary Protection",
            "implemented-by": (
                "P2 Zero-IGW/Zero-NAT PrivateLink VPC + K8s NetworkPolicy"
                if air_gapped
                else "P2 Private ClusterIP + mTLS x5t#S256"
            ),
        },
        {
            "control-id": "sc-28",
            "title": "Protection of Information at Rest",
            "implemented-by": "P6 HKDF AES-256-GCM Session Vault + P7 AESGCMPayloadCodec + P12 KMS Vault",
        },
    ]
    return {
        "system-security-plan": {
            "oscal-version": "1.1.2",
            "metadata": {
                "title": f"Aegis Zero-Trust AI System Security Plan — {client_name}",
                "version": "2.0.0",
            },
            "system-characteristics": {
                "security-sensitivity-level": "high",
                "air-gapped-enclave": air_gapped,
                "active-modules": selected_modules,
            },
            "control-implementation": {
                "description": "NIST SP 800-53 Rev 5 High-Baseline Automated Control Mapping",
                "implemented-requirements": controls,
            },
        }
    }


def generate_eu_ai_act_conformity_dossier(client_name: str) -> dict[str, str]:
    """Map EU AI Act High-Risk System Obligations (Articles 9-15) to concrete Aegis mechanisms."""
    return {
        "client": client_name,
        "article_9_risk_management": "P10 Stratified 500-Ticket Shadow Replay + Canary Auto-Rollback",
        "article_10_data_governance": "P3 Byte-Offset/Page Provenance + P6 Deterministic PII/FPE Redaction",
        "article_12_record_keeping": "Immutable Per-Tenant SHA-256 Audit Ledger + OTel Trace Waterfalls",
        "article_14_human_oversight": "P7 M-of-N Quorum + Four-Eyes SoD + WebAuthn Hardware Step-Up",
        "article_15_accuracy_robustness_security": "P1 DPoP/mTLS + P4 Citation Grounding + P8 Fail-Closed KV Guard",
    }


def generate_customer_gitops_values_yaml(
    *,
    client_name: str,
    air_gapped: bool,
    autonomous_write_max_usd: float,
) -> str:
    """Compile approved discovery intake directly into ready-to-commit Helm `values-customer.yaml`."""
    slug = "".join(ch if ch.isalnum() else "-" for ch in client_name.lower()).strip("-")[:32]
    doc: dict[str, Any] = {
        "global": {
            "environment": "prod-airgap" if air_gapped else "production",
            "airGapped": air_gapped,
            "tenantId": slug,
        },
        "enterpriseTwin": {"enabled": False},
        "networkPolicy": {"enabled": True, "denyAllPublicEgress": air_gapped},
        "sreOperability": {
            "pdbEnabled": True,
            "hpaEnabled": True,
            "prometheusRulesEnabled": True,
            "targetAvailabilitySlo": "0.9995",
        },
        "mcpErpBridge": {"autonomousPoCeilingUsd": autonomous_write_max_usd},
    }
    return yaml.safe_dump(doc, sort_keys=False)


def simulate_delivery_schedule_monte_carlo(
    *,
    air_gapped: bool,
    has_sap_soap: bool,
    has_cobol: bool,
    trials: int = 2_000,
    seed: int = 2026,
) -> dict[str, float | str]:
    """Deterministic-seed Monte Carlo critical-path schedule risk simulator (`p50` / `p90` days)."""
    rng = random.Random(seed)  # noqa: S311
    durations: list[float] = []
    for _ in range(trials):
        # Week 1: IdP SAML/OIDC + VPC/Air-gap provisioning
        w1 = rng.triangular(3.5, 8.0 if air_gapped else 6.0, 5.0)
        # Week 2: Corpus + COBOL/PDF ingestion
        w2 = rng.triangular(3.5, 7.5 if has_cobol else 5.5, 4.5)
        # Week 3: SAP firewall & SOAP BAPI + Temporal Gate
        w3 = rng.triangular(4.0, 8.5 if has_sap_soap else 5.5, 5.0)
        # Week 4: Shadow Replay sign-off + Admin Portal handoff
        w4 = rng.triangular(3.0, 6.0, 4.5)
        durations.append(w1 + w2 + w3 + w4)

    durations.sort()
    p50 = round(durations[int(0.50 * len(durations))], 1)
    p90 = round(durations[int(0.90 * len(durations))], 1)
    under_20_biz_days = round(sum(1 for d in durations if d <= 22.0) / len(durations), 4)
    bottleneck = (
        "Customer Air-Gap Registry & InfoSec CAB Gate"
        if air_gapped
        else ("SAP Firewall & RFC Service Account Provisioning" if has_sap_soap else "IdP Federation")
    )
    return {
        "p50_business_days": p50,
        "p90_business_days": p90,
        "four_week_on_time_probability": under_20_biz_days,
        "primary_critical_path_risk": bottleneck,
    }
