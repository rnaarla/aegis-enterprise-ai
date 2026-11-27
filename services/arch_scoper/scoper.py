"""Translates executive AI intakes into Optimized BOMs, OSCAL SSPs, EU AI Act & 4-Week SOWs."""

from __future__ import annotations

import math
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arch_scoper.optimizer_oscal import (
    generate_customer_gitops_values_yaml,
    generate_eu_ai_act_conformity_dossier,
    generate_oscal_ssp_json,
    simulate_delivery_schedule_monte_carlo,
    solve_optimal_gpu_topology,
)


class ScopeDiscoveryIntake(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    client_name: str = Field(min_length=2, max_length=128)
    executive_objective: str = Field(min_length=10, max_length=2000)
    compliance_regimes: list[Literal["SOC2", "PCI_DSS", "HIPAA", "SEC_FINRA_MNPI", "FEDRAMP_HIGH"]]
    air_gapped_vpc_required: bool
    requested_hosted_public_llm_api: bool = False
    legacy_sources: list[Literal["SAP_SOAP", "COBOL_MAINFRAME", "SCANNED_PDFS", "SHAREPOINT"]]
    peak_concurrent_users: int = Field(ge=1, le=50_000)
    corpus_document_count: int = Field(ge=100, le=100_000_000)
    autonomous_write_max_usd: float = Field(default=0.0, ge=0.0)
    target_ttft_p99_ms: float = Field(default=350.0, ge=80.0, le=5000.0)


class ConstraintConflict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    conflict_code: str
    severity: Literal["BLOCKING", "WARNING"]
    explanation: str
    enforced_resolution: str


class InfrastructureBOM(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    inference_gpu_type: str
    inference_gpu_count: int
    total_vram_gb: int
    pgvector_storage_gb: int
    clickhouse_telemetry_storage_gb: int
    estimated_monthly_infra_usd: float
    projected_ttft_p99_ms: float = 220.0


class ThreatControlMapping(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    threat_id: str
    stride_category: str
    owasp_llm_ref: str
    attack_scenario: str
    mitigating_aegis_module: str


class MilestoneWeek(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    week: int
    deliverable: str
    customer_prerequisite_gate: str
    exit_metric: str


class GeneratedSOWPackage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    client_name: str
    selected_aegis_modules: list[str]
    conflicts_resolved: list[ConstraintConflict]
    bom: InfrastructureBOM
    threat_model: list[ThreatControlMapping]
    four_week_plan: list[MilestoneWeek]
    mermaid_architecture_diagram: str
    sow_markdown: str
    oscal_ssp_json: dict[str, Any] = Field(default_factory=dict)
    eu_ai_act_dossier: dict[str, str] = Field(default_factory=dict)
    gitops_helm_values_yaml: str = ""
    monte_carlo_schedule_risk: dict[str, float | str] = Field(default_factory=dict)


def validate_mermaid_flowchart_syntax(diagram: str) -> tuple[bool, str]:
    """Deterministically verify Mermaid flowchart syntax, balanced brackets, and no HTML tags."""
    lines = [ln.strip() for ln in diagram.strip().splitlines() if ln.strip()]
    if not lines or not lines[0].startswith(("flowchart ", "graph ")):
        return False, "Diagram must open with 'flowchart <DIR>' or 'graph <DIR>'"
    full = "\n".join(lines)
    if "<br" in full.lower():
        return False, "HTML tags like <br/> are prohibited in Mermaid labels"
    if full.count("[") != full.count("]") or full.count('"') % 2 != 0:
        return False, "Unbalanced brackets or quotes in Mermaid node definitions"
    return True, "Valid Mermaid flowchart"


class ArchitectureScoperEngine:
    """Deterministic scoping engine with Branch-and-Bound SKU Optimizer, OSCAL SSP & Monte Carlo."""

    def generate_sow(self, intake: ScopeDiscoveryIntake) -> GeneratedSOWPackage:
        conflicts: list[ConstraintConflict] = []
        modules: list[str] = [
            "P1: SSO & Delegation Broker",
            "P4: Row-Level Secure RAG",
            "P9: FinOps & ROI",
            "P12: Admin Portal",
        ]

        use_self_hosted_llm = intake.air_gapped_vpc_required or (
            "FEDRAMP_HIGH" in intake.compliance_regimes
        )
        if intake.air_gapped_vpc_required and intake.requested_hosted_public_llm_api:
            conflicts.append(
                ConstraintConflict(
                    conflict_code="AIRGAP_VS_PUBLIC_LLM_API",
                    severity="BLOCKING",
                    explanation=(
                        "Requested zero-egress air-gapped VPC alongside a public hosted frontier API; "
                        "public internet egress violates zero-egress CNI & route-table blackholes."
                    ),
                    enforced_resolution=(
                        "Switched inference BOM to self-hosted in-VPC vLLM GPU cluster packaged via "
                        "P2 Zarf OCI weights (or AWS Bedrock / Azure OpenAI via VPC PrivateLink if cloud-hosted)."
                    ),
                )
            )
            use_self_hosted_llm = True

        if intake.air_gapped_vpc_required:
            modules.append("P2: Air-Gapped Helm + Zarf Deployer")

        if any(s in intake.legacy_sources for s in ("COBOL_MAINFRAME", "SCANNED_PDFS")):
            modules.append("P3: Unstructured Legacy Ingestor (OCR + COBOL)")

        if "SAP_SOAP" in intake.legacy_sources:
            modules.append("P5: Raw MCP-to-ERP SOAP Bridge")

        if any(r in intake.compliance_regimes for r in ("PCI_DSS", "HIPAA", "SEC_FINRA_MNPI")):
            modules.append("P6: Deterministic PII Unmasking Proxy")
            modules.append("P8: Local Quantized AWQ 8B Triage Node")

        if intake.autonomous_write_max_usd > 0:
            modules.append("P7: Async Temporal Approval Gate")

        modules.append("P10: Historical Shadow Replay Harness")
        sorted_modules = sorted(modules)

        gpu_type, gpu_count, vram_gb, gpu_monthly_usd, proj_ttft = solve_optimal_gpu_topology(
            peak_concurrent_users=intake.peak_concurrent_users,
            self_hosted_70b_required=use_self_hosted_llm,
            target_ttft_p99_ms=intake.target_ttft_p99_ms,
        )

        pg_gb = max(50, math.ceil((intake.corpus_document_count * 8 * 4096) / (1024**3)) * 2)
        ch_gb = max(100, intake.peak_concurrent_users * 2)
        monthly_usd = round(gpu_monthly_usd + pg_gb * 0.25 + ch_gb * 0.12 + 450.0, 2)

        bom = InfrastructureBOM(
            inference_gpu_type=gpu_type,
            inference_gpu_count=gpu_count,
            total_vram_gb=vram_gb,
            pgvector_storage_gb=pg_gb,
            clickhouse_telemetry_storage_gb=ch_gb,
            estimated_monthly_infra_usd=monthly_usd,
            projected_ttft_p99_ms=proj_ttft,
        )

        threats = [
            ThreatControlMapping(
                threat_id="THR-01",
                stride_category="Elevation of Privilege",
                owasp_llm_ref="LLM08: Vector and Embedding Weaknesses",
                attack_scenario="Junior employee uses prompt injection to retrieve executive M&A or HR chunks.",
                mitigating_aegis_module="P1 (RFC 8693 DPoP/RAR JWT) + P4 (Postgres 18 Transitive FORCE RLS)",
            ),
            ThreatControlMapping(
                threat_id="THR-02",
                stride_category="Information Disclosure",
                owasp_llm_ref="LLM02: Sensitive Information Disclosure",
                attack_scenario="Raw SSNs, credit cards, or unannounced MNPI leak to external model endpoints.",
                mitigating_aegis_module="P8 (Fail-Closed GPU Triage) + P6 (Feistel FPE & Exfiltration Firewall)",
            ),
            ThreatControlMapping(
                threat_id="THR-03",
                stride_category="Tampering / Excessive Agency",
                owasp_llm_ref="LLM06: Excessive Agency",
                attack_scenario=(
                    "Agent hallucinates or double-submits a high-dollar ERP Purchase Order "
                    "or Vendor bank IBAN drifts."
                ),
                mitigating_aegis_module="P5 (AIMD + WAL Idempotency) + P7 (Quorum/SoD + WebAuthn FIDO2 + ETag)",
            ),
        ]

        plan = [
            MilestoneWeek(
                week=1,
                deliverable="VPC / Air-Gap Foundation, SSO Token Exchange (P1) & Kernel RLS RAG (P4)",
                customer_prerequisite_gate="Client provisions OIDC/SAML client ID + private K8s namespace by Day 2.",
                exit_metric="Zero cross-clearance leakage verified across 100 adversarial RLS queries.",
            ),
            MilestoneWeek(
                week=2,
                deliverable="Legacy Corpus Ingestion (P3), Edge Triage (P8) & PII Proxy (P6)",
                customer_prerequisite_gate="Client delivers scrubbed sample of 500 PDFs/COBOL copybooks.",
                exit_metric=">=99% SSN/Luhn recall with <150ms P99 edge triage overhead.",
            ),
            MilestoneWeek(
                week=3,
                deliverable="ERP SOAP MCP Integration (P5) & Async Temporal Approval Gate (P7)",
                customer_prerequisite_gate="Client provides sandbox SAP BAPI service account + Slack app secret.",
                exit_metric="100% idempotency on duplicate retries + worker SIGKILL recovery verified.",
            ),
            MilestoneWeek(
                week=4,
                deliverable="500-Ticket Shadow Replay (P10), FinOps ROI (P9) & IT Admin Handoff (P12)",
                customer_prerequisite_gate="Client Ops signs off on historical ticket ground-truth rubric.",
                exit_metric=">=96% shadow trajectory accuracy with 0 policy violations prior to go-live.",
            ),
        ]

        diagram = "\n".join(
            [
                "flowchart LR",
                '    IdP["Client Enterprise IdP"] --> Broker["P1: RFC 8693 Delegation Broker"]',
                '    Broker --> Triage["P8: Local AWQ 8B Triage"]',
                '    Triage --> PII["P6: AES-GCM PII SSE Proxy"]',
                '    Broker --> RAG["P4: Postgres 18 FORCE RLS RAG"]',
                '    RAG --> MCP["P5 & P7: Temporal + SAP SOAP MCP"]',
                '    MCP --> Admin["P9, P10 & P12: Shadow Gate & Admin Portal"]',
            ]
        )
        valid_diag, diag_msg = validate_mermaid_flowchart_syntax(diagram)
        if not valid_diag:
            raise ValueError(f"Generated invalid Mermaid diagram: {diag_msg}")

        oscal = generate_oscal_ssp_json(
            client_name=intake.client_name,
            selected_modules=sorted_modules,
            air_gapped=intake.air_gapped_vpc_required,
        )
        eu_dossier = generate_eu_ai_act_conformity_dossier(intake.client_name)
        helm_yaml = generate_customer_gitops_values_yaml(
            client_name=intake.client_name,
            air_gapped=intake.air_gapped_vpc_required,
            autonomous_write_max_usd=intake.autonomous_write_max_usd,
        )
        mc_risk = simulate_delivery_schedule_monte_carlo(
            air_gapped=intake.air_gapped_vpc_required,
            has_sap_soap="SAP_SOAP" in intake.legacy_sources,
            has_cobol="COBOL_MAINFRAME" in intake.legacy_sources,
        )

        conflict_md = (
            "\n".join(
                f"- **[{c.severity}] {c.conflict_code}:** {c.explanation} -> *{c.enforced_resolution}*"
                for c in conflicts
            )
            or "- Zero architectural constraint conflicts detected."
        )
        sow_md = (
            f"# 4-Week Statement of Work — {intake.client_name}\n\n"
            f"## Objective\n{intake.executive_objective}\n\n"
            f"## Architectural Constraint Resolutions\n{conflict_md}\n\n"
            f"## Infrastructure Sizing & Monthly Run-Rate\n"
            f"- **Compute:** {bom.inference_gpu_count}x {bom.inference_gpu_type} "
            f"({bom.total_vram_gb} GB VRAM, projected TTFT p99 `{bom.projected_ttft_p99_ms}ms`)\n"
            f"- **Storage:** {bom.pgvector_storage_gb} GB RLS Vector DB + "
            f"{bom.clickhouse_telemetry_storage_gb} GB FinOps OLAP\n"
            f"- **Estimated Run-Rate:** USD {bom.estimated_monthly_infra_usd:,.2f}/month\n"
            f"- **Monte Carlo Schedule:** p50 `{mc_risk['p50_business_days']}` days / "
            f"p90 `{mc_risk['p90_business_days']}` days\n"
        )

        return GeneratedSOWPackage(
            client_name=intake.client_name,
            selected_aegis_modules=sorted_modules,
            conflicts_resolved=conflicts,
            bom=bom,
            threat_model=threats,
            four_week_plan=plan,
            mermaid_architecture_diagram=diagram,
            sow_markdown=sow_md,
            oscal_ssp_json=oscal,
            eu_ai_act_dossier=eu_dossier,
            gitops_helm_values_yaml=helm_yaml,
            monte_carlo_schedule_risk=mc_risk,
        )
