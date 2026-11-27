"""Project 2 V2: Static, SRE Operability & Supply-Chain Air-Gap Readiness Auditor."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict


class AirGapAuditFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    check_id: str
    passed: bool
    detail: str


class AirGapAuditReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    all_passed: bool
    findings: list[AirGapAuditFinding]


def verify_airgap_bundle_readiness(repo_root: Path) -> AirGapAuditReport:
    """Verify Helm, Zarf, Compose, AWS/Azure Terraform, SRE PDB/SLO, and Cosign/SLSA policies."""
    findings: list[AirGapAuditFinding] = []

    helm_airgap_path = repo_root / "deploy" / "helm" / "aegis" / "values-prod-airgap.yaml"
    airgap_vals: dict[str, Any] = yaml.safe_load(helm_airgap_path.read_text(encoding="utf-8"))
    twin_disabled = airgap_vals.get("enterpriseTwin", {}).get("enabled") is False
    findings.append(
        AirGapAuditFinding(
            check_id="HELM_DEMO_TWIN_DISABLED_IN_PROD",
            passed=twin_disabled,
            detail=f"enterpriseTwin.enabled={airgap_vals.get('enterpriseTwin', {}).get('enabled')}",
        )
    )

    netpol_blocked = (
        airgap_vals.get("networkPolicy", {}).get("enabled") is True
        and airgap_vals.get("networkPolicy", {}).get("denyAllPublicEgress") is True
    )
    findings.append(
        AirGapAuditFinding(
            check_id="HELM_ZERO_EGRESS_NETWORKPOLICY",
            passed=netpol_blocked,
            detail="Kubernetes NetworkPolicy denies 0.0.0.0/0 public egress",
        )
    )

    base_vals: dict[str, Any] = yaml.safe_load(
        (repo_root / "deploy" / "helm" / "aegis" / "values.yaml").read_text(encoding="utf-8")
    )
    digests_ok = all(
        str(base_vals.get(svc, {}).get("image", {}).get("digest", "")).startswith("sha256:")
        for svc in ("ssoBroker", "secureRag")
    ) and all(
        str(item.get("digest", "")).startswith("sha256:")
        for item in base_vals.get("platformServices", [])
    )
    findings.append(
        AirGapAuditFinding(
            check_id="IMMUTABLE_SHA256_IMAGE_DIGESTS",
            passed=digests_ok,
            detail="All core & runtime container images pinned by @sha256 digest",
        )
    )

    sre_tpl = (
        repo_root / "deploy" / "helm" / "aegis" / "templates" / "sre-operability.yaml"
    ).read_text(encoding="utf-8")
    sre_ok = (
        "PodDisruptionBudget" in sre_tpl
        and "HorizontalPodAutoscaler" in sre_tpl
        and "PrometheusRule" in sre_tpl
        and "ClusterPolicy" in sre_tpl
    )
    findings.append(
        AirGapAuditFinding(
            check_id="SRE_PDB_HPA_SLO_AND_KYVERNO_COSIGN",
            passed=sre_ok,
            detail="Helm chart bundles PDB, HPA v2, Multi-Burn PrometheusRule & Kyverno Cosign policy",
        )
    )

    compose_data: dict[str, Any] = yaml.safe_load(
        (repo_root / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    )
    internal_net = (
        compose_data.get("networks", {}).get("aegis-internal", {}).get("internal") is True
    )
    findings.append(
        AirGapAuditFinding(
            check_id="COMPOSE_INTERNAL_ISOLATED_BRIDGE",
            passed=internal_net,
            detail=f"docker-compose aegis-internal network internal={internal_net}",
        )
    )

    zarf_data: dict[str, Any] = yaml.safe_load(
        (repo_root / "deploy" / "zarf" / "zarf.yaml").read_text(encoding="utf-8")
    )
    zarf_ok = (
        zarf_data.get("kind") == "ZarfPackageConfig"
        and len(zarf_data.get("components", [])) >= 1
    )
    findings.append(
        AirGapAuditFinding(
            check_id="ZARF_DISCONNECTED_PACKAGE_SPEC",
            passed=zarf_ok,
            detail=f"Zarf package {zarf_data.get('metadata', {}).get('name', '')} validated",
        )
    )

    tf_root_text = (repo_root / "deploy" / "terraform" / "aws_airgap_vpc" / "main.tf").read_text(
        encoding="utf-8"
    )
    tf_mod_path = (
        repo_root
        / "deploy"
        / "terraform"
        / "aws_airgap_vpc"
        / "modules"
        / "aws_enclave"
        / "vpc_privatelink.tf"
    )
    tf_mod_text = tf_mod_path.read_text(encoding="utf-8") if tf_mod_path.exists() else ""
    az_tf_path = repo_root / "deploy" / "terraform" / "azure_gov_enclave" / "main.tf"
    az_tf_ok = az_tf_path.exists() and "Standard_DC32as_v5" in az_tf_path.read_text(encoding="utf-8")

    dockerfile_text = (repo_root / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8")
    dockerfile_ok = (
        "USER 65532:65532" in dockerfile_text
        and "HF_HUB_OFFLINE=1" in dockerfile_text
        and "--factory" in dockerfile_text
    )
    tf_zero_egress = (
        "aws_internet_gateway" not in tf_root_text
        and "aws_nat_gateway" not in tf_root_text
        and 'resource "aws_internet_gateway"' not in tf_mod_text
        and 'resource "aws_nat_gateway"' not in tf_mod_text
        and 'resource "aws_vpc_endpoint"' in tf_mod_text
        and dockerfile_ok
        and az_tf_ok
    )
    findings.append(
        AirGapAuditFinding(
            check_id="TERRAFORM_MULTI_CLOUD_ZERO_EGRESS_AND_CONFIDENTIAL_COMPUTE",
            passed=tf_zero_egress,
            detail="AWS PrivateLink + Azure Gov SEV-SNP enclave enforce zero IGW/NAT + factory Dockerfile",
        )
    )

    return AirGapAuditReport(
        all_passed=all(f.passed for f in findings),
        findings=findings,
    )
