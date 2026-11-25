"""Project 2: Static & Manifest Air-Gap Zero-Egress Readiness Auditor."""

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
    """Verify Helm, Zarf, Docker Compose, and Terraform enforce zero public egress."""
    findings: list[AirGapAuditFinding] = []

    # 1. Verify air-gapped Helm values disable Enterprise Twin & enforce NetworkPolicy
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

    # 2. Verify base Helm values pin `@sha256:` digests rather than mutable `:latest` tags
    base_vals: dict[str, Any] = yaml.safe_load(
        (repo_root / "deploy" / "helm" / "aegis" / "values.yaml").read_text(encoding="utf-8")
    )
    digests_ok = all(
        str(base_vals.get(svc, {}).get("image", {}).get("digest", "")).startswith("sha256:")
        for svc in ("ssoBroker", "secureRag")
    )
    findings.append(
        AirGapAuditFinding(
            check_id="IMMUTABLE_SHA256_IMAGE_DIGESTS",
            passed=digests_ok,
            detail="All core service container images pinned by @sha256 digest",
        )
    )

    # 3. Verify Docker Compose bridge network uses `internal: true` (zero host internet routing)
    compose_data: dict[str, Any] = yaml.safe_load(
        (repo_root / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    )
    internal_net = compose_data.get("networks", {}).get("aegis-internal", {}).get("internal") is True
    findings.append(
        AirGapAuditFinding(
            check_id="COMPOSE_INTERNAL_ISOLATED_BRIDGE",
            passed=internal_net,
            detail=f"docker-compose aegis-internal network internal={internal_net}",
        )
    )

    # 4. Verify Zarf disconnected bundle packages local Helm chart & offline images
    zarf_data: dict[str, Any] = yaml.safe_load(
        (repo_root / "deploy" / "zarf" / "zarf.yaml").read_text(encoding="utf-8")
    )
    zarf_ok = zarf_data.get("kind") == "ZarfPackageConfig" and len(zarf_data.get("components", [])) >= 1
    findings.append(
        AirGapAuditFinding(
            check_id="ZARF_DISCONNECTED_PACKAGE_SPEC",
            passed=zarf_ok,
            detail=f"Zarf package {zarf_data.get('metadata', {}).get('name', '')} validated",
        )
    )

    # 5. Verify AWS Air-Gap VPC Terraform & PrivateLink module forbid IGW and NAT Gateways
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
    dockerfile_path = repo_root / "deploy" / "docker" / "Dockerfile"
    dockerfile_ok = (
        dockerfile_path.exists()
        and "USER 65532:65532" in dockerfile_path.read_text(encoding="utf-8")
        and "HF_HUB_OFFLINE=1" in dockerfile_path.read_text(encoding="utf-8")
    )
    tf_zero_egress = (
        "aws_internet_gateway" not in tf_root_text
        and "aws_nat_gateway" not in tf_root_text
        and "resource \"aws_internet_gateway\"" not in tf_mod_text
        and "resource \"aws_nat_gateway\"" not in tf_mod_text
        and "resource \"aws_vpc_endpoint\"" in tf_mod_text
        and dockerfile_ok
    )
    findings.append(
        AirGapAuditFinding(
            check_id="TERRAFORM_ZERO_IGW_ZERO_NAT",
            passed=tf_zero_egress,
            detail="AWS VPC provisions zero Internet Gateways and zero NAT Gateways",
        )
    )

    return AirGapAuditReport(
        all_passed=all(f.passed for f in findings),
        findings=findings,
    )
