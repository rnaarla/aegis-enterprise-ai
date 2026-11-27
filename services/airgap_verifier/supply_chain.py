"""Project 2 V2: Cryptographic Supply-Chain Attestation (Offline Cosign, SLSA L3 & CycloneDX SBOM)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field


class SBOMVulnerability(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    cve_id: str
    package_name: str
    severity: str
    fixed_version: str | None = None


class CycloneDXSBOM(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    bomFormat: str = "CycloneDX"  # noqa: N815
    specVersion: str = "1.5"  # noqa: N815
    version: int = 1
    components: list[dict[str, str]]
    vulnerabilities: list[SBOMVulnerability] = Field(default_factory=list)


class SLSABuildProvenance(BaseModel):
    """SLSA v1.0 in-toto Statement proving hermetic pinned build provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    predicate_type: str = "https://slsa.dev/provenance/v1"
    builder_id: str
    subject_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_commit_sha: str = Field(min_length=7, max_length=64)
    hermetic_offline_build: bool = True
    built_at: datetime


class SignedSupplyChainBundle(BaseModel):
    """Offline Cosign-style ECDSA P-256 signed attestation bundle shipped inside Zarf air-gap tar."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    image_ref: str
    image_digest: str
    sbom: CycloneDXSBOM
    slsa_provenance: SLSABuildProvenance
    payload_sha256: str
    cosign_ecdsa_sig_b64: str


def _canonical_bundle_bytes(
    image_ref: str,
    image_digest: str,
    sbom: CycloneDXSBOM,
    provenance: SLSABuildProvenance,
) -> bytes:
    doc: dict[str, Any] = {
        "image_ref": image_ref,
        "image_digest": image_digest,
        "sbom": sbom.model_dump(mode="json"),
        "slsa_provenance": provenance.model_dump(mode="json"),
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_supply_chain_bundle(
    *,
    private_key_pem: bytes,
    image_ref: str,
    image_digest: str,
    components: list[dict[str, str]],
    source_commit_sha: str,
    builder_id: str = "https://github.com/rnaarla/aegis-enterprise-ai/.github/workflows/ci.yml",
    vulnerabilities: list[SBOMVulnerability] | None = None,
) -> SignedSupplyChainBundle:
    """Create and sign an offline Cosign ECDSA P-256 supply-chain bundle (SBOM + SLSA v1.0)."""
    sbom = CycloneDXSBOM(components=components, vulnerabilities=vulnerabilities or [])
    provenance = SLSABuildProvenance(
        builder_id=builder_id,
        subject_image_digest=image_digest,
        source_commit_sha=source_commit_sha,
        hermetic_offline_build=True,
        built_at=datetime.now(tz=UTC),
    )
    raw = _canonical_bundle_bytes(image_ref, image_digest, sbom, provenance)
    digest_hex = hashlib.sha256(raw).hexdigest()
    priv_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Offline Cosign signer requires an ECDSA P-256 private key")
    sig = priv_key.sign(raw, ec.ECDSA(hashes.SHA256()))
    return SignedSupplyChainBundle(
        image_ref=image_ref,
        image_digest=image_digest,
        sbom=sbom,
        slsa_provenance=provenance,
        payload_sha256=digest_hex,
        cosign_ecdsa_sig_b64=base64.b64encode(sig).decode("ascii"),
    )


def verify_supply_chain_admission(
    bundle: SignedSupplyChainBundle,
    *,
    trusted_public_key_pem: bytes,
    expected_image_digest: str,
) -> tuple[bool, str]:
    """Admission-gate verification: Cosign signature + digest match + SLSA L3 + 0 HIGH/CRITICAL CVEs."""
    if bundle.image_digest != expected_image_digest:
        return False, "Image @sha256 digest mismatch against admission request"
    if bundle.slsa_provenance.subject_image_digest != expected_image_digest:
        return False, "SLSA provenance subject digest does not match container digest"
    if not bundle.slsa_provenance.hermetic_offline_build:
        return False, "SLSA provenance indicates non-hermetic build"

    raw = _canonical_bundle_bytes(
        bundle.image_ref, bundle.image_digest, bundle.sbom, bundle.slsa_provenance
    )
    if hashlib.sha256(raw).hexdigest() != bundle.payload_sha256:
        return False, "Tampered supply-chain payload hash"

    pub_key = serialization.load_pem_public_key(trusted_public_key_pem)
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        return False, "Trusted root key is not ECDSA P-256"
    try:
        sig = base64.b64decode(bundle.cosign_ecdsa_sig_b64)
        pub_key.verify(sig, raw, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False, "Offline Cosign ECDSA signature verification failed"

    blocking_vulns = [
        v.cve_id
        for v in bundle.sbom.vulnerabilities
        if v.severity.upper() in ("CRITICAL", "HIGH")
    ]
    if blocking_vulns:
        return False, f"Blocked by CycloneDX SBOM vulnerability gate: {blocking_vulns}"

    return True, "Verified Cosign signature, SLSA v1.0 provenance, and zero CRITICAL/HIGH CVEs"
