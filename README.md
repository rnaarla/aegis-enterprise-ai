# Aegis Enterprise AI — Complete 12-Module Fortune 500 Solution Accelerator

Zero-trust enterprise AI control plane, runtime, and plug-and-play Fortune 500 solution accelerator. Runs **live executive & CISO technical due-diligence proofs** via an isolated `enterprise_twin` profile and cuts over **Day-1 into regulated banking, healthcare, and defense VPCs** strictly via `values.yaml` configuration swaps—zero "demo-ware" code branches.

## Quickstart Verification

```bash
# Run mypy --strict (Python) + tsc --noEmit (TypeScript), ruff, helm lint, terraform validate,
# pytest (unit + PostgreSQL 18 FORCE RLS + Temporal SDK), and live 12-Module F500 PoV:
make verify-all
```

## Implemented 12-Project Matrix

| # | Module | Location | Core Production Implementation |
| :- | :--- | :--- | :--- |
| **P1** | Enterprise SSO & Delegation Broker | `services/sso_delegation_broker` | OIDC + XXE-hardened SAML 2.0 -> 300s ES256 RFC 8693 `at+jwt`, triple-scope intersection, JTI/agent kill-switch |
| **P2** | One-Click Air-Gapped Helm Deployer | `deploy/` & `services/airgap_verifier` | `@sha256` CNCF Helm chart, zero-egress K8s `NetworkPolicy`, `zarf.yaml`, zero-IGW/NAT AWS VPC Terraform, static readiness auditor |
| **P3** | Unstructured Legacy Ingestor | `services/legacy_ingestor` | Binary IBM `CP037` EBCDIC + signed `COMP-3` BCD COBOL Copybook parser & `pypdf`/Tesseract OCR layout chunker with cross-page table carryover |
| **P4** | Row-Level Secure RAG Engine | `services/secure_rag_engine` | PostgreSQL 18 `FORCE ROW LEVEL SECURITY` (`aegis_app_runtime` `NOBYPASSRLS`), dual `PERMISSIVE` ReBAC + `RESTRICTIVE` tenant/MAC/ethical-wall policies, RRF hybrid search |
| **P5** | Raw MCP-to-ERP SOAP Bridge | `services/mcp_erp_bridge` | JSON-RPC 2.0 MCP server -> SAP SOAP 1.2 + WS-Security (`BAPI_PO_CREATE1` / `BAPI_VENDOR_GETDETAIL`), `BAPIRET2` error parsing, write idempotency |
| **P6** | Deterministic PII Unmasking Proxy | `services/pii_unmasking_proxy` | IRS SSN + Luhn PCI + IBAN + co-reference detector, HKDF/AES-256-GCM session vault, split-chunk SSE lookahead stream rehydrator |
| **P7** | Async Temporal Approval Gate | `services/temporal_approval_gate` | `temporalio` workflow/activities + SQLite WAL crash recovery, Slack `v0` HMAC-SHA256 webhook verification, fresh approver JWT minting, anti-TOCTOU ETag check |
| **P8** | Local Quantized Triage Node | `services/edge_triage_router` | `vLLM` AWQ 8B guided-JSON schema classifier + fail-closed KV-cache backpressure routing (`HOT_MNPI` / `WARM_PII` / `COLD_SAFE`) |
| **P9** | Dept FinOps & ROI Dashboard | `services/finops_telemetry` | ClickHouse OLAP DDL, cache/reasoning/retry-aware token rate cards, rework-penalized CFO net ROI engine |
| **P10** | Historical Shadow Replay Harness | `services/shadow_replay_harness` | 500-ticket point-in-time (`world_state_at_t0`) shadow evaluator preventing temporal leakage & live ERP side effects |
| **P11** | Automated Architecture Scoper | `services/arch_scoper` | Deterministic constraint conflict solver (`AIRGAP_VS_PUBLIC_LLM_API`), VRAM/storage BOM calculator, STRIDE/OWASP LLM threat model, 4-week SOW generator |
| **P12** | Self-Serve Customer Admin Portal | `services/admin_control_plane` & `apps/admin_portal` | Strict TypeScript 6.0 SDK/waterfall/ROI presenter + FastAPI backend gating prompt promotion on P10's 500-ticket shadow suite & AES-GCM secret masking |
