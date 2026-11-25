"""Meridian Global Financial multi-classification RAG corpus & Zanzibar ReBAC graph."""

from __future__ import annotations

from aegis_core.models import (
    ClearanceLevel,
    DocumentChunk,
    DocumentClassification,
    ReBACTuple,
)


def build_meridian_corpus() -> tuple[list[DocumentChunk], list[ReBACTuple]]:
    """Return realistic M&A, COBOL core banking, SAP procurement, and research chunks + ACLs."""
    chunks: list[DocumentChunk] = [
        DocumentChunk(
            chunk_id="chk-chronos-val-01",
            document_id="doc-chronos-valuation",
            tenant_id="meridian-fin",
            title="Project Chronos — Confidential Valuation & Fairness Opinion (Helios Semi)",
            source_uri="sharepoint://meridian.fin/corp-dev/deal-chronos/valuation_v9_final.pdf",
            source_system="sharepoint_ma",
            page_or_record_ref="page=14,bbox=[72,118,540,392]",
            classification=DocumentClassification.TOP_SECRET_MA,
            clearance_required=ClearanceLevel.TOP_SECRET_MA,
            content=(
                "CONFIDENTIAL MNPI — PROJECT CHRONOS: Meridian Corporate Development recommends "
                "an all-cash acquisition of Helios Semiconductor Corp at USD 4.20 billion enterprise "
                "value, representing 14.5x FY26E Adjusted EBITDA (USD 289.6M). Projected run-rate "
                "wafer-fab procurement synergies reach USD 310M within 24 months post-close, with "
                "a reverse termination breakup fee capped at USD 165M."
            ),
            department_owner="CORP_DEV",
        ),
        DocumentChunk(
            chunk_id="chk-chronos-spa-02",
            document_id="doc-chronos-spa-draft",
            tenant_id="meridian-fin",
            title="Project Chronos — Draft Stock Purchase Agreement Section 7.4 (CFIUS & Antitrust)",
            source_uri="sharepoint://meridian.fin/corp-dev/deal-chronos/spa_execution_draft.pdf",
            source_system="sharepoint_ma",
            page_or_record_ref="page=48,bbox=[68,94,544,610]",
            classification=DocumentClassification.TOP_SECRET_MA,
            clearance_required=ClearanceLevel.TOP_SECRET_MA,
            content=(
                "SECTION 7.4 REGULATORY DIVESTITURE CAP: Buyer (Meridian Capital Holdings) shall "
                "not be obligated to divest lithography subsystem assets generating more than "
                "USD 95M in trailing twelve-month revenue to secure HSR or CFIUS clearance under "
                "Project Chronos."
            ),
            department_owner="CORP_DEV",
        ),
        DocumentChunk(
            chunk_id="chk-cobol-nostro-01",
            document_id="doc-cobol-nostro-ledger",
            tenant_id="meridian-fin",
            title="IBM z/OS Mainframe Copybook ACCTLDGR — Escrow & Nostro Liquidity Position",
            source_uri="zos://PRD.MERIDIAN.CORE.ACCTLDGR.EBCDIC",
            source_system="cobol_core_banking",
            page_or_record_ref="byte_offset=0x004A80,copybook=ACCTLDGR,pic=S9(11)V99_COMP-3",
            classification=DocumentClassification.RESTRICTED,
            clearance_required=ClearanceLevel.RESTRICTED,
            content=(
                "MAINFRAME SETTLEMENT EXTRACT [CP037 DECODED]: Nostro Fedwire Account 021000021-8841 "
                "holds committed M&A escrow liquidity of USD 1,840,500,000.00 available for T+1 "
                "institutional wire settlement; intraday credit facility utilization stands at 12.4%."
            ),
            department_owner="TREASURY_CORE",
        ),
        DocumentChunk(
            chunk_id="chk-sap-po-policy-01",
            document_id="doc-sap-vendor-master",
            tenant_id="meridian-fin",
            title="SAP S/4HANA Procurement Governance & Approved Cloud/Advisory Vendor Thresholds",
            source_uri="sap://PRD-ECC-800/BAPI_VENDOR_POLICY/2026-Q4",
            source_system="sap_procurement",
            page_or_record_ref="sap_doc=POL-PROC-402,company_code=1000",
            classification=DocumentClassification.CONFIDENTIAL,
            clearance_required=ClearanceLevel.CONFIDENTIAL,
            content=(
                "MERIDIAN PROCUREMENT CONTROL 402: Autonomous or user-assisted SAP Purchase Orders "
                "(BAPI_PO_CREATE1, Company Code 1000) up to USD 50,000 may execute under VP "
                "Procurement authority. Any Purchase Order exceeding USD 50,000.00 strictly requires "
                "asynchronous Temporal approval sign-off from a Managing Director with state-hash "
                "verification prior to SAP commit."
            ),
            department_owner="FINANCE_OPS",
        ),
        DocumentChunk(
            chunk_id="chk-equity-semi-q3",
            document_id="doc-q3-macro-research",
            tenant_id="meridian-fin",
            title="Meridian Equity Research — Public Semiconductor Sector Multiples (Q3 Public Note)",
            source_uri="kb://meridian.fin/equity-research/2026-q3-semi-public-comps.pdf",
            source_system="policy_kb",
            page_or_record_ref="page=3,bbox=[72,140,520,420]",
            classification=DocumentClassification.INTERNAL,
            clearance_required=ClearanceLevel.INTERNAL,
            content=(
                "PUBLIC COMP SHEET (NON-MNPI): Based solely on public SEC Form 10-Q filings, mid-cap "
                "analog and specialty semiconductor peers trade at a median valuation multiple of "
                "11.2x NTM EV/EBITDA. Analysts must consult Compliance before publishing commentary "
                "on issuers placed on the Meridian Restricted Watchlist."
            ),
            department_owner="EQUITY_RESEARCH",
        ),
        DocumentChunk(
            chunk_id="chk-corp-expense-01",
            document_id="doc-travel-expense-policy",
            tenant_id="meridian-fin",
            title="Meridian Global Corporate Travel, T&E & AI Acceptable Use Policy",
            source_uri="kb://meridian.fin/hr/global-policy-2026.pdf",
            source_system="policy_kb",
            page_or_record_ref="page=2,section=1.4",
            classification=DocumentClassification.PUBLIC,
            clearance_required=ClearanceLevel.PUBLIC,
            content=(
                "All Meridian personnel using enterprise AI assistants operate under zero-trust "
                "5-minute delegated tokens. Client SSNs, payment card numbers, and wire credentials "
                "are automatically tokenized by the Aegis PII Proxy prior to model inference."
            ),
            department_owner="SEC_OPS",
        ),
        # Cross-tenant canary chunk to verify hard multi-tenant isolation at the DB kernel
        DocumentChunk(
            chunk_id="chk-rival-bank-canary",
            document_id="doc-rival-tenant-secret",
            tenant_id="apex-bancorp",
            title="Apex Bancorp — Tenant Isolation Canary Document",
            source_uri="s3://apex-bancorp-vault/canary.pdf",
            source_system="sharepoint_ma",
            page_or_record_ref="page=1",
            classification=DocumentClassification.PUBLIC,
            clearance_required=ClearanceLevel.PUBLIC,
            content=(
                "TENANT CANARY SECRET: Project Chronos cross-tenant test record belonging to "
                "apex-bancorp. Must NEVER be visible to meridian-fin principals even at PUBLIC level."
            ),
            department_owner="SEC_OPS",
        ),
    ]

    tuples: list[ReBACTuple] = [
        # Project Chronos M&A docs: ONLY deal-chronos group, PLUS ethical-wall DENY on julian.ross!
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-chronos-valuation",
            relation="viewer",
            subject_type="group",
            subject_id="deal-chronos",
        ),
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-chronos-valuation",
            relation="ethical_wall_deny",
            subject_type="user",
            subject_id="julian.ross",
        ),
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-chronos-spa-draft",
            relation="viewer",
            subject_type="group",
            subject_id="md-ma",
        ),
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-chronos-spa-draft",
            relation="ethical_wall_deny",
            subject_type="user",
            subject_id="julian.ross",
        ),
        # Mainframe Nostro Ledger: Managing Directors only
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-cobol-nostro-ledger",
            relation="viewer",
            subject_type="group",
            subject_id="md-ma",
        ),
        # SAP Procurement Policy: Procurement VP, AP Ops, and MDs
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-sap-vendor-master",
            relation="viewer",
            subject_type="group",
            subject_id="procurement-vp",
        ),
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-sap-vendor-master",
            relation="viewer",
            subject_type="group",
            subject_id="ap-ops",
        ),
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-sap-vendor-master",
            relation="viewer",
            subject_type="group",
            subject_id="md-ma",
        ),
        # Internal Equity Research & Public Policy: all meridian-fin employees
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-q3-macro-research",
            relation="viewer",
            subject_type="group",
            subject_id="all-employees",
        ),
        ReBACTuple(
            tenant_id="meridian-fin",
            object_id="doc-travel-expense-policy",
            relation="viewer",
            subject_type="group",
            subject_id="all-employees",
        ),
        # Rival tenant canary tuple (valid inside apex-bancorp, blocked for meridian-fin by tenant RLS)
        ReBACTuple(
            tenant_id="apex-bancorp",
            object_id="doc-rival-tenant-secret",
            relation="viewer",
            subject_type="group",
            subject_id="all-employees",
        ),
    ]
    return chunks, tuples
