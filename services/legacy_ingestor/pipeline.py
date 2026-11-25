"""Idempotent Legacy Ingestion Pipeline feeding COBOL & PDF exports into Project 4 RLS Store."""

from __future__ import annotations

import hashlib

from aegis_core.models import (
    AuditEventType,
    DocumentChunk,
    DocumentClassification,
    ReBACTuple,
)
from aegis_core.ports import AuditLedgerPort, RetrievalStorePort
from legacy_ingestor.cobol_ebcdic import ACCTLDGR_COPYBOOK, parse_ebcdic_copybook_stream
from legacy_ingestor.pdf_layout_ocr import extract_layout_aware_pdf_chunks


class LegacyIngestionPipeline:
    """Normalizes binary mainframe COBOL dumps and messy PDFs into deterministic RLS chunks."""

    def __init__(
        self,
        *,
        retrieval_store: RetrievalStorePort,
        audit_ledger: AuditLedgerPort,
    ) -> None:
        self._store = retrieval_store
        self._audit = audit_ledger

    def ingest_cobol_acctldgr_dump(
        self,
        *,
        tenant_id: str,
        document_id: str,
        source_uri: str,
        raw_ebcdic: bytes,
        classification: DocumentClassification,
        department_owner: str,
        viewer_groups: list[str],
    ) -> list[DocumentChunk]:
        decoded_rows = parse_ebcdic_copybook_stream(raw_ebcdic, ACCTLDGR_COPYBOOK)
        chunks: list[DocumentChunk] = []
        for row in decoded_rows:
            offset_hex = str(row["_byte_offset_hex"])
            acct_id = str(row["ACCT_ID"])
            content = (
                f"MAINFRAME {ACCTLDGR_COPYBOOK.copybook_name} RECORD [{offset_hex}]: "
                f"Account={acct_id} | CostCenter={row['COST_CENTER']} | "
                f"SettleDate={row['SETTLE_DATE']} | BalanceUSD={row['BALANCE_USD']} | "
                f"FacilityPct={row['FACILITY_PCT']}% | Status={row['STATUS_DESC']}"
            )
            stable_id = hashlib.sha256(
                f"{tenant_id}|{document_id}|{offset_hex}|{acct_id}".encode()
            ).hexdigest()[:16]
            chunks.append(
                DocumentChunk(
                    chunk_id=f"chk-cobol-{stable_id}",
                    document_id=document_id,
                    tenant_id=tenant_id,
                    title=f"COBOL {ACCTLDGR_COPYBOOK.copybook_name} Account {acct_id}",
                    source_uri=source_uri,
                    source_system="cobol_core_banking",
                    page_or_record_ref=f"byte_offset={offset_hex},copybook=ACCTLDGR",
                    classification=classification,
                    clearance_required=classification.to_clearance(),
                    content=content,
                    department_owner=department_owner,
                )
            )

        tuples = [
            ReBACTuple(
                tenant_id=tenant_id,
                object_id=document_id,
                relation="viewer",
                subject_type="group",
                subject_id=grp,
            )
            for grp in viewer_groups
        ]
        self._store.ingest_chunks(chunks, tuples)
        self._audit.append(
            tenant_id=tenant_id,
            event_type=AuditEventType.LEGACY_BATCH_INGESTED,
            human_subject="batch_ingestor",
            actor_id="spiffe://meridian.fin/agent/legacy-ingestor",
            jti=None,
            decision="ALLOW",
            detail={
                "source_type": "cobol_ebcdic_comp3",
                "document_id": document_id,
                "records_decoded": len(chunks),
            },
        )
        return chunks

    def ingest_pdf_document(
        self,
        *,
        tenant_id: str,
        document_id: str,
        title: str,
        source_uri: str,
        pdf_bytes: bytes,
        classification: DocumentClassification,
        department_owner: str,
        viewer_groups: list[str],
    ) -> list[DocumentChunk]:
        page_chunks = extract_layout_aware_pdf_chunks(pdf_bytes)
        chunks: list[DocumentChunk] = []
        for p_chunk in page_chunks:
            stable_id = hashlib.sha256(
                f"{tenant_id}|{document_id}|p{p_chunk.page_number}".encode()
            ).hexdigest()[:16]
            chunks.append(
                DocumentChunk(
                    chunk_id=f"chk-pdf-{stable_id}",
                    document_id=document_id,
                    tenant_id=tenant_id,
                    title=f"{title} (Page {p_chunk.page_number})",
                    source_uri=source_uri,
                    source_system="sharepoint_ma",
                    page_or_record_ref=f"page={p_chunk.page_number},method={p_chunk.extraction_method}",
                    classification=classification,
                    clearance_required=classification.to_clearance(),
                    content=p_chunk.content,
                    department_owner=department_owner,
                )
            )

        tuples = [
            ReBACTuple(
                tenant_id=tenant_id,
                object_id=document_id,
                relation="viewer",
                subject_type="group",
                subject_id=grp,
            )
            for grp in viewer_groups
        ]
        self._store.ingest_chunks(chunks, tuples)
        self._audit.append(
            tenant_id=tenant_id,
            event_type=AuditEventType.LEGACY_BATCH_INGESTED,
            human_subject="batch_ingestor",
            actor_id="spiffe://meridian.fin/agent/legacy-ingestor",
            jti=None,
            decision="ALLOW",
            detail={
                "source_type": "pdf_layout_ocr",
                "document_id": document_id,
                "pages_ingested": len(chunks),
            },
        )
        return chunks
