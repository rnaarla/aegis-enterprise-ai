"""Idempotent Legacy Ingestion Pipeline with Merkle Delta Re-Sync, COBOL VB/ODO & ISO 20022."""

from __future__ import annotations

import hashlib

from aegis_core.models import (
    AuditEventType,
    DocumentChunk,
    DocumentClassification,
    ReBACTuple,
)
from aegis_core.ports import AuditLedgerPort, RetrievalStorePort
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry
from legacy_ingestor.cobol_advanced import (
    SupportedEBCDICCodepage,
    decode_variable_wire_batch_vb_stream,
    parse_iso20022_pacs008_wire,
)
from legacy_ingestor.cobol_ebcdic import ACCTLDGR_COPYBOOK, parse_ebcdic_copybook_stream
from legacy_ingestor.merkle_sync import MerkleDeltaResult, MerkleSyncTracker
from legacy_ingestor.pdf_layout_ocr import extract_layout_aware_pdf_chunks


class LegacyIngestionPipeline:
    """Normalizes mainframe COBOL (`FB` & `VB` ODO/REDEFINES), ISO 20022, & PDFs with Merkle sync."""

    def __init__(
        self,
        *,
        retrieval_store: RetrievalStorePort,
        audit_ledger: AuditLedgerPort,
        merkle_tracker: MerkleSyncTracker | None = None,
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self._store = retrieval_store
        self._audit = audit_ledger
        self._merkle = merkle_tracker or MerkleSyncTracker()
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY

    def _ingest_with_merkle_delta(
        self,
        *,
        tenant_id: str,
        document_id: str,
        candidate_chunks: list[DocumentChunk],
        tuples: list[ReBACTuple],
    ) -> tuple[list[DocumentChunk], MerkleDeltaResult]:
        delta = self._merkle.compute_and_commit_delta(
            tenant_id=tenant_id,
            document_id=document_id,
            chunk_ids_and_contents=[(c.chunk_id, c.content) for c in candidate_chunks],
        )
        changed_chunks = [candidate_chunks[idx] for idx in delta.changed_indices]
        if changed_chunks or delta.previous_root_hash is None:
            self._store.ingest_chunks(changed_chunks, tuples)
        self._sli.inc_counter(
            "aegis_ingestor_chunks_total",
            float(len(changed_chunks)),
            {"action": "embedded"},
        )
        if delta.unchanged_count > 0:
            self._sli.inc_counter(
                "aegis_ingestor_chunks_total",
                float(delta.unchanged_count),
                {"action": "merkle_skipped"},
            )
        return changed_chunks, delta

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
        _, delta = self._ingest_with_merkle_delta(
            tenant_id=tenant_id,
            document_id=document_id,
            candidate_chunks=chunks,
            tuples=tuples,
        )
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
                "merkle_reembedded": len(delta.changed_indices),
                "merkle_skipped": delta.unchanged_count,
            },
        )
        return chunks

    def ingest_cobol_recfm_vb_wirebatch(
        self,
        *,
        tenant_id: str,
        document_id: str,
        source_uri: str,
        raw_vb_stream: bytes,
        classification: DocumentClassification,
        department_owner: str,
        viewer_groups: list[str],
        codepage: SupportedEBCDICCodepage = "cp037",
    ) -> tuple[list[DocumentChunk], MerkleDeltaResult]:
        """Ingest z/OS `RECFM=VB` stream with `OCCURS DEPENDING ON` & `REDEFINES` overlays."""
        rows = decode_variable_wire_batch_vb_stream(raw_vb_stream, codepage=codepage)
        chunks: list[DocumentChunk] = []
        for row in rows:
            offset_hex = str(row["_byte_offset_hex"])
            cust_id = str(row["customer_id"])
            alloc_desc = "; ".join(
                f"{it['deal_code']}=USD {it['amount_usd']}" for it in row["allocations"]
            )
            content = (
                f"MAINFRAME WIREBATCH VB [{offset_hex}] Customer={cust_id} "
                f"Instrument={row['instrument_kind']} Redefines={row['redefines_detail']} "
                f"Allocations({row['allocation_count']}): [{alloc_desc}]"
            )
            stable_id = hashlib.sha256(
                f"{tenant_id}|{document_id}|{offset_hex}|{cust_id}".encode()
            ).hexdigest()[:16]
            chunks.append(
                DocumentChunk(
                    chunk_id=f"chk-vb-{stable_id}",
                    document_id=document_id,
                    tenant_id=tenant_id,
                    title=f"COBOL WIREBATCH {cust_id}",
                    source_uri=source_uri,
                    source_system="cobol_core_banking",
                    page_or_record_ref=f"byte_offset={offset_hex},recfm=VB,codepage={codepage}",
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
        return self._ingest_with_merkle_delta(
            tenant_id=tenant_id,
            document_id=document_id,
            candidate_chunks=chunks,
            tuples=tuples,
        )

    def ingest_iso20022_pacs008(
        self,
        *,
        tenant_id: str,
        document_id: str,
        source_uri: str,
        xml_bytes: bytes,
        classification: DocumentClassification,
        department_owner: str,
        viewer_groups: list[str],
    ) -> list[DocumentChunk]:
        """Ingest ISO 20022 `pacs.008` SWIFT wire settlement messages into RLS chunks."""
        txs = parse_iso20022_pacs008_wire(xml_bytes)
        chunks: list[DocumentChunk] = []
        for idx, tx in enumerate(txs, start=1):
            e2e = tx["end_to_end_id"]
            content = (
                f"ISO20022 PACS.008 WIRE [{e2e}]: Debtor={tx['debtor_name']} -> "
                f"Creditor={tx['creditor_name']} | Amount={tx['currency']} {tx['amount']} | "
                f"Remittance={tx['remittance_info']}"
            )
            stable_id = hashlib.sha256(f"{tenant_id}|{document_id}|{e2e}".encode()).hexdigest()[:16]
            chunks.append(
                DocumentChunk(
                    chunk_id=f"chk-iso-{stable_id}",
                    document_id=document_id,
                    tenant_id=tenant_id,
                    title=f"ISO 20022 Wire {e2e}",
                    source_uri=source_uri,
                    source_system="swift_iso20022",
                    page_or_record_ref=f"tx_index={idx},e2e={e2e}",
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
        self._ingest_with_merkle_delta(
            tenant_id=tenant_id,
            document_id=document_id,
            candidate_chunks=chunks,
            tuples=tuples,
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
        # Contextual Late-Window Header Injection: prepend global filing context to every page leaf
        doc_context_prefix = f"[Document={title} | Dept={department_owner} | Class={classification.value}]\n"
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
                    content=doc_context_prefix + p_chunk.content,
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
        _, delta = self._ingest_with_merkle_delta(
            tenant_id=tenant_id,
            document_id=document_id,
            candidate_chunks=chunks,
            tuples=tuples,
        )
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
                "merkle_reembedded": len(delta.changed_indices),
                "merkle_skipped": delta.unchanged_count,
            },
        )
        return chunks
