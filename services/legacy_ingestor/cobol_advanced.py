"""Project 3 V2: Enterprise COBOL (`RECFM=VB`, `OCCURS DEPENDING ON`, `REDEFINES`) & ISO 20022."""

from __future__ import annotations

import struct
from decimal import Decimal
from typing import Any, Literal

from lxml import etree

from legacy_ingestor.cobol_ebcdic import decode_comp3, encode_comp3

SupportedEBCDICCodepage = Literal["cp037", "cp500", "cp1140"]


def pack_zos_recfm_vb_block(variable_records: list[bytes]) -> bytes:
    """Pack variable-length z/OS records into an IBM `RECFM=VB` block with 4-byte BDW + RDWs."""
    body = bytearray()
    for rec in variable_records:
        rdw_len = len(rec) + 4
        if rdw_len > 32760:
            raise ValueError(f"z/OS RECFM=VB record exceeds 32760-byte LRECL limit: {rdw_len}")
        body.extend(struct.pack(">HH", rdw_len, 0))
        body.extend(rec)
    bdw_len = len(body) + 4
    return struct.pack(">HH", bdw_len, 0) + bytes(body)


def unpack_zos_recfm_vb_stream(
    raw_vb_stream: bytes,
) -> list[tuple[int, bytes]]:
    """Unpack IBM z/OS `RECFM=VB` (Block Descriptor Word + Record Descriptor Word) binary blocks.

    Returns `[(byte_offset, logical_record_bytes), ...]`.
    """
    out: list[tuple[int, bytes]] = []
    pos = 0
    total = len(raw_vb_stream)
    while pos < total:
        if pos + 4 > total:
            raise ValueError("Truncated IBM BDW header in RECFM=VB stream")
        bdw_len, bdw_reserved = struct.unpack(">HH", raw_vb_stream[pos : pos + 4])
        if bdw_len < 8 or bdw_reserved != 0 or (pos + bdw_len) > total:
            raise ValueError(f"Corrupt IBM BDW length={bdw_len} at offset 0x{pos:06X}")
        blk_end = pos + bdw_len
        rec_cursor = pos + 4
        while rec_cursor < blk_end:
            if rec_cursor + 4 > blk_end:
                raise ValueError("Truncated IBM RDW header inside RECFM=VB block")
            rdw_len, _ = struct.unpack(">HH", raw_vb_stream[rec_cursor : rec_cursor + 4])
            if rdw_len < 5 or (rec_cursor + rdw_len) > blk_end:
                raise ValueError(f"Corrupt IBM RDW length={rdw_len} at offset 0x{rec_cursor:06X}")
            payload = raw_vb_stream[rec_cursor + 4 : rec_cursor + rdw_len]
            out.append((rec_cursor, payload))
            rec_cursor += rdw_len
        pos = blk_end
    return out


def encode_variable_wire_batch_record(
    *,
    customer_id: str,
    instrument_kind: Literal["WIRE", "CARD"],
    routing_or_pan_detail: str,
    allocations: list[tuple[str, Decimal]],
    codepage: SupportedEBCDICCodepage = "cp037",
) -> bytes:
    """Encode a COBOL record exercising `REDEFINES` union + `OCCURS 0 TO 10 DEPENDING ON`.

    Copybook (`WIREBATCH`):
      05 CUST-ID          PIC X(10).
      05 INSTR-KIND       PIC X(4).          ('WIRE' or 'CARD')
      05 INSTR-DETAIL     PIC X(20).         (REDEFINES: ABA+Acct for WIRE, MaskedToken for CARD)
      05 ALLOC-COUNT      PIC 9(2).          (Controls OCCURS DEPENDING ON)
      05 ALLOC-ITEM OCCURS 0 TO 10 TIMES DEPENDING ON ALLOC-COUNT.
         10 DEAL-CODE     PIC X(8).
         10 AMOUNT-USD    PIC S9(9)V99 COMP-3 (6 bytes BCD).
    """
    if len(allocations) > 10:
        raise ValueError("OCCURS DEPENDING ON max bound is 10 items")
    buf = bytearray()
    buf.extend(customer_id.ljust(10)[:10].encode(codepage))
    buf.extend(instrument_kind.ljust(4)[:4].encode(codepage))
    buf.extend(routing_or_pan_detail.ljust(20)[:20].encode(codepage))
    buf.extend(str(len(allocations)).rjust(2, "0").encode(codepage))
    for deal_code, amt in allocations:
        buf.extend(deal_code.ljust(8)[:8].encode(codepage))
        buf.extend(encode_comp3(amt, byte_length=6, scale=2))
    return bytes(buf)


def decode_variable_wire_batch_vb_stream(
    raw_vb_stream: bytes,
    *,
    codepage: SupportedEBCDICCodepage = "cp037",
) -> list[dict[str, Any]]:
    """Decode `RECFM=VB` stream containing `REDEFINES` + `OCCURS DEPENDING ON` records."""
    unpacked = unpack_zos_recfm_vb_stream(raw_vb_stream)
    decoded_records: list[dict[str, Any]] = []
    for byte_offset, rec in unpacked:
        if len(rec) < 36:
            raise ValueError(f"WIREBATCH base header requires >=36 bytes; got {len(rec)}")
        cust_id = rec[0:10].decode(codepage).strip()
        instr_kind = rec[10:14].decode(codepage).strip()
        raw_union = rec[14:34].decode(codepage).strip()
        alloc_cnt = int(rec[34:36].decode(codepage).strip())

        # Discriminated COBOL REDEFINES overlay
        redefines_view: dict[str, str] = (
            {"aba_routing": raw_union[:9], "beneficiary_acct": raw_union[9:].strip()}
            if instr_kind == "WIRE"
            else {"card_network_token": raw_union}
        )

        expected_len = 36 + alloc_cnt * 14
        if len(rec) != expected_len:
            raise ValueError(
                f"OCCURS DEPENDING ON length mismatch: count={alloc_cnt} expected {expected_len}B, got {len(rec)}B"
            )
        items: list[dict[str, str | Decimal]] = []
        cursor = 36
        for _ in range(alloc_cnt):
            deal = rec[cursor : cursor + 8].decode(codepage).strip()
            amt = decode_comp3(rec[cursor + 8 : cursor + 14], scale=2)
            items.append({"deal_code": deal, "amount_usd": amt})
            cursor += 14

        decoded_records.append(
            {
                "_byte_offset_hex": f"0x{byte_offset:06X}",
                "customer_id": cust_id,
                "instrument_kind": instr_kind,
                "redefines_detail": redefines_view,
                "allocation_count": alloc_cnt,
                "allocations": items,
            }
        )
    return decoded_records


def parse_iso20022_pacs008_wire(xml_bytes: bytes) -> list[dict[str, str]]:
    """XXE-hardened parser for ISO 20022 `pacs.008` Customer Credit Transfer XML messages."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(xml_bytes, parser=parser)
    txs: list[dict[str, str]] = []
    for tx_node in root.xpath("//*[local-name()='CdtTrfTxInf']"):
        e2e = tx_node.xpath(".//*[local-name()='EndToEndId']/text()")
        amt = tx_node.xpath(".//*[local-name()='IntrBkSttlmAmt']/text()")
        ccy = tx_node.xpath(".//*[local-name()='IntrBkSttlmAmt']/@Ccy")
        dbtr = tx_node.xpath(".//*[local-name()='Dbtr']/*[local-name()='Nm']/text()")
        cdtr = tx_node.xpath(".//*[local-name()='Cdtr']/*[local-name()='Nm']/text()")
        rmt = tx_node.xpath(".//*[local-name()='Ustrd']/text()")
        txs.append(
            {
                "end_to_end_id": str(e2e[0]).strip() if e2e else "UNKNOWN",
                "amount": str(amt[0]).strip() if amt else "0.00",
                "currency": str(ccy[0]).strip() if ccy else "USD",
                "debtor_name": str(dbtr[0]).strip() if dbtr else "UNKNOWN",
                "creditor_name": str(cdtr[0]).strip() if cdtr else "UNKNOWN",
                "remittance_info": str(rmt[0]).strip() if rmt else "",
            }
        )
    if not txs:
        raise ValueError("No CdtTrfTxInf credit transfer transactions found in ISO 20022 XML")
    return txs
