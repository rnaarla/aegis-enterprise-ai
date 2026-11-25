"""True IBM z/OS `CP037` EBCDIC & `COMP-3` Packed-Decimal COBOL Copybook parser."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Literal


@dataclass(frozen=True)
class CobolCopybookField:
    """Single elementary field in an IBM Enterprise COBOL fixed-width record."""

    name: str
    field_type: Literal["PIC_X", "PIC_9_DISPLAY", "PIC_S9_COMP3"]
    byte_length: int
    scale: int = 0


@dataclass(frozen=True)
class CobolCopybookSpec:
    """Fixed-width mainframe record specification."""

    copybook_name: str
    fields: tuple[CobolCopybookField, ...]

    @property
    def record_byte_length(self) -> int:
        return sum(f.byte_length for f in self.fields)


# Reference Meridian Core-Banking Nostro/Escrow Ledger Copybook (`ACCTLDGR`, 56 bytes/record)
# 01 ACCTLDGR-RECORD.
#    05 ACCT-ID          PIC X(14).             (14 bytes CP037)
#    05 COST-CENTER      PIC X(8).              ( 8 bytes CP037)
#    05 SETTLE-DATE      PIC 9(8).              ( 8 bytes CP037 YYYYMMDD)
#    05 BALANCE-USD      PIC S9(11)V99 COMP-3.  ( 7 bytes BCD: 13 digits + sign nibble = 14 nibbles)
#    05 FACILITY-PCT     PIC S9(3)V99 COMP-3.   ( 3 bytes BCD:  5 digits + sign nibble =  6 nibbles)
#    05 STATUS-DESC      PIC X(16).             (16 bytes CP037)
ACCTLDGR_COPYBOOK = CobolCopybookSpec(
    copybook_name="ACCTLDGR",
    fields=(
        CobolCopybookField("ACCT_ID", "PIC_X", 14),
        CobolCopybookField("COST_CENTER", "PIC_X", 8),
        CobolCopybookField("SETTLE_DATE", "PIC_9_DISPLAY", 8),
        CobolCopybookField("BALANCE_USD", "PIC_S9_COMP3", 7, scale=2),
        CobolCopybookField("FACILITY_PCT", "PIC_S9_COMP3", 3, scale=2),
        CobolCopybookField("STATUS_DESC", "PIC_X", 16),
    ),
)


def encode_comp3(value: Decimal, *, byte_length: int, scale: int = 0, signed: bool = True) -> bytes:
    """Encode a `Decimal` into IBM z/OS `COMP-3` packed binary-coded decimal bytes."""
    negative = value < 0
    quantizer = Decimal(10) ** (-scale)
    scaled_int = int((abs(value).quantize(quantizer)) * (10**scale))
    total_digit_slots = byte_length * 2 - 1
    digits_str = str(scaled_int).rjust(total_digit_slots, "0")
    if len(digits_str) > total_digit_slots:
        raise ValueError(
            f"Decimal {value} overflows COMP-3({byte_length} bytes, {total_digit_slots} digits)"
        )

    sign_nibble = (0x0D if negative else 0x0C) if signed else 0x0F
    nibbles = [int(ch) for ch in digits_str] + [sign_nibble]
    out = bytearray(byte_length)
    for idx in range(byte_length):
        out[idx] = (nibbles[idx * 2] << 4) | nibbles[idx * 2 + 1]
    return bytes(out)


def decode_comp3(raw_bytes: bytes, *, scale: int = 0) -> Decimal:
    """Decode IBM z/OS `COMP-3` packed decimal bytes into an exact `Decimal`."""
    if not raw_bytes:
        raise ValueError("Empty COMP-3 byte slice")

    digits: list[str] = []
    for b in raw_bytes[:-1]:
        hi = (b >> 4) & 0x0F
        lo = b & 0x0F
        if hi > 9 or lo > 9:
            raise ValueError(f"Invalid BCD digit nibble in byte 0x{b:02x}")
        digits.append(str(hi))
        digits.append(str(lo))

    last = raw_bytes[-1]
    last_digit = (last >> 4) & 0x0F
    sign_nibble = last & 0x0F
    if last_digit > 9:
        raise ValueError(f"Invalid final BCD digit nibble in 0x{last:02x}")
    digits.append(str(last_digit))

    if sign_nibble in (0x0C, 0x0F, 0x0A, 0x0E):
        sign = Decimal(1)
    elif sign_nibble in (0x0D, 0x0B):
        sign = Decimal(-1)
    else:
        raise ValueError(f"Invalid COMP-3 sign nibble: 0x{sign_nibble:x}")

    int_val = Decimal("".join(digits))
    return sign * (int_val / (Decimal(10) ** scale))


def encode_acctldgr_ebcdic_record(
    *,
    acct_id: str,
    cost_center: str,
    settle_date: str,
    balance_usd: Decimal,
    facility_pct: Decimal,
    status_desc: str,
) -> bytes:
    """Pack a single 56-byte `ACCTLDGR` mainframe binary record (`CP037` + `COMP-3`)."""
    buf = bytearray()
    buf.extend(acct_id.ljust(14)[:14].encode("cp037"))
    buf.extend(cost_center.ljust(8)[:8].encode("cp037"))
    buf.extend(settle_date.rjust(8, "0")[:8].encode("cp037"))
    buf.extend(encode_comp3(balance_usd, byte_length=7, scale=2))
    buf.extend(encode_comp3(facility_pct, byte_length=3, scale=2))
    buf.extend(status_desc.ljust(16)[:16].encode("cp037"))
    assert len(buf) == ACCTLDGR_COPYBOOK.record_byte_length
    return bytes(buf)


def parse_ebcdic_copybook_stream(
    raw_stream: bytes,
    spec: CobolCopybookSpec = ACCTLDGR_COPYBOOK,
) -> list[dict[str, str | int | Decimal]]:
    """Decode fixed-width binary mainframe dump into structured records with exact byte offsets."""
    rec_len = spec.record_byte_length
    if len(raw_stream) % rec_len != 0:
        raise ValueError(
            f"Corrupt EBCDIC stream length {len(raw_stream)}: not a multiple of {rec_len} bytes"
        )

    records: list[dict[str, str | int | Decimal]] = []
    for rec_idx, start_offset in enumerate(range(0, len(raw_stream), rec_len)):
        rec_bytes = raw_stream[start_offset : start_offset + rec_len]
        cursor = 0
        parsed: dict[str, str | int | Decimal] = {
            "_record_index": rec_idx,
            "_byte_offset_hex": f"0x{start_offset:06X}",
        }
        for field in spec.fields:
            slice_bytes = rec_bytes[cursor : cursor + field.byte_length]
            cursor += field.byte_length
            if field.field_type == "PIC_X" or field.field_type == "PIC_9_DISPLAY":
                parsed[field.name] = slice_bytes.decode("cp037").strip()
            elif field.field_type == "PIC_S9_COMP3":
                parsed[field.name] = decode_comp3(slice_bytes, scale=field.scale)
        records.append(parsed)
    return records
