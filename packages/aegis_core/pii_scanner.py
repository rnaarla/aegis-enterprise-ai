"""Pure Functional Core: Single-Pass `O(L)` PII Entity Scanner & ISO 7812 Luhn Validator.

Extracted into `aegis_core` (`Functional Core, Imperative Shell`) so both Edge Triage (P8)
and the Deterministic PII Unmasking Proxy (P6) share one zero-side-effect lexical engine
without cross-service coupling.
"""

from __future__ import annotations

import re
from collections.abc import Callable

_NON_PERSON_LEADERS = (
    "Project|Meridian|Helios|Standard|Purchase|Company|Nostro|"
    "Client|Vendor|Authorize|Approved|Cleared|Verify|Confirmed|Account|Onboard"
)

_FULL_PERSON_PATTERN = rf"\b(?!{_NON_PERSON_LEADERS}\b)[A-Z][a-z]{{2,20}}\s+[A-Z][a-z]{{2,25}}\b"
_FULL_PERSON_PREPASS_RE = re.compile(_FULL_PERSON_PATTERN)

_MASTER_PII_RE = re.compile(
    r"(?P<SSN>\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b)"
    r"|(?P<IBAN>\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b)"
    r"|(?P<EMAIL>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)"
    r"|(?P<CC>\b(?:\d[ -]*?){13,19}\b)"
    rf"|(?P<HONORIFIC>\b(?:Mr|Ms|Mrs|Dr)\.\s+[A-Z][a-z]{{2,25}}\b)"
    rf"|(?P<PERSON>{_FULL_PERSON_PATTERN})"
)


def passes_luhn_checksum(raw_card: str) -> bool:
    """Verify ISO/IEC 7812 Luhn Mod-10 checksum in `O(d)` time (`13 <= d <= 19`)."""
    digits = [ord(ch) - 48 for ch in raw_card if "0" <= ch <= "9"]
    n = len(digits)
    if n < 13 or n > 19:
        return False
    total = 0
    parity = n & 1
    for idx, d in enumerate(digits):
        if (idx & 1) == parity:
            d <<= 1
            if d > 9:
                d -= 9
        total += d
    return (total % 10) == 0


def mask_text_entities(
    text: str,
    mask_fn: Callable[[str, str], str],
) -> tuple[str, list[str]]:
    """Mask all regulated PII/PCI entities in `O(L)` time without re-scanning emitted tags."""
    detected_tags: list[str] = []

    for full_match in _FULL_PERSON_PREPASS_RE.finditer(text):
        mask_fn("PERSON", full_match.group(0))

    def _dispatch(match: re.Match[str]) -> str:
        group_name = match.lastgroup
        raw_val = match.group(0)
        if group_name == "CC":
            if not passes_luhn_checksum(raw_val):
                return raw_val
            etype = "CC"
        elif group_name in ("PERSON", "HONORIFIC"):
            etype = "PERSON"
        else:
            etype = str(group_name)
        tag = mask_fn(etype, raw_val)
        detected_tags.append(tag)
        return tag

    masked = _MASTER_PII_RE.sub(_dispatch, text)
    return masked, detected_tags
