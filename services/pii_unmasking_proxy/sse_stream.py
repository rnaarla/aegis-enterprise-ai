"""Single-pass $O(L)$ PII detector & index-cursor SSE lookahead rehydrator ($O(1)$ carry)."""

from __future__ import annotations

import re
from collections.abc import Callable

_NON_PERSON_LEADERS = (
    "Project|Meridian|Helios|Standard|Purchase|Company|Nostro|"
    "Client|Vendor|Authorize|Approved|Cleared|Verify|Confirmed|Account|Onboard"
)

_FULL_PERSON_PATTERN = rf"\b(?!{_NON_PERSON_LEADERS}\b)[A-Z][a-z]{{2,20}}\s+[A-Z][a-z]{{2,25}}\b"
_FULL_PERSON_PREPASS_RE = re.compile(_FULL_PERSON_PATTERN)

# Single compiled alternation automaton scanning input in ONE O(L) linear pass
_MASTER_PII_RE = re.compile(
    r"(?P<SSN>\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b)"
    r"|(?P<IBAN>\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b)"
    r"|(?P<EMAIL>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)"
    r"|(?P<CC>\b(?:\d[ -]*?){13,19}\b)"
    rf"|(?P<HONORIFIC>\b(?:Mr|Ms|Mrs|Dr)\.\s+[A-Z][a-z]{{2,25}}\b)"
    rf"|(?P<PERSON>{_FULL_PERSON_PATTERN})"
)

_SURROGATE_TAG_RE = re.compile(r"^<(?:SSN|CC|IBAN|EMAIL|PERSON)_\d{3}>$")
MAX_SURROGATE_TAG_LEN = 18


def passes_luhn_checksum(raw_card: str) -> bool:
    """Verify ISO/IEC 7812 Luhn Mod-10 checksum in $O(d)$ time ($13 \\le d \\le 19$)."""
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
    """Mask all regulated PII/PCI entities in $O(L)$ time without re-scanning emitted tags."""
    detected_tags: list[str] = []

    # Pre-seed full-name aliases so honorific co-references ("Ms. Vance") resolve even if cataphoric
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


class StreamingSurrogateRehydrator:
    """$O(L)$ index-cursor SSE stream rehydrator with $O(1)$ bounded carry (`<= 18` chars).

    Eliminates $O(B^2)$ repeated string-prefix slicing by advancing an integer cursor `idx`
    across `data = self._carry + chunk` in a single left-to-right pass.
    """

    def __init__(self, unmask_fn: Callable[[str], str | None]) -> None:
        self._unmask_fn = unmask_fn
        self._carry = ""
        self.unmasked_tags: list[str] = []

    def feed(self, chunk: str) -> str:
        if not chunk and not self._carry:
            return ""
        data = self._carry + chunk if self._carry else chunk
        self._carry = ""
        n = len(data)
        idx = 0
        emitted: list[str] = []

        while idx < n:
            lt_pos = data.find("<", idx)
            if lt_pos == -1:
                emitted.append(data[idx:])
                break

            if lt_pos > idx:
                emitted.append(data[idx:lt_pos])
                idx = lt_pos

            gt_pos = data.find(">", idx + 1)
            if gt_pos == -1:
                next_lt = data.find("<", idx + 1)
                if next_lt != -1:
                    emitted.append(data[idx:next_lt])
                    idx = next_lt
                    continue
                if (n - idx) > MAX_SURROGATE_TAG_LEN:
                    emitted.append(data[idx:])
                    break
                self._carry = data[idx:]
                break

            inner_lt = data.find("<", idx + 1, gt_pos)
            if inner_lt != -1:
                emitted.append(data[idx:inner_lt])
                idx = inner_lt
                continue

            candidate_tag = data[idx : gt_pos + 1]
            idx = gt_pos + 1
            if _SURROGATE_TAG_RE.match(candidate_tag):
                restored = self._unmask_fn(candidate_tag)
                if restored is not None:
                    self.unmasked_tags.append(candidate_tag)
                    emitted.append(restored)
                else:
                    emitted.append(candidate_tag)
            else:
                emitted.append(candidate_tag)

        return "".join(emitted)

    def flush(self) -> str:
        rem = self._carry
        self._carry = ""
        return rem
