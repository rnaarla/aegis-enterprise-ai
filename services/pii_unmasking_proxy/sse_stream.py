"""Index-cursor SSE lookahead rehydrator (`O(1)` carry) + re-exported pure PII scanner."""

from __future__ import annotations

import re
from collections.abc import Callable

from aegis_core.pii_scanner import mask_text_entities, passes_luhn_checksum

_SURROGATE_TAG_RE = re.compile(r"^<(?:SSN|CC|IBAN|EMAIL|PERSON|DEAL|CLIENT)_\d{3}>$")
MAX_SURROGATE_TAG_LEN = 18


class StreamingSurrogateRehydrator:
    """`O(L)` index-cursor SSE stream rehydrator with `O(1)` bounded carry (`<= 18` chars)."""

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


__all__ = ["MAX_SURROGATE_TAG_LEN", "StreamingSurrogateRehydrator", "mask_text_entities", "passes_luhn_checksum"]
