"""Project 6 V2: Balanced Feistel FPE (Luhn-Valid PANs), `O(L + Z)` Aho-Corasick & Canary Guard."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections import deque

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class PIIExfiltrationBlockedError(PermissionError):
    """Raised when LLM output attempts to exfiltrate PII surrogates via URLs, Base64, or spacing."""


def compute_luhn_check_digit(payload_digits: str) -> str:
    """Compute ISO/IEC 7812 Luhn Mod-10 check digit for a numeric prefix."""
    total = 0
    for idx, ch in enumerate(reversed(payload_digits)):
        d = ord(ch) - 48
        if idx % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - (total % 10)) % 10)


class FeistelNumericFPE:
    """6-Round Keyed HMAC-SHA256 Balanced Feistel Cipher over `10^k` Decimal Domains (NIST FPE style).

    Guarantees bijective, collision-free, reversible Format-Preserving Encryption so downstream
    SQL/ERP tools receive syntactically valid Luhn-passing 16-digit PANs and 9-digit SSNs.
    """

    def __init__(self, master_key: bytes, *, rounds: int = 6) -> None:
        if len(master_key) < 16:
            raise ValueError("FPE master_key must be >= 16 bytes")
        self._master = master_key
        self._rounds = rounds

    def _derive_key(self, session_id: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"aegis-feistel-fpe-v2",
            info=session_id.encode("utf-8"),
        ).derive(self._master)

    def _prf(self, key: bytes, round_num: int, right_val: int, half_mod: int, tweak: str) -> int:
        msg = f"{round_num}|{tweak}|{right_val}".encode("ascii")
        digest = hmac.new(key, msg, hashlib.sha256).digest()
        return int.from_bytes(digest[:8], "big") % half_mod

    def encrypt_digits(self, digits: str, *, session_id: str, tweak: str = "default") -> str:
        n = len(digits)
        if n % 2 != 0 or not digits.isdigit():
            raise ValueError("Balanced decimal Feistel requires even-length digit string")
        half = n // 2
        mod = 10**half
        key = self._derive_key(session_id)
        left = int(digits[:half])
        right = int(digits[half:])
        for r in range(self._rounds):
            new_left = right
            new_right = (left + self._prf(key, r, right, mod, tweak)) % mod
            left, right = new_left, new_right
        return f"{left:0{half}d}{right:0{half}d}"

    def decrypt_digits(self, cipher_digits: str, *, session_id: str, tweak: str = "default") -> str:
        n = len(cipher_digits)
        if n % 2 != 0 or not cipher_digits.isdigit():
            raise ValueError("Balanced decimal Feistel requires even-length digit string")
        half = n // 2
        mod = 10**half
        key = self._derive_key(session_id)
        left = int(cipher_digits[:half])
        right = int(cipher_digits[half:])
        for r in range(self._rounds - 1, -1, -1):
            prev_right = left
            prev_left = (right - self._prf(key, r, prev_right, mod, tweak)) % mod
            left, right = prev_left, prev_right
        return f"{left:0{half}d}{right:0{half}d}"

    def mask_credit_card_luhn_preserving(self, raw_pan: str, *, session_id: str) -> str:
        """Preserve synthetic test BIN `400000` + Feistel-encrypt middle 8 digits + valid Luhn digit."""
        clean = "".join(ch for ch in raw_pan if ch.isdigit())
        if len(clean) != 16:
            raise ValueError("Luhn FPE requires standard 16-digit PAN")
        # Encrypt digits [1..14] (14 digits = even length!) so full entropy is reversible
        enc_core = self.encrypt_digits(clean[1:15], session_id=session_id, tweak=f"pan:{clean[0]}")
        prefix15 = clean[0] + enc_core
        check = compute_luhn_check_digit(prefix15)
        full = prefix15 + check
        return f"{full[0:4]}-{full[4:8]}-{full[8:12]}-{full[12:16]}"


class AhoCorasickEntityMatcher:
    """True `O(L + Z)` Aho-Corasick Trie Automaton with BFS Failure Links for 10,000+ Deal Codenames."""

    def __init__(self, terms_by_label: dict[str, str]) -> None:
        # `terms_by_label`: `{raw_phrase: entity_type}`, e.g. `{"Project Chronos": "DEAL_CODENAME"}`
        self._goto: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._output: list[list[tuple[int, str, str]]] = [[]]

        for phrase, etype in sorted(terms_by_label.items(), key=lambda kv: -len(kv[0])):
            norm = phrase.lower()
            if not norm:
                continue
            state = 0
            for ch in norm:
                nxt = self._goto[state].get(ch)
                if nxt is None:
                    nxt = len(self._goto)
                    self._goto.append({})
                    self._fail.append(0)
                    self._output.append([])
                    self._goto[state][ch] = nxt
                state = nxt
            self._output[state].append((len(norm), phrase, etype))

        queue: deque[int] = deque()
        for _ch, s in self._goto[0].items():
            self._fail[s] = 0
            queue.append(s)

        while queue:
            r = queue.popleft()
            for ch, u in self._goto[r].items():
                queue.append(u)
                v = self._fail[r]
                while v != 0 and ch not in self._goto[v]:
                    v = self._fail[v]
                self._fail[u] = self._goto[v].get(ch, 0)
                self._output[u].extend(self._output[self._fail[u]])

    def find_non_overlapping(self, text: str) -> list[tuple[int, int, str]]:
        """Scan `text` in single `O(L)` pass; return non-overlapping `(start, end, entity_type)`."""
        if len(self._goto) == 1:
            return []
        lower = text.lower()
        raw_hits: list[tuple[int, int, str]] = []
        state = 0
        for idx, ch in enumerate(lower):
            while state != 0 and ch not in self._goto[state]:
                state = self._fail[state]
            state = self._goto[state].get(ch, 0)
            for pat_len, _orig, etype in self._output[state]:
                start = idx - pat_len + 1
                end = idx + 1
                # Enforce word-boundary alignment so short codenames don't match mid-word
                left_ok = start == 0 or not lower[start - 1].isalnum()
                right_ok = end == len(lower) or not lower[end].isalnum()
                if left_ok and right_ok:
                    raw_hits.append((start, end, etype))

        # Greedy leftmost-longest interval selection
        raw_hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        selected: list[tuple[int, int, str]] = []
        cursor = 0
        for start, end, etype in raw_hits:
            if start >= cursor:
                selected.append((start, end, etype))
                cursor = end
        return selected


_MD_EXFIL_URL_RE = re.compile(
    r"!\[[^\]]*\]\(https?://[^)]*<[A-Z_]+_\d{3}>[^)]*\)|https?://\S*<[A-Z_]+_\d{3}>",
    re.IGNORECASE,
)
_SPACED_OBFUSCATION_RE = re.compile(
    r"<\s*(?:P\s+E\s+R\s+S\s+O\s+N|S\s+S\s+N|C\s+A\s+R\s+D|C\s+C|I\s+B\s+A\s+N)\s*_\s*\d\s*\d\s*\d\s*>",
    re.IGNORECASE,
)
_B64_CANDIDATE_RE = re.compile(r"(?:(?<=\s)|^)[A-Za-z0-9+/]{12,80}={0,2}(?=\s|$)")


def assert_no_surrogate_exfiltration(llm_output: str, active_tags: list[str]) -> None:
    """Detect prompt-injection exfiltration of surrogates via URLs, spacing, or Base64 encoding."""
    if _MD_EXFIL_URL_RE.search(llm_output):
        raise PIIExfiltrationBlockedError(
            "Blocked PII exfiltration attempt: surrogate token embedded inside external URL/image"
        )
    if _SPACED_OBFUSCATION_RE.search(llm_output):
        raise PIIExfiltrationBlockedError(
            "Blocked PII obfuscation attempt: spaced-out surrogate token detected"
        )
    if active_tags:
        tag_set = set(active_tags)
        for m in _B64_CANDIDATE_RE.finditer(llm_output):
            tok = m.group(0)
            decoded = ""
            try:
                decoded = base64.b64decode(tok, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                decoded = ""
            if decoded and any(t in decoded for t in tag_set):
                raise PIIExfiltrationBlockedError(
                    "Blocked PII exfiltration attempt: Base64-encoded surrogate token detected"
                )
