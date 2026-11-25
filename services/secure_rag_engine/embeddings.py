"""$O(T)$ linear-time, $O(1)$-auxiliary-space streaming financial embedder & vLLM adapter."""

from __future__ import annotations

import hashlib
import itertools
import math
import re
from typing import Any

import httpx

_RAW_CLUSTERS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        0,
        (
            "chronos",
            "helios",
            "acquisition",
            "merger",
            "takeover",
            "valuation",
            "ebitda",
            "synergies",
            "synergy",
            "breakup",
            "mnpi",
        ),
    ),
    (
        1,
        (
            "spa",
            "divestiture",
            "cfius",
            "antitrust",
            "hsr",
            "regulatory",
            "lithography",
            "agreement",
        ),
    ),
    (
        2,
        (
            "mainframe",
            "cobol",
            "ebcdic",
            "cp037",
            "acctldgr",
            "nostro",
            "fedwire",
            "liquidity",
            "escrow",
            "wire",
        ),
    ),
    (
        3,
        (
            "sap",
            "bapi",
            "purchase",
            "order",
            "orders",
            "procurement",
            "vendor",
            "vendors",
            "threshold",
            "thresholds",
            "temporal",
            "50000",
            "approval",
        ),
    ),
    (
        4,
        (
            "equity",
            "research",
            "public",
            "10-q",
            "sec",
            "peers",
            "semiconductor",
            "semiconductors",
            "multiples",
            "multiple",
            "watchlist",
        ),
    ),
    (5, ("travel", "expense", "policy", "pii", "ssn", "tokenized", "acceptable", "corporate")),
    (6, ("apex", "canary", "rival", "bancorp")),
)

# Pre-compiled O(1) hash map + compiled regex automaton (eliminates O(|C|*|T|*|K|) nested loops)
_EXACT_KEYWORD_CLUSTER: dict[str, int] = {
    kw: cluster_idx for cluster_idx, kws in _RAW_CLUSTERS for kw in kws
}
_TOKEN_RE = re.compile(r"[a-z0-9_.-]+")


def _hash_gram_into(vec: list[float], gram: str, hash_span: int) -> None:
    digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
    idx = 16 + (int.from_bytes(digest[:4], "big") % hash_span)
    vec[idx] += 1.0 if (digest[4] & 1) == 0 else -1.0


class DeterministicFinancialEmbedder:
    """Zero-egress 64-D L2-normalized embedder running in $O(T)$ time and $O(D)$ space."""

    def __init__(self, dim: int = 64) -> None:
        if dim < 16:
            raise ValueError("Embedding dimension must be >= 16")
        self._dim = dim

    @property
    def dimension(self) -> int:
        return self._dim

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vec = [0.0] * self._dim
        token_iter = (m.group(0) for m in _TOKEN_RE.finditer(text.lower()))
        first_tok = next(token_iter, None)
        if first_tok is None:
            vec[0] = 1.0
            return vec

        hash_span = self._dim - 16
        cluster_hits = [0] * len(_RAW_CLUSTERS)

        # Single streaming pass over unigrams + adjacent bigrams (`O(1)` auxiliary memory!)
        all_tokens = itertools.chain((first_tok,), token_iter)
        prev_tok: str | None = None
        for tok in all_tokens:
            c_idx = _EXACT_KEYWORD_CLUSTER.get(tok)
            if c_idx is None and "_" in tok:
                for sub_part in tok.split("_"):
                    c_idx = _EXACT_KEYWORD_CLUSTER.get(sub_part)
                    if c_idx is not None:
                        break
            if c_idx is not None:
                cluster_hits[c_idx] += 1

            _hash_gram_into(vec, tok, hash_span)
            if prev_tok is not None:
                _hash_gram_into(vec, f"{prev_tok}_{tok}", hash_span)
            prev_tok = tok

        for c_idx, hits in enumerate(cluster_hits):
            if hits > 0:
                slot = c_idx * 2
                vec[slot] += 2.5 * math.log1p(hits)
                vec[slot + 1] += 1.5 * hits

        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            vec[0] = 1.0
            return vec
        return [round(v / norm, 8) for v in vec]


class OpenAICompatibleEmbeddingAdapter:
    """Production embedding adapter targeting in-VPC `vLLM` (`/v1/embeddings`) or Azure OpenAI."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str = "BAAI/bge-large-en-v1.5",
        dim: int = 1024,
        timeout_seconds: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._dim = dim
        self._timeout = timeout_seconds
        self._transport = transport

    @property
    def dimension(self) -> int:
        return self._dim

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
        payload: dict[str, Any] = {"model": self._model, "input": texts}
        with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
            resp = client.post(f"{self._base_url}/embeddings", headers=headers, json=payload)
            resp.raise_for_status()
            body: dict[str, Any] = resp.json()
        data_items: list[dict[str, Any]] = sorted(body["data"], key=lambda x: int(x["index"]))
        return [[float(x) for x in item["embedding"]] for item in data_items]
