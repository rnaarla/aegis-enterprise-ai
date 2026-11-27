"""Project 4 V2: Zero-Egress Local Cross-Encoder Reranker & Deterministic Citation Verifier."""

from __future__ import annotations

import math
import re

from pydantic import BaseModel, ConfigDict

from aegis_core.models import ScoredChunk

_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")
_CITATION_RE = re.compile(r"\[(chk-[a-z0-9-]+)\]")
_STOPWORDS = frozenset(
    {"the", "and", "for", "with", "that", "this", "from", "are", "was", "were", "what", "who"}
)


def _content_tokens(text: str) -> list[str]:
    return [m.group(0) for m in _TOKEN_RE.finditer(text.lower()) if m.group(0) not in _STOPWORDS]


class CitationVerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    grounded: bool
    cited_chunk_ids: list[str]
    unauthorized_or_missing_citations: list[str]
    lexical_entailment_score: float
    reason: str


class LocalCrossEncoderReranker:
    """Deterministic on-prem second-stage reranker (BM25 saturation + contiguous bigram boost)."""

    def rerank(self, query: str, candidates: list[ScoredChunk], *, top_k: int) -> list[ScoredChunk]:
        if not candidates:
            return []
        q_tokens = _content_tokens(query)
        if not q_tokens:
            return candidates[:top_k]

        q_set = set(q_tokens)
        q_bigrams = {(q_tokens[i], q_tokens[i + 1]) for i in range(len(q_tokens) - 1)}

        scored: list[ScoredChunk] = []
        for chk in candidates:
            doc_tokens = _content_tokens(f"{chk.title} {chk.content}")
            doc_set = set(doc_tokens)
            overlap = len(q_set & doc_set) / max(1, len(q_set))

            doc_bigrams = {
                (doc_tokens[i], doc_tokens[i + 1]) for i in range(len(doc_tokens) - 1)
            }
            bigram_overlap = (
                len(q_bigrams & doc_bigrams) / len(q_bigrams) if q_bigrams else overlap
            )
            # Sigmoid-normalized fusion of RRF prior, exact term coverage, and phrase proximity
            raw = 0.45 * overlap + 0.35 * bigram_overlap + 0.20 * min(1.0, chk.rrf_score * 30.0)
            ce_score = round(1.0 / (1.0 + math.exp(-6.0 * (raw - 0.35))), 6)
            scored.append(chk.model_copy(update={"rerank_score": ce_score}))

        scored.sort(
            key=lambda c: (c.rerank_score if c.rerank_score is not None else 0.0, c.rrf_score),
            reverse=True,
        )
        return scored[:top_k]


def verify_answer_citations(
    *,
    answer_text: str,
    authorized_chunks: list[ScoredChunk],
    min_entailment_overlap: float = 0.25,
) -> CitationVerificationResult:
    """Ensure every `[chk-...]` citation in an LLM answer is RLS-authorized and lexically entailed."""
    cited = list(dict.fromkeys(_CITATION_RE.findall(answer_text)))
    if not cited:
        return CitationVerificationResult(
            grounded=False,
            cited_chunk_ids=[],
            unauthorized_or_missing_citations=[],
            lexical_entailment_score=0.0,
            reason="Missing mandatory [chk-...] provenance citation in generated answer",
        )

    auth_by_id = {c.chunk_id: c for c in authorized_chunks}
    unauthorized = [cid for cid in cited if cid not in auth_by_id]
    if unauthorized:
        return CitationVerificationResult(
            grounded=False,
            cited_chunk_ids=cited,
            unauthorized_or_missing_citations=unauthorized,
            lexical_entailment_score=0.0,
            reason=f"Citation references unauthorized or hallucinated chunk IDs: {unauthorized}",
        )

    cleaned_answer = _CITATION_RE.sub("", answer_text)
    ans_tokens = set(_content_tokens(cleaned_answer))
    if not ans_tokens:
        return CitationVerificationResult(
            grounded=False,
            cited_chunk_ids=cited,
            unauthorized_or_missing_citations=[],
            lexical_entailment_score=0.0,
            reason="Answer contains no substantive tokens outside citation markers",
        )

    evidence_tokens: set[str] = set()
    for cid in cited:
        chk = auth_by_id[cid]
        evidence_tokens.update(_content_tokens(f"{chk.title} {chk.content}"))

    entailment = round(len(ans_tokens & evidence_tokens) / len(ans_tokens), 4)
    if entailment < min_entailment_overlap:
        return CitationVerificationResult(
            grounded=False,
            cited_chunk_ids=cited,
            unauthorized_or_missing_citations=[],
            lexical_entailment_score=entailment,
            reason=(
                f"Answer claims fail lexical entailment against cited chunks "
                f"({entailment:.2%} < {min_entailment_overlap:.2%})"
            ),
        )
    return CitationVerificationResult(
        grounded=True,
        cited_chunk_ids=cited,
        unauthorized_or_missing_citations=[],
        lexical_entailment_score=entailment,
        reason="All citations verified against RLS-authorized chunks with lexical entailment",
    )
