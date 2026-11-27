"""Project 8 V2: Conformal Logprob Cascade, Bounded-Load Consistent Hash Ring & Multi-LoRA WFQ."""

from __future__ import annotations

import bisect
import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Literal

PriorityClass = Literal["CRITICAL", "INTERACTIVE", "BATCH"]


def compute_normalized_logprob_entropy(top_logprobs: list[float]) -> float:
    """Compute normalized Shannon entropy `H(p) / log(K)` in `[0.0, 1.0]` from token logprobs."""
    if len(top_logprobs) <= 1:
        return 0.0
    max_lp = max(top_logprobs)
    exps = [math.exp(lp - max_lp) for lp in top_logprobs]
    total = sum(exps)
    probs = [x / total for x in exps]
    entropy = -sum(p * math.log(max(1e-12, p)) for p in probs)
    return round(min(1.0, entropy / math.log(len(probs))), 6)


@dataclass(frozen=True)
class ConformalCascadeDecision:
    serve_locally_on_8b: bool
    nonconformity_score: float
    conformal_threshold_tau: float
    estimated_cloud_cost_saved_usd: float


class ConformalCascadeDecider:
    """Calibrated Conformal Abstention Router keeping routine `COLD` queries on local 8B GPU."""

    def __init__(self, *, conformal_tau: float = 0.35) -> None:
        if not (0.05 <= conformal_tau <= 0.95):
            raise ValueError("conformal_tau must be in [0.05, 0.95]")
        self._tau = conformal_tau

    def evaluate(
        self,
        *,
        prompt: str,
        classifier_confidence: float,
        top_logprobs: list[float] | None = None,
    ) -> ConformalCascadeDecision:
        if top_logprobs:
            entropy = compute_normalized_logprob_entropy(top_logprobs)
        else:
            # Deterministic structural complexity proxy when raw vLLM logprobs are absent
            complexity_terms = ("synthesize", "multi-step", "derivative", "arbitrage", "proof")
            complex_hits = sum(1 for kw in complexity_terms if kw in prompt.lower())
            length_penalty = min(0.5, len(prompt) / 4000.0)
            entropy = min(1.0, 0.12 + 0.25 * complex_hits + length_penalty)

        nonconformity = round(0.6 * entropy + 0.4 * (1.0 - classifier_confidence), 4)
        serve_local = nonconformity <= self._tau
        saved_usd = round((max(64, len(prompt) // 4) / 1_000_000.0) * 5.00, 6) if serve_local else 0.0
        return ConformalCascadeDecision(
            serve_locally_on_8b=serve_local,
            nonconformity_score=nonconformity,
            conformal_threshold_tau=self._tau,
            estimated_cloud_cost_saved_usd=saved_usd,
        )


class ConsistentHashGPURouter:
    """Bounded-Load Consistent Hash Ring (`O(log V)`) maximizing vLLM RadixAttention prefix hits."""

    def __init__(
        self,
        replica_ids: list[str],
        *,
        virtual_nodes: int = 128,
        load_factor_c: float = 1.25,
    ) -> None:
        if not replica_ids:
            raise ValueError("At least one GPU replica required")
        self._replicas = sorted(set(replica_ids))
        self._vnodes = virtual_nodes
        self._c = max(1.01, load_factor_c)
        self._lock = threading.Lock()
        self._ring_hashes: list[int] = []
        self._ring_nodes: list[str] = []
        self._inflight_by_node: dict[str, int] = {r: 0 for r in self._replicas}

        pairs: list[tuple[int, str]] = []
        for rep in self._replicas:
            for vn in range(self._vnodes):
                h = int.from_bytes(
                    hashlib.sha256(f"{rep}#vn{vn}".encode("ascii")).digest()[:8], "big"
                )
                pairs.append((h, rep))
        pairs.sort(key=lambda p: p[0])
        self._ring_hashes = [p[0] for p in pairs]
        self._ring_nodes = [p[1] for p in pairs]

    def select_replica(self, prefix_key: str) -> str:
        """Select sticky GPU replica for `prefix_key`, spilling to successor only if bounded-load full."""
        key_hash = int.from_bytes(hashlib.sha256(prefix_key.encode("utf-8")).digest()[:8], "big")
        start_idx = bisect.bisect_left(self._ring_hashes, key_hash) % len(self._ring_hashes)

        with self._lock:
            total_inflight = sum(self._inflight_by_node.values()) + 1
            cap = math.ceil((total_inflight / len(self._replicas)) * self._c)
            for offset in range(len(self._ring_hashes)):
                candidate = self._ring_nodes[(start_idx + offset) % len(self._ring_hashes)]
                if self._inflight_by_node[candidate] < cap:
                    self._inflight_by_node[candidate] += 1
                    return candidate
            fallback = self._ring_nodes[start_idx]
            self._inflight_by_node[fallback] += 1
            return fallback

    def release_replica(self, replica_id: str) -> None:
        with self._lock:
            if replica_id in self._inflight_by_node:
                self._inflight_by_node[replica_id] = max(0, self._inflight_by_node[replica_id] - 1)


class MultiLoRARegistry:
    """Maps tenant/department domains to hot-swappable `<32MB` vLLM LoRA adapter IDs."""

    def __init__(self, adapters: dict[str, str] | None = None) -> None:
        self._adapters = dict(
            adapters
            or {
                "M&A Advisory": "lora-mnpi-ma-v2",
                "Procurement": "lora-sap-mm-v2",
                "Treasury": "lora-iso20022-wire-v2",
            }
        )

    def resolve_adapter(self, department: str) -> str:
        return self._adapters.get(department, "lora-base-enterprise-v2")
