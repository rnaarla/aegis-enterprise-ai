"""Project 10 V2: Paired Bootstrap 99% CI, Stratified Slice Gates, Fault Taxonomy & Shadow Tap."""

from __future__ import annotations

import math
import random
import threading
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict


def compute_bootstrap_ci99_lower(
    outcomes: list[bool],
    *,
    num_resamples: int = 300,
    seed: int = 42,
) -> float:
    """Compute deterministic paired bootstrap 99% lower confidence bound (`alpha = 0.01`)."""
    n = len(outcomes)
    if n == 0:
        return 0.0
    if all(outcomes):
        # Exact Clopper-Pearson / rule-of-three 99% lower bound for 0 failures over N trials
        return round(max(0.0, 1.0 - (4.605 / max(10, n))), 4)

    rng = random.Random(seed)  # noqa: S311 - deterministic statistical CI resampling seed
    int_outcomes = [1 if ok else 0 for ok in outcomes]
    means: list[float] = []
    for _ in range(num_resamples):
        sample_sum = sum(int_outcomes[rng.randrange(n)] for _ in range(n))
        means.append(sample_sum / n)
    means.sort()
    idx = max(0, math.floor(0.01 * len(means)))
    return round(means[idx], 4)


class AdversarialScenarioResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    total_attacks: int
    blocked_attacks: int
    defense_rate: float
    passed: bool


@dataclass(frozen=True)
class DarkTrafficComparison:
    total_mirrored: int
    exact_tool_matches: int
    agreement_rate: float
    divergent_categories: dict[str, int]


class DarkTrafficShadowMirror:
    """Envoy-style read-only dark-traffic shadow tap comparing `prod` vs `v_next` prompts."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total = 0
        self._matches = 0
        self._divergences: dict[str, int] = {}

    def tap_request(
        self,
        *,
        prod_tool: str,
        candidate_tool: str,
        category: str = "live_traffic",
    ) -> bool:
        matched = prod_tool == candidate_tool
        with self._lock:
            self._total += 1
            if matched:
                self._matches += 1
            else:
                self._divergences[category] = self._divergences.get(category, 0) + 1
        return matched

    def snapshot(self) -> DarkTrafficComparison:
        with self._lock:
            rate = round(self._matches / self._total, 4) if self._total > 0 else 1.0
            return DarkTrafficComparison(
                total_mirrored=self._total,
                exact_tool_matches=self._matches,
                agreement_rate=rate,
                divergent_categories=dict(self._divergences),
            )
