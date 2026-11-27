"""Project 9 V2: Atomic Budget Governor, GPU Energy Amortization, Z-Score Anomaly & FOCUS 1.0."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from typing import Any, Literal

BudgetDecisionType = Literal[
    "ALLOW_REQUESTED_MODEL",
    "STEP_DOWN_LOCAL_MODEL",
    "HARD_STOP_BUDGET_EXCEEDED",
]


@dataclass(frozen=True)
class BudgetAdmissionResult:
    decision: BudgetDecisionType
    effective_model_id: str
    utilization_ratio: float
    remaining_budget_usd: float
    runbook_ref: str | None = None


class AtomicBudgetGovernor:
    """Thread-safe atomic pre-flight spend reservation with 80% soft step-down & 100% hard cap."""

    def __init__(
        self,
        *,
        soft_stepdown_ratio: float = 0.80,
        fallback_local_model: str = "qwen2.5-8b-awq-local",
    ) -> None:
        self._soft = soft_stepdown_ratio
        self._fallback = fallback_local_model
        self._lock = threading.Lock()
        self._caps: dict[tuple[str, str], float] = {}
        self._spent: dict[tuple[str, str], float] = {}

    def set_monthly_budget(self, tenant_id: str, cost_center: str, cap_usd: float) -> None:
        if cap_usd <= 0:
            raise ValueError("cap_usd must be > 0")
        with self._lock:
            self._caps[(tenant_id, cost_center)] = cap_usd

    def evaluate_and_reserve(
        self,
        *,
        tenant_id: str,
        cost_center: str,
        requested_model_id: str,
        estimated_cost_usd: float,
        is_critical_override: bool = False,
    ) -> BudgetAdmissionResult:
        key = (tenant_id, cost_center)
        with self._lock:
            cap = self._caps.get(key)
            if cap is None:
                return BudgetAdmissionResult(
                    decision="ALLOW_REQUESTED_MODEL",
                    effective_model_id=requested_model_id,
                    utilization_ratio=0.0,
                    remaining_budget_usd=float("inf"),
                )
            curr = self._spent.get(key, 0.0)
            projected_ratio = (curr + estimated_cost_usd) / cap

            if projected_ratio > 1.0 and not is_critical_override:
                return BudgetAdmissionResult(
                    decision="HARD_STOP_BUDGET_EXCEEDED",
                    effective_model_id=self._fallback,
                    utilization_ratio=round(curr / cap, 4),
                    remaining_budget_usd=round(max(0.0, cap - curr), 4),
                    runbook_ref="https://runbooks.aegis.internal/finops#budget-hard-cap",
                )

            if projected_ratio >= self._soft and requested_model_id != self._fallback:
                stepped_cost = max(0.25, estimated_cost_usd * 0.25)
                if (curr + stepped_cost) > cap and not is_critical_override:
                    return BudgetAdmissionResult(
                        decision="HARD_STOP_BUDGET_EXCEEDED",
                        effective_model_id=self._fallback,
                        utilization_ratio=round(curr / cap, 4),
                        remaining_budget_usd=round(max(0.0, cap - curr), 4),
                        runbook_ref="https://runbooks.aegis.internal/finops#budget-hard-cap",
                    )
                self._spent[key] = curr + stepped_cost
                return BudgetAdmissionResult(
                    decision="STEP_DOWN_LOCAL_MODEL",
                    effective_model_id=self._fallback,
                    utilization_ratio=round(self._spent[key] / cap, 4),
                    remaining_budget_usd=round(max(0.0, cap - self._spent[key]), 4),
                    runbook_ref="https://runbooks.aegis.internal/finops#soft-cap-model-stepdown",
                )

            self._spent[key] = curr + estimated_cost_usd
            return BudgetAdmissionResult(
                decision="ALLOW_REQUESTED_MODEL",
                effective_model_id=requested_model_id,
                utilization_ratio=round(self._spent[key] / cap, 4),
                remaining_budget_usd=round(max(0.0, cap - self._spent[key]), 4),
            )


def compute_onprem_gpu_amortized_cost_usd(
    *,
    gpu_compute_ms: float,
    gpu_hourly_capex_usd: float = 1.85,
    gpu_tdp_watts: float = 350.0,
    pue: float = 1.25,
    kwh_rate_usd: float = 0.11,
) -> float:
    """Attribute self-hosted L40S/H100 hardware CapEx depreciation + datacenter power (`$/GPU-ms`)."""
    hours = max(0.0, gpu_compute_ms) / 3_600_000.0
    capex = hours * gpu_hourly_capex_usd
    kwh = (gpu_tdp_watts * pue / 1000.0) * hours
    power = kwh * kwh_rate_usd
    return round(capex + power, 8)


@dataclass(frozen=True)
class CostAnomalyAlert:
    key: str
    observed_tokens: int
    mean_tokens: float
    z_score: float
    is_anomalous: bool


class WelfordCostAnomalyDetector:
    """Online `O(1)`-memory Welford streaming Z-score detector catching runaway agent retry loops."""

    def __init__(self, *, z_threshold: float = 3.0, min_samples: int = 10) -> None:
        self._z_thresh = z_threshold
        self._min_n = min_samples
        self._lock = threading.Lock()
        # `key -> (count, mean, m2)`
        self._stats: dict[str, tuple[int, float, float]] = {}

    def observe(self, key: str, total_tokens: int) -> CostAnomalyAlert:
        x = float(total_tokens)
        with self._lock:
            n, mean, m2 = self._stats.get(key, (0, 0.0, 0.0))
            if n >= self._min_n:
                variance = max(1.0, m2 / (n - 1))
                std = math.sqrt(variance)
                z = (x - mean) / std
                anomalous = z >= self._z_thresh
            else:
                z = 0.0
                anomalous = False

            # Do not pollute baseline variance with extreme runaway loop outliers
            if not anomalous:
                n_new = n + 1
                delta = x - mean
                mean_new = mean + delta / n_new
                delta2 = x - mean_new
                m2_new = m2 + delta * delta2
                self._stats[key] = (n_new, mean_new, m2_new)

            return CostAnomalyAlert(
                key=key,
                observed_tokens=total_tokens,
                mean_tokens=round(mean, 2),
                z_score=round(z, 3),
                is_anomalous=anomalous,
            )


def render_focus_1_0_chargeback_rows(
    tenant_id: str,
    reports: list[Any],
) -> list[dict[str, str | float | int]]:
    """Export FinOps Open Cost & Usage Specification (FOCUS 1.0) general-ledger rows."""
    rows: list[dict[str, str | float | int]] = []
    for rep in reports:
        rows.append(
            {
                "BillingAccountId": tenant_id,
                "SubAccountId": rep.cost_center,
                "ChargeCategory": "Usage",
                "ServiceName": "Aegis Enterprise AI Runtime",
                "BillingCurrency": "USD",
                "BilledCost": rep.total_ai_spend_usd,
                "EffectiveCost": rep.total_ai_spend_usd,
                "ConsumedQuantity": rep.total_tokens,
                "ConsumedUnit": "Tokens",
                "x_RetryWasteUsd": rep.retry_waste_usd,
                "x_NetRoiUsd": rep.net_roi_usd,
                "x_RoiMultiple": rep.roi_multiple,
            }
        )
    return rows
