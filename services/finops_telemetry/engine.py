"""Cache/retry/GPU-aware FinOps Engine with Atomic Budget Step-Down, Anomaly Z-Score & FOCUS 1.0."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis_core.http_middleware import install_aegis_http_layer
from aegis_core.sli_metrics import GLOBAL_SLI_REGISTRY, SLIRegistry
from finops_telemetry.budget_governor import (
    AtomicBudgetGovernor,
    BudgetAdmissionResult,
    WelfordCostAnomalyDetector,
    compute_onprem_gpu_amortized_cost_usd,
    render_focus_1_0_chargeback_rows,
)


@dataclass(frozen=True)
class ModelRateCard:
    """USD per 1,000,000 tokens (separating uncached input, cached read, reasoning, output)."""

    model_id: str
    input_per_1m_usd: float
    cached_input_per_1m_usd: float
    reasoning_per_1m_usd: float
    output_per_1m_usd: float


@dataclass(frozen=True)
class WorkflowBenchmark:
    """Calibrated baseline human task duration & rework penalty when an agent escalates/errs."""

    workflow_type: str
    human_baseline_minutes: float
    escalation_rework_minutes: float
    loaded_hourly_rate_usd: float


DEFAULT_RATE_CARDS: dict[str, ModelRateCard] = {
    "gpt-5-enterprise": ModelRateCard("gpt-5-enterprise", 5.00, 0.50, 15.00, 15.00),
    "claude-4-sonnet": ModelRateCard("claude-4-sonnet", 3.00, 0.30, 12.00, 15.00),
    "qwen2.5-8b-awq-local": ModelRateCard("qwen2.5-8b-awq-local", 0.08, 0.02, 0.08, 0.12),
    "bge-large-en-v1.5": ModelRateCard("bge-large-en-v1.5", 0.05, 0.05, 0.0, 0.0),
}

DEFAULT_WORKFLOW_BENCHMARKS: dict[str, WorkflowBenchmark] = {
    "ma_diligence_memo": WorkflowBenchmark("ma_diligence_memo", 45.0, 20.0, 220.0),
    "sap_po_triage": WorkflowBenchmark("sap_po_triage", 18.0, 10.0, 95.0),
    "wire_settlement_recon": WorkflowBenchmark("wire_settlement_recon", 25.0, 15.0, 130.0),
}


class GenAITelemetryEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(min_length=3, max_length=128)
    trace_id: str = Field(min_length=4, max_length=128)
    tenant_id: str
    cost_center: str
    workflow_type: str
    human_subject: str
    actor_spiffe_id: str
    model_id: str
    uncached_input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    reasoning_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    external_api_cost_usd: float = Field(default=0.0, ge=0.0)
    onprem_gpu_compute_ms: float = Field(default=0.0, ge=0.0)
    is_retry_attempt: bool = False
    outcome: Literal["VERIFIED_RESOLVED", "HUMAN_ESCALATED", "FAILED_RETRY"]


class DepartmentROIReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    cost_center: str
    total_events: int
    verified_resolutions: int
    human_escalations: int
    failed_retries: int
    total_tokens: int
    retry_waste_usd: float
    total_ai_spend_usd: float
    net_hours_saved: float
    gross_productivity_value_usd: float
    net_roi_usd: float
    roi_multiple: float


class FinOpsTelemetryEngine:
    """Ingests OTel `gen_ai.*` events, governs atomic budgets, detects anomalies & exports FOCUS."""

    def __init__(
        self,
        *,
        db_path: Path | None = None,
        rate_cards: dict[str, ModelRateCard] | None = None,
        benchmarks: dict[str, WorkflowBenchmark] | None = None,
        sli_registry: SLIRegistry | None = None,
    ) -> None:
        self._uri = str(db_path) if db_path is not None else ":memory:"
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._uri, check_same_thread=False)
        if db_path is not None:
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._rates = dict(rate_cards) if rate_cards is not None else dict(DEFAULT_RATE_CARDS)
        self._benchmarks = (
            dict(benchmarks) if benchmarks is not None else dict(DEFAULT_WORKFLOW_BENCHMARKS)
        )
        self.budget_governor = AtomicBudgetGovernor()
        self.anomaly_detector = WelfordCostAnomalyDetector()
        self._sli = sli_registry or GLOBAL_SLI_REGISTRY
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS finops_events (
                    event_id              TEXT PRIMARY KEY,
                    trace_id              TEXT NOT NULL,
                    tenant_id             TEXT NOT NULL,
                    cost_center           TEXT NOT NULL,
                    workflow_type         TEXT NOT NULL,
                    human_subject         TEXT NOT NULL,
                    actor_spiffe_id       TEXT NOT NULL,
                    model_id              TEXT NOT NULL,
                    total_tokens          INTEGER NOT NULL,
                    computed_cost_usd     REAL NOT NULL,
                    is_retry_attempt      INTEGER NOT NULL,
                    outcome               TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    def compute_event_cost_usd(self, ev: GenAITelemetryEvent) -> float:
        rate = self._rates.get(ev.model_id)
        if rate is None:
            raise KeyError(f"Missing pricing rate card for model {ev.model_id!r}")
        token_cost = (
            (ev.uncached_input_tokens / 1_000_000.0) * rate.input_per_1m_usd
            + (ev.cached_input_tokens / 1_000_000.0) * rate.cached_input_per_1m_usd
            + (ev.reasoning_tokens / 1_000_000.0) * rate.reasoning_per_1m_usd
            + (ev.output_tokens / 1_000_000.0) * rate.output_per_1m_usd
        )
        gpu_cost = (
            compute_onprem_gpu_amortized_cost_usd(gpu_compute_ms=ev.onprem_gpu_compute_ms)
            if ev.onprem_gpu_compute_ms > 0.0
            else 0.0
        )
        return round(token_cost + ev.external_api_cost_usd + gpu_cost, 8)

    def record_event(self, ev: GenAITelemetryEvent) -> float:
        cost = self.compute_event_cost_usd(ev)
        total_toks = (
            ev.uncached_input_tokens
            + ev.cached_input_tokens
            + ev.reasoning_tokens
            + ev.output_tokens
        )
        alert = self.anomaly_detector.observe(f"{ev.tenant_id}:{ev.workflow_type}", total_toks)
        if alert.is_anomalous:
            self._sli.inc_counter(
                "aegis_finops_token_anomalies_total", 1.0, {"tenant": ev.tenant_id}
            )
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO finops_events (
                    event_id, trace_id, tenant_id, cost_center, workflow_type,
                    human_subject, actor_spiffe_id, model_id, total_tokens,
                    computed_cost_usd, is_retry_attempt, outcome
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev.event_id,
                    ev.trace_id,
                    ev.tenant_id,
                    ev.cost_center,
                    ev.workflow_type,
                    ev.human_subject,
                    ev.actor_spiffe_id,
                    ev.model_id,
                    total_toks,
                    cost,
                    1 if ev.is_retry_attempt else 0,
                    ev.outcome,
                ),
            )
            self._conn.commit()
        return cost

    def evaluate_budget_gate(
        self,
        *,
        tenant_id: str,
        cost_center: str,
        requested_model_id: str,
        estimated_cost_usd: float,
        is_critical_override: bool = False,
    ) -> BudgetAdmissionResult:
        res = self.budget_governor.evaluate_and_reserve(
            tenant_id=tenant_id,
            cost_center=cost_center,
            requested_model_id=requested_model_id,
            estimated_cost_usd=estimated_cost_usd,
            is_critical_override=is_critical_override,
        )
        self._sli.inc_counter(
            "aegis_finops_budget_decisions_total", 1.0, {"decision": res.decision}
        )
        return res

    def export_focus_chargeback(self, tenant_id: str) -> list[dict[str, str | float | int]]:
        reports = self.department_roi_reports(tenant_id)
        return render_focus_1_0_chargeback_rows(tenant_id, reports)

    def department_roi_reports(self, tenant_id: str) -> list[DepartmentROIReport]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT cost_center, workflow_type, total_tokens, computed_cost_usd,
                       is_retry_attempt, outcome
                FROM finops_events
                WHERE tenant_id = ?
                ORDER BY cost_center ASC
                """,
                (tenant_id,),
            ).fetchall()

        grouped: dict[str, list[tuple[str, int, float, int, str]]] = {}
        for r in rows:
            cc = str(r[0])
            grouped.setdefault(cc, []).append(
                (str(r[1]), int(r[2]), float(r[3]), int(r[4]), str(r[5]))
            )

        reports: list[DepartmentROIReport] = []
        for cc, items in sorted(grouped.items()):
            verified = 0
            escalations = 0
            retries = 0
            tokens = 0
            spend = 0.0
            retry_waste = 0.0
            net_minutes = 0.0
            gross_value = 0.0

            for wf_type, tok, cost, is_retry, outcome in items:
                tokens += tok
                spend += cost
                if is_retry or outcome == "FAILED_RETRY":
                    retries += 1
                    retry_waste += cost
                bench = self._benchmarks.get(
                    wf_type, WorkflowBenchmark(wf_type, 15.0, 10.0, 100.0)
                )
                if outcome == "VERIFIED_RESOLVED":
                    verified += 1
                    hrs = bench.human_baseline_minutes / 60.0
                    net_minutes += bench.human_baseline_minutes
                    gross_value += hrs * bench.loaded_hourly_rate_usd
                elif outcome == "HUMAN_ESCALATED":
                    escalations += 1
                    hrs_lost = bench.escalation_rework_minutes / 60.0
                    net_minutes -= bench.escalation_rework_minutes
                    gross_value -= hrs_lost * bench.loaded_hourly_rate_usd

            net_roi = gross_value - spend
            multiple = round(gross_value / spend, 2) if spend > 0 else 0.0
            reports.append(
                DepartmentROIReport(
                    tenant_id=tenant_id,
                    cost_center=cc,
                    total_events=len(items),
                    verified_resolutions=verified,
                    human_escalations=escalations,
                    failed_retries=retries,
                    total_tokens=tokens,
                    retry_waste_usd=round(retry_waste, 4),
                    total_ai_spend_usd=round(spend, 4),
                    net_hours_saved=round(net_minutes / 60.0, 3),
                    gross_productivity_value_usd=round(gross_value, 2),
                    net_roi_usd=round(net_roi, 2),
                    roi_multiple=multiple,
                )
            )
        return reports


class SetBudgetRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    cost_center: str
    monthly_cap_usd: float = Field(gt=0.0)


class BudgetCheckRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str
    cost_center: str
    requested_model_id: str
    estimated_cost_usd: float = Field(ge=0.0)
    is_critical_override: bool = False


def create_finops_app(engine: FinOpsTelemetryEngine) -> FastAPI:
    app = FastAPI(title="Aegis Department FinOps & ROI Telemetry API", version="0.3.0")
    install_aegis_http_layer(app, service_name="finops-telemetry")

    @app.post("/v1/finops/events")
    def ingest_event(ev: GenAITelemetryEvent) -> dict[str, float | str]:
        cost = engine.record_event(ev)
        return {"event_id": ev.event_id, "attributed_cost_usd": cost}

    @app.post("/v1/finops/budgets")
    def set_budget(req: SetBudgetRequest) -> dict[str, Any]:
        engine.budget_governor.set_monthly_budget(
            req.tenant_id, req.cost_center, req.monthly_cap_usd
        )
        return {"status": "configured", "monthly_cap_usd": req.monthly_cap_usd}

    @app.post("/v1/finops/budgets/evaluate", response_model=None)
    def check_budget(req: BudgetCheckRequest) -> dict[str, Any] | JSONResponse:
        res = engine.evaluate_budget_gate(
            tenant_id=req.tenant_id,
            cost_center=req.cost_center,
            requested_model_id=req.requested_model_id,
            estimated_cost_usd=req.estimated_cost_usd,
            is_critical_override=req.is_critical_override,
        )
        code = 429 if res.decision == "HARD_STOP_BUDGET_EXCEEDED" else 200
        return JSONResponse(
            status_code=code,
            content={
                "decision": res.decision,
                "effective_model_id": res.effective_model_id,
                "utilization_ratio": res.utilization_ratio,
                "remaining_budget_usd": res.remaining_budget_usd,
                "runbook_ref": res.runbook_ref,
            },
        )

    @app.get("/v1/finops/roi/{tenant_id}", response_model=list[DepartmentROIReport])
    def get_roi(tenant_id: str) -> list[DepartmentROIReport]:
        return engine.department_roi_reports(tenant_id)

    @app.get("/v1/finops/focus-export/{tenant_id}")
    def get_focus_export(tenant_id: str) -> list[dict[str, str | float | int]]:
        return engine.export_focus_chargeback(tenant_id)

    return app
