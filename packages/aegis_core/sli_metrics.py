"""SRE Service Level Indicator (SLI), Error Budget & Prometheus OpenMetrics Engine.

Implements Google SRE Four Golden Signals (Latency, Traffic, Errors, Saturation) and
Multi-Window Multi-Burn-Rate SLO tracking (`99.95%` target) with zero external daemon
dependencies and thread-safe `O(1)` counter/gauge updates + fixed-bucket histograms.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

DEFAULT_LATENCY_BUCKETS_SECONDS: tuple[float, ...] = (
    0.001,
    0.0025,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
)


def _format_labels(labels: dict[str, str] | None) -> str:
    if not labels:
        return ""
    parts = [
        f'{k}="{v.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
        for k, v in sorted(labels.items())
    ]
    return "{" + ",".join(parts) + "}"


def _label_key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted(labels.items()))


@dataclass(frozen=True)
class HistogramSnapshot:
    count: int
    total_sum: float
    p50_seconds: float
    p95_seconds: float
    p99_seconds: float


@dataclass(frozen=True)
class SLOBurnSnapshot:
    service_name: str
    target_availability: float
    total_requests: int
    error_requests: int
    observed_availability: float
    error_budget_remaining_ratio: float
    burn_rate_short_window: float
    burn_rate_long_window: float
    page_alert_fast_burn_14_4x: bool
    ticket_alert_slow_burn_6x: bool


class _HistogramSeries:
    """Fixed-bucket cumulative histogram + bounded ring buffer (`<= 2048`) for exact quantiles."""

    def __init__(self, buckets: tuple[float, ...], sample_window: int = 2048) -> None:
        self.buckets = buckets
        self.bucket_counts = [0] * len(buckets)
        self.count = 0
        self.total_sum = 0.0
        self.recent_samples: deque[float] = deque(maxlen=sample_window)

    def observe(self, value: float) -> None:
        v = max(0.0, value)
        self.count += 1
        self.total_sum += v
        self.recent_samples.append(v)
        for idx, bound in enumerate(self.buckets):
            if v <= bound:
                self.bucket_counts[idx] += 1

    def quantile(self, q: float) -> float:
        if not self.recent_samples:
            return 0.0
        ordered = sorted(self.recent_samples)
        pos = min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))
        return round(ordered[pos], 6)


class SLIRegistry:
    """Thread-safe Prometheus OpenMetrics registry + Google SRE Multi-Burn SLO evaluator."""

    def __init__(
        self,
        *,
        target_availability: float = 0.9995,
        latency_buckets: tuple[float, ...] = DEFAULT_LATENCY_BUCKETS_SECONDS,
        clock: Any = time.monotonic,
    ) -> None:
        if not (0.9 <= target_availability < 1.0):
            raise ValueError("target_availability must be in [0.9, 1.0)")
        self._target_avail = target_availability
        self._buckets = latency_buckets
        self._clock = clock
        self._lock = threading.RLock()
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
        self._gauges: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
        self._histograms: dict[str, dict[tuple[tuple[str, str], ...], _HistogramSeries]] = {}
        # Bounded sliding event ring `(monotonic_ts, is_error)` per service (`<= 10_000` events)
        self._slo_events: dict[str, deque[tuple[float, bool]]] = {}
        self._slo_totals: dict[str, tuple[int, int]] = {}

    def inc_counter(
        self,
        name: str,
        amount: float = 1.0,
        labels: dict[str, str] | None = None,
    ) -> None:
        key = _label_key(labels)
        with self._lock:
            series = self._counters.setdefault(name, {})
            series[key] = series.get(key, 0.0) + amount

    def set_gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        key = _label_key(labels)
        with self._lock:
            series = self._gauges.setdefault(name, {})
            series[key] = value

    def add_gauge(
        self,
        name: str,
        delta: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        key = _label_key(labels)
        with self._lock:
            series = self._gauges.setdefault(name, {})
            series[key] = series.get(key, 0.0) + delta

    def observe_histogram(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        key = _label_key(labels)
        with self._lock:
            series = self._histograms.setdefault(name, {})
            hist = series.get(key)
            if hist is None:
                hist = _HistogramSeries(self._buckets)
                series[key] = hist
            hist.observe(value)

    def record_sli_request(
        self,
        *,
        service_name: str,
        method: str,
        route: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        """Record Golden Signals (Traffic, Latency, Errors) and update SLO burn windows."""
        status_str = str(status_code)
        is_server_error = status_code >= 500 and status_code != 503
        # Note: Intentional fail-closed backpressure (HTTP 503 gpu_overload / sap_backpressure)
        # is tracked distinctly from unhandled 5xx faults; callers can also inspect 503 rate.
        self.inc_counter(
            "aegis_http_requests_total",
            1.0,
            {"service": service_name, "method": method, "route": route, "status": status_str},
        )
        self.observe_histogram(
            "aegis_http_request_duration_seconds",
            duration_seconds,
            {"service": service_name, "method": method, "route": route},
        )
        now = float(self._clock())
        with self._lock:
            tot, errs = self._slo_totals.get(service_name, (0, 0))
            self._slo_totals[service_name] = (tot + 1, errs + (1 if is_server_error else 0))
            ring = self._slo_events.setdefault(service_name, deque(maxlen=10_000))
            ring.append((now, is_server_error))

    def histogram_snapshot(
        self,
        name: str,
        labels: dict[str, str] | None = None,
    ) -> HistogramSnapshot:
        key = _label_key(labels)
        with self._lock:
            series = self._histograms.get(name, {})
            if labels is not None:
                hist = series.get(key)
                if hist is None:
                    return HistogramSnapshot(0, 0.0, 0.0, 0.0, 0.0)
                return HistogramSnapshot(
                    count=hist.count,
                    total_sum=round(hist.total_sum, 6),
                    p50_seconds=hist.quantile(0.50),
                    p95_seconds=hist.quantile(0.95),
                    p99_seconds=hist.quantile(0.99),
                )
            # Aggregate across all label sets for the given metric name
            combined: list[float] = []
            tot_count = 0
            tot_sum = 0.0
            for h in series.values():
                tot_count += h.count
                tot_sum += h.total_sum
                combined.extend(h.recent_samples)
            if not combined:
                return HistogramSnapshot(0, 0.0, 0.0, 0.0, 0.0)
            combined.sort()

            def _q(p: float) -> float:
                idx = min(len(combined) - 1, max(0, math.ceil(p * len(combined)) - 1))
                return round(combined[idx], 6)

            return HistogramSnapshot(
                count=tot_count,
                total_sum=round(tot_sum, 6),
                p50_seconds=_q(0.50),
                p95_seconds=_q(0.95),
                p99_seconds=_q(0.99),
            )

    def evaluate_slo(
        self,
        service_name: str,
        *,
        short_window_seconds: float = 300.0,
        long_window_seconds: float = 3600.0,
    ) -> SLOBurnSnapshot:
        """Evaluate Google SRE Workbook Multi-Window Multi-Burn-Rate alerts (14.4x / 6x)."""
        error_budget = 1.0 - self._target_avail
        now = float(self._clock())
        with self._lock:
            tot, errs = self._slo_totals.get(service_name, (0, 0))
            events = list(self._slo_events.get(service_name, ()))

        if tot == 0:
            return SLOBurnSnapshot(
                service_name=service_name,
                target_availability=self._target_avail,
                total_requests=0,
                error_requests=0,
                observed_availability=1.0,
                error_budget_remaining_ratio=1.0,
                burn_rate_short_window=0.0,
                burn_rate_long_window=0.0,
                page_alert_fast_burn_14_4x=False,
                ticket_alert_slow_burn_6x=False,
            )

        obs_avail = (tot - errs) / tot
        obs_err_rate = errs / tot
        remaining = max(0.0, 1.0 - (obs_err_rate / error_budget))

        short_events = [is_err for ts, is_err in events if (now - ts) <= short_window_seconds]
        long_events = [is_err for ts, is_err in events if (now - ts) <= long_window_seconds]

        short_err_rate = (
            sum(1 for e in short_events if e) / len(short_events) if short_events else 0.0
        )
        long_err_rate = (
            sum(1 for e in long_events if e) / len(long_events) if long_events else 0.0
        )

        burn_short = round(short_err_rate / error_budget, 4)
        burn_long = round(long_err_rate / error_budget, 4)

        # Require minimum traffic floor (>= 20 requests) to prevent low-QPS false-positive paging
        min_qps_met = len(long_events) >= 20
        fast_alert = min_qps_met and burn_short >= 14.4 and burn_long >= 14.4
        slow_alert = min_qps_met and burn_short >= 6.0 and burn_long >= 6.0

        return SLOBurnSnapshot(
            service_name=service_name,
            target_availability=self._target_avail,
            total_requests=tot,
            error_requests=errs,
            observed_availability=round(obs_avail, 6),
            error_budget_remaining_ratio=round(remaining, 4),
            burn_rate_short_window=burn_short,
            burn_rate_long_window=burn_long,
            page_alert_fast_burn_14_4x=fast_alert,
            ticket_alert_slow_burn_6x=slow_alert,
        )

    def render_prometheus_text(self) -> str:
        """Serialize all registered counters, gauges, and histograms in Prometheus 0.0.4 text format."""
        lines: list[str] = []
        with self._lock:
            for name, series in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} counter")
                for key, val in sorted(series.items()):
                    lbl = _format_labels(dict(key))
                    lines.append(f"{name}{lbl} {val}")

            for name, series in sorted(self._gauges.items()):
                lines.append(f"# TYPE {name} gauge")
                for key, val in sorted(series.items()):
                    lbl = _format_labels(dict(key))
                    lines.append(f"{name}{lbl} {val}")

            for name, h_series in sorted(self._histograms.items()):
                lines.append(f"# TYPE {name} histogram")
                for key, hist in sorted(h_series.items()):
                    base_dict = dict(key)
                    for bound, b_cnt in zip(hist.buckets, hist.bucket_counts, strict=True):
                        b_lbl = _format_labels({**base_dict, "le": str(bound)})
                        lines.append(f"{name}_bucket{b_lbl} {b_cnt}")
                    inf_lbl = _format_labels({**base_dict, "le": "+Inf"})
                    lines.append(f"{name}_bucket{inf_lbl} {hist.count}")
                    base_lbl = _format_labels(base_dict)
                    lines.append(f"{name}_sum{base_lbl} {round(hist.total_sum, 6)}")
                    lines.append(f"{name}_count{base_lbl} {hist.count}")

        return "\n".join(lines) + "\n"


GLOBAL_SLI_REGISTRY = SLIRegistry()
