"""OpenTelemetry instrumentation for security & GenAI operations (OTel semantic conventions)."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult


class InMemoryTelemetryCollector(SpanExporter):
    """Captures OpenTelemetry spans in-process for audit inspection, tests, and FinOps export."""

    def __init__(self) -> None:
        self._spans: list[ReadableSpan] = []

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self._spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None

    def get_finished_spans(self) -> list[ReadableSpan]:
        return list(self._spans)

    def clear(self) -> None:
        self._spans.clear()


class AegisTelemetry:
    """Structured OpenTelemetry wrapper emitting `aegis.*` and `gen_ai.*` spans."""

    def __init__(self, service_name: str = "aegis-enterprise-ai") -> None:
        self.collector = InMemoryTelemetryCollector()
        resource = Resource.create({"service.name": service_name})
        self._provider = TracerProvider(resource=resource)
        self._provider.add_span_processor(SimpleSpanProcessor(self.collector))
        self._tracer = self._provider.get_tracer(service_name)

    def finished_spans(self) -> list[ReadableSpan]:
        """Encapsulated span snapshot accessor (preserves Law of Demeter for callers)."""
        return self.collector.get_finished_spans()

    def clear_spans(self) -> None:
        """Clear recorded spans through the facade without reaching into `collector`."""
        self.collector.clear()

    @contextmanager
    def span(
        self,
        name: str,
        attributes: dict[str, str | int | float | bool] | None = None,
    ) -> Iterator[trace.Span]:
        with self._tracer.start_as_current_span(name) as current_span:
            if attributes:
                for key, val in attributes.items():
                    current_span.set_attribute(key, val)
            yield current_span
