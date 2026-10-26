"""HkdfGuard's telemetry: one :class:`ComponentTelemetry` per component, the span, attribute, event
and metric names every component emits, and the log messages they share."""

from hkdfguard.diagnostics._log import HkdfGuardEventId, HkdfGuardLog
from hkdfguard.diagnostics._names import AttributeNames, EventNames, MetricNames, SpanNames
from hkdfguard.diagnostics._telemetry import CacheMetrics, ComponentTelemetry, HkdfGuardTelemetry, record_exception

__all__ = [
    "AttributeNames",
    "CacheMetrics",
    "ComponentTelemetry",
    "EventNames",
    "HkdfGuardEventId",
    "HkdfGuardLog",
    "HkdfGuardTelemetry",
    "MetricNames",
    "SpanNames",
    "record_exception",
]
