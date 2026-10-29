from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
from hkdfguard.diagnostics import (
    AttributeNames,
    CacheMetrics,
    ComponentTelemetry,
    EventNames,
    HkdfGuardEventId,
    HkdfGuardLog,
    HkdfGuardTelemetry,
    MetricNames,
    SpanNames,
    record_exception,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader, NumberDataPoint
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import INVALID_SPAN, StatusCode

ALL_COMPONENTS = [
    HkdfGuardTelemetry.ROOT,
    HkdfGuardTelemetry.CACHE,
    HkdfGuardTelemetry.DATA_PROTECTION,
    HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION,
    HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256,
    HkdfGuardTelemetry.KEY_WRAPPING,
]


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    HkdfGuardTelemetry.set_tracer_provider(provider)
    yield exporter
    HkdfGuardTelemetry.set_tracer_provider(None)


@pytest.fixture
def sensitive(request: pytest.FixtureRequest) -> Iterator[None]:
    originals = [(c, c.sensitive_logging_enabled) for c in ALL_COMPONENTS]
    yield
    for component, original in reversed(originals):
        component.sensitive_logging_enabled = original


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def recording_logger(level: int = logging.DEBUG) -> tuple[logging.Logger, RecordingHandler]:
    logger = logging.Logger(f"recording-{id(object())}", level)
    handler = RecordingHandler()
    logger.addHandler(handler)
    return logger, handler


# --- Components -----------------------------------------------------------------------------


@pytest.mark.parametrize("component", ALL_COMPONENTS, ids=lambda c: c.source_name)
def test_spans_are_reported_under_the_components_scope_name(component: ComponentTelemetry, spans: InMemorySpanExporter) -> None:
    with component.start_span("test-span"):
        pass

    (span,) = spans.get_finished_spans()
    assert span.instrumentation_scope is not None
    assert span.instrumentation_scope.name == component.source_name


@pytest.mark.parametrize("component", ALL_COMPONENTS, ids=lambda c: c.source_name)
def test_an_exception_escaping_a_span_is_recorded_and_marks_it_errored(component: ComponentTelemetry, spans: InMemorySpanExporter) -> None:
    with pytest.raises(ValueError, match="boom"), component.start_span("test-span"):
        raise ValueError("boom")

    (span,) = spans.get_finished_spans()
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description == "boom"
    assert any(e.name == "exception" for e in span.events)


def test_record_exception_with_no_span_does_nothing() -> None:
    record_exception(None, ValueError("boom"))


@pytest.mark.parametrize("component", ALL_COMPONENTS, ids=lambda c: c.source_name)
def test_log_sensitive_operation_with_no_or_a_non_recording_span_does_nothing(component: ComponentTelemetry, sensitive: None) -> None:
    component.sensitive_logging_enabled = True
    component.log_sensitive_operation(None, "op")
    component.log_sensitive_operation(INVALID_SPAN, "op")


@pytest.mark.parametrize("component", ALL_COMPONENTS, ids=lambda c: c.source_name)
def test_log_sensitive_operation_when_disabled_adds_no_event(component: ComponentTelemetry, spans: InMemorySpanExporter, sensitive: None) -> None:
    component.sensitive_logging_enabled = False
    with component.start_span("test-span") as span:
        component.log_sensitive_operation(span, "test-op", {"key": "value"})

    assert spans.get_finished_spans()[0].events == ()


@pytest.mark.parametrize("component", ALL_COMPONENTS, ids=lambda c: c.source_name)
def test_log_sensitive_operation_when_enabled_adds_the_fixed_name_event(component: ComponentTelemetry, spans: InMemorySpanExporter,
                                                                       sensitive: None) -> None:
    component.sensitive_logging_enabled = True
    with component.start_span("test-span") as span:
        component.log_sensitive_operation(span, "test-op", {AttributeNames.NAME: "item"})

    (event,) = spans.get_finished_spans()[0].events
    assert event.name == EventNames.SENSITIVE_OPERATION
    assert event.attributes is not None
    assert event.attributes[AttributeNames.OPERATION_NAME] == "test-op"
    assert event.attributes[AttributeNames.NAME] == "item"


def test_root_shares_its_flag_with_cache_data_protection_and_encrypted_configuration(sensitive: None) -> None:
    HkdfGuardTelemetry.ROOT.sensitive_logging_enabled = True
    assert HkdfGuardTelemetry.CACHE.sensitive_logging_enabled
    assert HkdfGuardTelemetry.DATA_PROTECTION.sensitive_logging_enabled
    assert HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION.sensitive_logging_enabled

    HkdfGuardTelemetry.CACHE.sensitive_logging_enabled = False
    assert not HkdfGuardTelemetry.ROOT.sensitive_logging_enabled
    assert not HkdfGuardTelemetry.DATA_PROTECTION.sensitive_logging_enabled


def test_crypto_provider_and_key_wrapping_flags_are_independent(sensitive: None) -> None:
    HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.sensitive_logging_enabled = False
    HkdfGuardTelemetry.KEY_WRAPPING.sensitive_logging_enabled = False

    HkdfGuardTelemetry.ROOT.sensitive_logging_enabled = True
    assert not HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.sensitive_logging_enabled
    assert not HkdfGuardTelemetry.KEY_WRAPPING.sensitive_logging_enabled

    HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.sensitive_logging_enabled = True
    assert not HkdfGuardTelemetry.KEY_WRAPPING.sensitive_logging_enabled


# --- Metrics --------------------------------------------------------------------------------


def test_cache_operations_counter_reports_measurements_with_their_attributes() -> None:
    reader = InMemoryMetricReader()
    HkdfGuardTelemetry.set_meter_provider(MeterProvider(metric_readers=[reader]))
    try:
        CacheMetrics.operations().add(1, {AttributeNames.RESULT: "success"})

        data = reader.get_metrics_data()
        assert data is not None
        metrics = [m for rm in data.resource_metrics for sm in rm.scope_metrics if sm.scope.name == HkdfGuardTelemetry.CACHE.source_name
                   for m in sm.metrics]
        (metric,) = [m for m in metrics if m.name == MetricNames.Cache.OPERATIONS]
        assert metric.unit == CacheMetrics.OPERATIONS_UNIT
        (point,) = metric.data.data_points
        assert isinstance(point, NumberDataPoint) and point.value == 1
        assert point.attributes == {AttributeNames.RESULT: "success"}
    finally:
        HkdfGuardTelemetry.set_meter_provider(None)


# --- Log messages ---------------------------------------------------------------------------


def _single(handler: RecordingHandler) -> logging.LogRecord:
    assert len(handler.records) == 1
    return handler.records[0]


def _event_id(record: logging.LogRecord) -> int:
    return int(getattr(record, HkdfGuardLog.EVENT_ID_KEY))


def test_event_ids_match_every_port() -> None:
    assert {member.name: member.value for member in HkdfGuardEventId} == {
        "SENSITIVE_OPERATION_LOGGED": 1,
        "OPERATION_FAILED": 2,
        "KEY_REFRESH_FAILED": 3,
        "KEY_ACCESS_SUSPENDED": 4,
        "KEY_ACCESS_RESUMED": 5,
        "EPHEMERAL_KEY_ROTATED": 6,
        "EPHEMERAL_KEY_ROTATION_FAILED": 7,
        "EPHEMERAL_KEY_RETIRED": 8,
        "EPHEMERAL_KEY_RETIREMENT_FAILED": 9,
        "ENCRYPTION_BUDGET_WARNING": 10,
    }


def test_cache_span_names_match_every_port() -> None:
    assert (SpanNames.Cache.ADD, SpanNames.Cache.ADD_OR_UPDATE, SpanNames.Cache.DECRYPT, SpanNames.Cache.POPULATE) == (
        "hkdfguard.cache.add", "hkdfguard.cache.add_or_update", "hkdfguard.cache.decrypt", "hkdfguard.cache.populate")


def test_a_record_carries_its_event_id_as_a_plain_int() -> None:
    logger, handler = recording_logger()

    HkdfGuardLog.key_access_resumed(logger, 3)

    event_id = getattr(_single(handler), HkdfGuardLog.EVENT_ID_KEY)
    assert type(event_id) is int
    assert event_id == HkdfGuardEventId.KEY_ACCESS_RESUMED


def test_sensitive_operation_logged_writes_a_debug_entry() -> None:
    logger, handler = recording_logger()

    HkdfGuardLog.sensitive_operation_logged(logger, "hkdfguard.cache.add", "item")

    record = _single(handler)
    assert record.levelno == logging.DEBUG
    assert _event_id(record) == 1
    assert record.getMessage() == "hkdfguard.cache.add completed for item."


def test_operation_failed_writes_an_error_entry_carrying_the_exception() -> None:
    logger, handler = recording_logger()
    failure = RuntimeError("boom")

    HkdfGuardLog.operation_failed(logger, "hkdfguard.cache.add", failure)

    record = _single(handler)
    assert record.levelno == logging.ERROR
    assert _event_id(record) == 2
    assert record.getMessage() == "hkdfguard.cache.add failed."
    assert record.exc_info is not None and record.exc_info[1] is failure


def test_key_refresh_failed_writes_an_error_entry_with_the_count_and_policy() -> None:
    logger, handler = recording_logger()
    failure = RuntimeError("KEK unavailable")

    HkdfGuardLog.key_refresh_failed(logger, 2, "fail closed after 3 consecutive failures", failure)

    record = _single(handler)
    assert record.levelno == logging.ERROR
    assert _event_id(record) == 3
    assert record.getMessage() == "Background key refresh failed (2 consecutive). Policy: fail closed after 3 consecutive failures."
    assert record.exc_info is not None and record.exc_info[1] is failure


def test_key_access_suspended_writes_a_critical_entry() -> None:
    logger, handler = recording_logger()

    HkdfGuardLog.key_access_suspended(logger, 3)

    record = _single(handler)
    assert record.levelno == logging.CRITICAL
    assert _event_id(record) == 4
    assert record.getMessage().startswith("Key access suspended after 3 consecutive failed refreshes")


@pytest.mark.parametrize(("log", "event_id", "level", "message"), [
    (lambda lg: HkdfGuardLog.key_access_resumed(lg, 4), 5, logging.INFO,
     "Key access resumed: a background refresh succeeded after 4 consecutive failures."),
    (lambda lg: HkdfGuardLog.ephemeral_key_rotated(lg, 8), 6, logging.INFO, "Ephemeral key rotated: version 8 is now current."),
    (lambda lg: HkdfGuardLog.ephemeral_key_rotation_failed(lg, 7, RuntimeError()), 7, logging.ERROR,
     "Ephemeral key rotation failed; version 7 stays current until the next attempt."),
    (lambda lg: HkdfGuardLog.ephemeral_key_retired(lg, 2), 8, logging.INFO,
     "Ephemeral key retired: version 2 has been removed and its key zeroed; values encrypted under it no longer decrypt."),
    (lambda lg: HkdfGuardLog.ephemeral_key_retirement_failed(lg, 3, RuntimeError()), 9, logging.ERROR,
     "Ephemeral key version 3 was removed from the ring, but disposing it failed."),
    (lambda lg: HkdfGuardLog.encryption_budget_warning(lg, 2, 10), 10, logging.WARNING,
     "This key has performed 2 encryptions of its 10 AES-GCM limit; rotate it before the limit, when it stops encrypting."),
])
def test_every_entry_carries_its_event_id_level_and_message(log, event_id: int, level: int, message: str) -> None:  # type: ignore[no-untyped-def]
    logger, handler = recording_logger()

    log(logger)

    record = _single(handler)
    assert (_event_id(record), record.levelno, record.getMessage()) == (event_id, level, message)


def test_entries_below_the_loggers_level_and_a_none_logger_write_nothing() -> None:
    logger, handler = recording_logger(logging.CRITICAL + 1)

    HkdfGuardLog.sensitive_operation_logged(logger, "op", "item")
    HkdfGuardLog.operation_failed(logger, "op", RuntimeError())
    HkdfGuardLog.key_access_suspended(logger, 1)
    HkdfGuardLog.key_access_suspended(None, 1)

    assert handler.records == []
