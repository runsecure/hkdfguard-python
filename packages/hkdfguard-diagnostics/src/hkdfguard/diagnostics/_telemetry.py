"""One :class:`ComponentTelemetry` per HkdfGuard component, and where their telemetry goes."""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import ClassVar, Final

from hkdfguard.diagnostics._names import AttributeNames, EventNames, MetricNames
from opentelemetry import metrics, trace
from opentelemetry.metrics import Counter, Meter, MeterProvider
from opentelemetry.trace import Span, Status, StatusCode, Tracer, TracerProvider
from opentelemetry.util.types import AttributeValue


class ComponentTelemetry:
    """One component's telemetry surface: a tracer and meter sharing the component's
    instrumentation scope name, a sensitive-logging toggle, and the helpers every operation calls.

    The tracer and meter are resolved from :class:`HkdfGuardTelemetry`'s providers on every call
    (the global ones unless overridden), so an SDK installed after import is still picked up.
    """

    def __init__(self, source_name: str, shared_flag_owner: ComponentTelemetry | None = None) -> None:
        self._source_name = source_name
        self._shared_flag_owner = shared_flag_owner
        self._sensitive_logging_enabled = False

    @property
    def source_name(self) -> str:
        """This component's instrumentation scope name, e.g. ``"HkdfGuard.Cache"``."""
        return self._source_name

    @property
    def tracer(self) -> Tracer:
        return trace.get_tracer(self._source_name, tracer_provider=HkdfGuardTelemetry.tracer_provider())

    @property
    def meter(self) -> Meter:
        return metrics.get_meter(self._source_name, meter_provider=HkdfGuardTelemetry.meter_provider())

    @property
    def sensitive_logging_enabled(self) -> bool:
        """When enabled, sensitive operations emit additional debug telemetry (lengths and
        identifiers). Raw key, plaintext, and ciphertext bytes are never logged regardless.
        Components built with a shared flag owner read and write that owner's flag."""
        if self._shared_flag_owner is not None:
            return self._shared_flag_owner.sensitive_logging_enabled
        return self._sensitive_logging_enabled

    @sensitive_logging_enabled.setter
    def sensitive_logging_enabled(self, enabled: bool) -> None:
        if self._shared_flag_owner is not None:
            self._shared_flag_owner.sensitive_logging_enabled = enabled
        else:
            self._sensitive_logging_enabled = enabled

    @contextmanager
    def start_span(self, name: str) -> Iterator[Span]:
        """Starts a span under this component's tracer and makes it current for the ``with``
        block. An exception escaping the block is recorded on the span, which is marked as
        errored, and then re-raised."""
        with self.tracer.start_as_current_span(name, record_exception=False, set_status_on_exception=False) as span:
            try:
                yield span
            except Exception as exception:
                record_exception(span, exception)
                raise

    def log_sensitive_operation(self, span: Span | None, operation_name: str, details: Mapping[str, AttributeValue] | None = None) -> None:
        """Adds a fixed-name (:attr:`EventNames.SENSITIVE_OPERATION`) event to the span when
        sensitive logging is enabled and the span is recording. Only pass non-sensitive metadata
        (lengths, identifiers) as details - never key, plaintext, or ciphertext bytes."""
        if not self.sensitive_logging_enabled or span is None or not span.is_recording():
            return

        attributes: dict[str, AttributeValue] = {AttributeNames.OPERATION_NAME: operation_name}
        if details:
            attributes.update(details)
        span.add_event(EventNames.SENSITIVE_OPERATION, attributes)


def record_exception(span: Span | None, exception: BaseException) -> None:
    """Records an exception on the span and marks it as errored. A ``None`` span is ignored."""
    if span is None:
        return
    span.record_exception(exception)
    span.set_status(Status(StatusCode.ERROR, str(exception)))


class HkdfGuardTelemetry:
    """One :class:`ComponentTelemetry` per component. Root, Cache, DataProtection and
    EncryptedConfiguration share one sensitive-logging flag; CryptoProviderAesGcm256 and KeyWrapping
    each keep their own.

    Telemetry goes to OpenTelemetry's global providers unless :meth:`set_tracer_provider` /
    :meth:`set_meter_provider` name others. The global providers are proxies, so an application may
    install its SDK before or after HkdfGuard is first used.
    """

    ROOT: ClassVar[ComponentTelemetry] = ComponentTelemetry("HkdfGuard")
    CACHE: ClassVar[ComponentTelemetry] = ComponentTelemetry("HkdfGuard.Cache", ROOT)
    DATA_PROTECTION: ClassVar[ComponentTelemetry] = ComponentTelemetry("HkdfGuard.DataEncryptionKey", ROOT)
    ENCRYPTED_CONFIGURATION: ClassVar[ComponentTelemetry] = ComponentTelemetry("HkdfGuard.EncryptedConfiguration", ROOT)
    CRYPTO_PROVIDER_AES_GCM256: ClassVar[ComponentTelemetry] = ComponentTelemetry("HkdfGuard.CryptoProvider.AesGcm256")
    KEY_WRAPPING: ClassVar[ComponentTelemetry] = ComponentTelemetry("HkdfGuard.KeyWrapping.V1")

    _tracer_provider: ClassVar[TracerProvider | None] = None
    _meter_provider: ClassVar[MeterProvider | None] = None

    @classmethod
    def tracer_provider(cls) -> TracerProvider | None:
        """The tracer provider set with :meth:`set_tracer_provider`, or ``None`` for the global one."""
        return cls._tracer_provider

    @classmethod
    def set_tracer_provider(cls, provider: TracerProvider | None) -> None:
        """Sends every component's spans to ``provider``; ``None`` reverts to the global provider."""
        cls._tracer_provider = provider

    @classmethod
    def meter_provider(cls) -> MeterProvider | None:
        """The meter provider set with :meth:`set_meter_provider`, or ``None`` for the global one."""
        return cls._meter_provider

    @classmethod
    def set_meter_provider(cls, provider: MeterProvider | None) -> None:
        """Sends every component's metrics to ``provider``; ``None`` reverts to the global provider."""
        cls._meter_provider = provider
        CacheMetrics._forget()


class CacheMetrics:
    """Cache component instruments, on :attr:`HkdfGuardTelemetry.CACHE`'s meter. ``operations``
    counts every ProtectedCache add/add_or_update and every fetch a populating cache (a
    RemoteSecretCache, such as the AWS Secrets Manager, Azure Key Vault, Google Secret Manager and
    HashiCorp Vault secret caches) makes on a miss, tagged with :attr:`AttributeNames.OPERATION_NAME`
    (which :class:`SpanNames.Cache` constant ran) and :attr:`AttributeNames.RESULT` (``"success"`` or
    ``"error"``, or ``"not_found"`` for a fetch whose source has no such value)."""

    OPERATIONS_UNIT: Final = "{operation}"
    OPERATIONS_DESCRIPTION: Final = "Number of ProtectedCache operations, tagged by operation and result."

    _lock: ClassVar = threading.Lock()
    _operations: ClassVar[Counter | None] = None

    @classmethod
    def operations(cls) -> Counter:
        """The :attr:`MetricNames.Cache.OPERATIONS` counter."""
        with cls._lock:
            if cls._operations is None:
                cls._operations = HkdfGuardTelemetry.CACHE.meter.create_counter(
                    MetricNames.Cache.OPERATIONS, unit=cls.OPERATIONS_UNIT, description=cls.OPERATIONS_DESCRIPTION)
            return cls._operations

    @classmethod
    def _forget(cls) -> None:
        with cls._lock:
            cls._operations = None
