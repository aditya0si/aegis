"""OTel setup — no-op if OTel not configured."""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

_tracer = None

def setup_otel(service_name: str = "aegis"):
    global _tracer
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            ConsoleSpanExporter,
        )
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        # console exporter always
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        if endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                    OTLPSpanExporter,
                )
                otlp = OTLPSpanExporter(endpoint=endpoint, insecure=True)
                provider.add_span_processor(BatchSpanProcessor(otlp))
            except Exception as e:
                log.warning(f"OTLP exporter failed: {e}")
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        # instrument FastAPI if available
        try:
            pass
            # instrument later when app created
        except Exception:
            pass
        log.info("OTel initialized for %s", service_name)
        return _tracer
    except Exception as e:
        log.warning(f"OTel init failed (running without tracing): {e}")
        return None

def get_tracer(name: str = "aegis"):
    if _tracer is not None:
        return _tracer
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except Exception:
        # dummy tracer
        class DummySpan:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def set_attribute(self, *a, **kw): pass
            def record_exception(self, *a, **kw): pass
        class DummyTracer:
            def start_as_current_span(self, name, **kw):
                return DummySpan()
        return DummyTracer()
