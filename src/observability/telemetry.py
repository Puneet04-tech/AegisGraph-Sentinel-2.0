"""
Telemetry and Metrics manager for AegisGraph Sentinel 2.0.

Provides OpenTelemetry Tracing and Prometheus Metrics initialization.
"""

import os
from functools import wraps
from typing import Callable, Any

from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME

from prometheus_client import Counter, Histogram, make_asgi_app

# --- Configuration ---
SERVICE = "aegisgraph-sentinel"

# --- Metrics ---
# Counters
request_count = Counter(
    "fraud_request_count",
    "Total number of fraud scoring requests",
    ["status"]
)
error_count = Counter(
    "aegis_error_count",
    "Total number of errors encountered",
    ["type"]
)

# Histograms
fraud_request_latency_seconds = Histogram(
    "fraud_request_latency_seconds",
    "Latency of overall fraud scoring request",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)
model_inference_latency_seconds = Histogram(
    "model_inference_latency_seconds",
    "Latency of HTGNN model inference",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)
graph_traversal_latency_seconds = Histogram(
    "graph_traversal_latency_seconds",
    "Latency of graph traversal and feature extraction",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)
)
neo4j_query_latency_seconds = Histogram(
    "neo4j_query_latency_seconds",
    "Latency of Neo4j Cypher queries",
    ["query_type"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)


def init_telemetry():
    """Initialise OpenTelemetry and Prometheus exporters."""
    resource = Resource(attributes={
        SERVICE_NAME: SERVICE
    })
    
    # Trace setup
    provider = TracerProvider(resource=resource)
    
    # Configure Exporter based on environment
    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if otlp_endpoint:
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
        processor = BatchSpanProcessor(exporter)
    else:
        # Fallback to console export (or in-memory for tests) if no endpoint is specified
        exporter = ConsoleSpanExporter()
        # Using a simple processor or batch processor with console is fine
        processor = BatchSpanProcessor(exporter)
        
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)


def get_tracer():
    return trace.get_tracer(SERVICE)


def trace_operation(name: str):
    """Decorator to automatically trace a function execution."""
    def decorator(func: Callable):
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    span.record_exception(e)
                    error_count.labels(type=e.__class__.__name__).inc()
                    raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    span.record_exception(e)
                    error_count.labels(type=e.__class__.__name__).inc()
                    raise

        if hasattr(func, '__code__') and func.__code__.co_flags & 0x80:  # iscoroutinefunction
            return async_wrapper
        return sync_wrapper
    return decorator


def get_metrics_app():
    """Return an ASGI app that serves Prometheus metrics."""
    return make_asgi_app()
