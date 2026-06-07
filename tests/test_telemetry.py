import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from src.observability.telemetry import trace_operation, error_count, request_count

@pytest.fixture
def memory_exporter():
    """Setup in-memory OpenTelemetry exporter for testing."""
    # Ensure telemetry is initialized
    from src.observability.telemetry import init_telemetry
    init_telemetry()
    
    provider = trace.get_tracer_provider()
    exporter = InMemorySpanExporter()
    processor = SimpleSpanProcessor(exporter)
    
    if hasattr(provider, "add_span_processor"):
        provider.add_span_processor(processor)
        
    yield exporter
    
    # Clear spans after test
    exporter.clear()


def test_trace_operation_sync(memory_exporter):
    @trace_operation("test_sync_op")
    def my_sync_func(x):
        return x * 2

    assert my_sync_func(5) == 10
    
    spans = memory_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "test_sync_op"


@pytest.mark.asyncio
async def test_trace_operation_async(memory_exporter):
    @trace_operation("test_async_op")
    async def my_async_func(x):
        return x * 2

    assert await my_async_func(5) == 10
    
    spans = memory_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "test_async_op"


def test_trace_operation_exception(memory_exporter):
    @trace_operation("test_error_op")
    def failing_func():
        raise ValueError("Something broke")

    with pytest.raises(ValueError, match="Something broke"):
        failing_func()

    spans = memory_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "test_error_op"
    # Status should indicate error
    assert not spans[0].status.is_ok
    # Error counter should increment
    err_val = error_count.labels(type="ValueError")._value.get()
    assert err_val > 0
