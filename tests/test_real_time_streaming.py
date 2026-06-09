"""
Tests for Real-time Streaming & Event Processing Engine.

Comprehensive tests for:
    - Stream Processor
    - Event Bus
    - Stream Analytics
    - Alert Generator
"""

import pytest
from datetime import datetime, timezone

from src.real_time_streaming import (
    WindowType,
    EventPriority,
    StreamEvent,
    StreamStore,
    get_stream_store,
    StreamProcessor,
    get_stream_processor,
    EventBus,
    get_event_bus,
    StreamAnalytics,
    get_stream_analytics,
    AlertGenerator,
    get_alert_generator,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh stream store for testing."""
    return StreamStore(max_size=100)


@pytest.fixture
def stream_processor(store):
    """Create a stream processor."""
    return StreamProcessor(store=store)


@pytest.fixture
def event_bus(store):
    """Create an event bus."""
    return EventBus(store=store)


@pytest.fixture
def stream_analytics(store):
    """Create stream analytics."""
    return StreamAnalytics(store=store)


@pytest.fixture
def alert_generator(store):
    """Create alert generator."""
    return AlertGenerator(store=store)


# =============================================================================
# Store Tests
# =============================================================================

class TestStreamStore:
    """Tests for StreamStore."""
    
    def test_add_event(self, store):
        """Test adding event to stream."""
        event = StreamEvent(
            event_type="test_event",
            source="test_source",
            payload={"value": 100},
        )
        
        stored = store.add_event("test_stream", event)
        
        assert stored.event_id is not None
    
    def test_get_stream_events(self, store):
        """Test getting events from stream."""
        for i in range(5):
            event = StreamEvent(
                event_type=f"event_{i}",
                source="test",
                payload={"index": i},
            )
            store.add_event("test_stream", event)
        
        events = store.get_stream_events("test_stream", limit=3)
        
        assert len(events) == 3
    
    def test_get_all_streams(self, store):
        """Test getting all streams."""
        streams = store.get_all_streams()
        
        assert len(streams) >= 4  # Default streams
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "streams_count" in stats
        assert "alerts_stored" in stats


# =============================================================================
# Stream Processor Tests
# =============================================================================

class TestStreamProcessor:
    """Tests for StreamProcessor."""
    
    def test_ingest_event(self, stream_processor):
        """Test ingesting an event."""
        event = stream_processor.ingest_event(
            stream_name="test_stream",
            event_type="test_event",
            source="test_source",
            payload={"value": 100},
        )
        
        assert event.event_id is not None
        assert event.event_type == "test_event"
    
    def test_create_window(self, stream_processor):
        """Test creating a window."""
        window = stream_processor.create_window(
            name="Test Window",
            window_type=WindowType.TUMBLING,
            size_seconds=60,
        )
        
        assert window.window_id is not None
        assert window.size_seconds == 60
    
    def test_get_stream_summary(self, stream_processor):
        """Test getting stream summary."""
        stream_processor.ingest_event(
            stream_name="summary_test",
            event_type="test",
            source="test",
            payload={},
        )
        
        summary = stream_processor.get_stream_summary("summary_test")
        
        assert "stream_name" in summary
        assert summary["total_events"] >= 1


# =============================================================================
# Event Bus Tests
# =============================================================================

class TestEventBus:
    """Tests for EventBus."""
    
    def test_publish_event(self, event_bus):
        """Test publishing an event."""
        event = event_bus.publish_event(
            event_type="test_event",
            source="test_source",
            payload={"data": "test"},
        )
        
        assert event.event_id is not None
    
    def test_subscribe(self, event_bus):
        """Test subscribing to events."""
        subscription = event_bus.subscribe(
            stream_name="test_stream",
            subscriber_id="subscriber_1",
            filter_criteria={"event_type": "test"},
        )
        
        assert subscription.subscription_id is not None
    
    def test_get_event_history(self, event_bus):
        """Test getting event history."""
        event_bus.publish_event(
            event_type="history_test",
            source="test",
            payload={},
        )
        
        history = event_bus.get_event_history(limit=10)
        
        assert isinstance(history, list)
    
    def test_correlate_events(self, event_bus):
        """Test correlating events."""
        event1 = event_bus.publish_event(
            event_type="event_1",
            source="same_source",
            payload={},
        )
        event2 = event_bus.publish_event(
            event_type="event_2",
            source="same_source",
            payload={},
        )
        
        correlation = event_bus.correlate_events([event1.event_id, event2.event_id])
        
        assert correlation["event_count"] == 2
        assert correlation["relationship"] == "same_source"


# =============================================================================
# Stream Analytics Tests
# =============================================================================

class TestStreamAnalytics:
    """Tests for StreamAnalytics."""
    
    def test_detect_pattern(self, stream_analytics):
        """Test defining a pattern."""
        pattern = stream_analytics.detect_pattern(
            name="High Frequency",
            pattern_type="frequency",
            definition={},
            window_seconds=60,
            threshold=10,
        )
        
        assert pattern.pattern_id is not None
    
    def test_detect_anomaly(self, stream_analytics, stream_processor):
        """Test anomaly detection."""
        # Add events with one anomaly
        for i in range(10):
            stream_processor.ingest_event(
                stream_name="anomaly_test",
                event_type="test",
                source="test",
                payload={"value": 10 + (i * 5 if i != 5 else 100)},  # Anomaly at index 5
            )
        
        result = stream_analytics.detect_anomaly(
            stream_name="anomaly_test",
            metric_name="value",
            sensitivity=2.0,
        )
        
        assert "anomaly_detected" in result
    
    def test_compute_stream_metrics(self, stream_analytics, stream_processor):
        """Test computing stream metrics."""
        for i in range(10):
            stream_processor.ingest_event(
                stream_name="metrics_test",
                event_type="test",
                source="test",
                payload={"latency_ms": 50},
            )
        
        metrics = stream_analytics.compute_stream_metrics("metrics_test")
        
        assert metrics.events_per_second >= 0
        assert metrics.queue_depth >= 0


# =============================================================================
# Alert Generator Tests
# =============================================================================

class TestAlertGenerator:
    """Tests for AlertGenerator."""
    
    def test_generate_alert(self, alert_generator):
        """Test generating an alert."""
        alert = alert_generator.generate_alert(
            alert_type="test_alert",
            title="Test Alert",
            description="This is a test alert",
            severity=EventPriority.HIGH,
        )
        
        assert alert.alert_id is not None
        assert alert.title == "Test Alert"
    
    def test_prioritize_alerts(self, alert_generator):
        """Test prioritizing alerts."""
        alert_generator.generate_alert(
            alert_type="low",
            title="Low",
            description="Low priority",
            severity=EventPriority.LOW,
        )
        alert_generator.generate_alert(
            alert_type="critical",
            title="Critical",
            description="Critical priority",
            severity=EventPriority.CRITICAL,
        )
        
        prioritized = alert_generator.prioritize_alerts()
        
        assert prioritized[0].severity == EventPriority.CRITICAL
    
    def test_deduplicate_alert(self, alert_generator):
        """Test alert deduplication."""
        alert = alert_generator.generate_alert(
            alert_type="dedup_test",
            title="Dedup Test",
            description="Test",
            severity=EventPriority.MEDIUM,
        )
        
        # First check - not duplicate
        is_dup = alert_generator.deduplicate_alert("dedup_key_1", alert)
        assert is_dup is False
        
        # Second check with same key - should be duplicate
        alert2 = alert_generator.generate_alert(
            alert_type="dedup_test",
            title="Dedup Test 2",
            description="Test",
            severity=EventPriority.MEDIUM,
        )
        is_dup2 = alert_generator.deduplicate_alert("dedup_key_1", alert2)
        assert is_dup2 is True
    
    def test_get_alert_summary(self, alert_generator):
        """Test getting alert summary."""
        summary = alert_generator.get_alert_summary()
        
        assert "total_alerts" in summary
        assert "by_severity" in summary


# =============================================================================
# Integration Tests
# =============================================================================

class TestStreamingIntegration:
    """Integration tests for streaming workflow."""
    
    def test_full_streaming_workflow(
        self,
        stream_processor,
        event_bus,
        stream_analytics,
        alert_generator,
    ):
        """Test full streaming workflow."""
        # 1. Ingest events
        for i in range(10):
            stream_processor.ingest_event(
                stream_name="integration_test",
                event_type="fraud_event",
                source="payment_system",
                payload={"amount": 100 + i * 10, "user_id": f"user_{i}"},
                priority=EventPriority.HIGH if i > 7 else EventPriority.MEDIUM,
            )
        
        # 2. Publish events
        event_bus.publish_event(
            event_type="integration_event",
            source="test",
            payload={"data": "test"},
        )
        
        # 3. Detect pattern
        pattern = stream_analytics.detect_pattern(
            name="High Amount",
            pattern_type="threshold",
            definition={"field": "amount"},
            window_seconds=60,
            threshold=150,
        )
        
        # 4. Generate alert
        alert = alert_generator.generate_alert(
            alert_type="integration_alert",
            title="Integration Test Alert",
            description="Test alert from integration workflow",
            severity=EventPriority.HIGH,
        )
        
        # Verify
        assert alert.alert_id is not None
        assert pattern.pattern_id is not None