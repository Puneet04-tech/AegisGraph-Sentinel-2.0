"""
Real-time Streaming & Event Processing Engine.

A production-grade streaming module for real-time fraud detection,
event-driven processing, and low-latency alert generation.

Modules:
    - Stream Processor: Real-time event ingestion and windowing
    - Event Bus: Pub/sub and event routing
    - Stream Analytics: Pattern detection and anomaly detection
    - Alert Generator: Low-latency alert management
"""

from .models import (
    WindowType,
    EventPriority,
    StreamEvent,
    StreamWindow,
    StreamAggregation,
    StreamPattern,
    StreamAlert,
    StreamSubscription,
    StreamMetrics,
)
from .store import StreamStore, get_stream_store
from .stream_processor import StreamProcessor, get_stream_processor
from .event_bus import EventBus, get_event_bus
from .stream_analytics import StreamAnalytics, get_stream_analytics
from .alert_generator import AlertGenerator, get_alert_generator

__all__ = [
    # Enums
    "WindowType",
    "EventPriority",
    # Models
    "StreamEvent",
    "StreamWindow",
    "StreamAggregation",
    "StreamPattern",
    "StreamAlert",
    "StreamSubscription",
    "StreamMetrics",
    # Store
    "StreamStore",
    "get_stream_store",
    # Modules
    "StreamProcessor",
    "get_stream_processor",
    "EventBus",
    "get_event_bus",
    "StreamAnalytics",
    "get_stream_analytics",
    "AlertGenerator",
    "get_alert_generator",
]