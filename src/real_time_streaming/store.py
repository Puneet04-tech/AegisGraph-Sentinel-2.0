"""
Real-time Streaming Storage Engine.

Thread-safe storage for streams, events, windows, and alerts.
"""

from collections import deque
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    StreamEvent,
    StreamWindow,
    StreamAggregation,
    StreamPattern,
    StreamAlert,
    StreamSubscription,
    StreamMetrics,
)

logger = logging.getLogger(__name__)


class StreamStore:
    """Thread-safe storage for streaming data.
    
    Provides:
        - O(1) lookup by ID
        - Bounded event buffers
        - Thread-safe operations
        - Stream management
    """
    
    def __init__(self, max_size: int = 10000):
        """Initialize the stream store."""
        self._max_size = max_size
        self._lock = Lock()
        
        # Streams
        self._streams: Dict[str, deque] = {}
        
        # Windows
        self._windows: Dict[str, StreamWindow] = {}
        
        # Aggregations
        self._aggregations: Dict[str, StreamAggregation] = {}
        
        # Patterns
        self._patterns: Dict[str, StreamPattern] = {}
        
        # Alerts
        self._alerts: Dict[str, StreamAlert] = {}
        
        # Subscriptions
        self._subscriptions: Dict[str, StreamSubscription] = {}
        
        # Metrics
        self._metrics: Dict[str, StreamMetrics] = {}
        
        # Event counts
        self._event_counts: Dict[str, int] = {}
        
        # Initialize default streams
        self._initialize_defaults()
    
    def _initialize_defaults(self):
        """Initialize default streams and windows."""
        default_streams = ["fraud_events", "alerts", "transactions", "audit_log"]
        for stream_name in default_streams:
            self._streams[stream_name] = deque(maxlen=self._max_size)
            self._event_counts[stream_name] = 0
    
    # Stream Methods
    def add_event(self, stream_name: str, event: StreamEvent) -> StreamEvent:
        """Add event to stream."""
        with self._lock:
            if stream_name not in self._streams:
                self._streams[stream_name] = deque(maxlen=self._max_size)
                self._event_counts[stream_name] = 0
            
            self._streams[stream_name].append(event)
            self._event_counts[stream_name] += 1
        
        return event
    
    def get_stream_events(
        self,
        stream_name: str,
        limit: int = 100,
    ) -> List[StreamEvent]:
        """Get events from stream."""
        if stream_name not in self._streams:
            return []
        
        events = list(self._streams[stream_name])[-limit:]
        return events
    
    def get_all_streams(self) -> List[str]:
        """Get all stream names."""
        return list(self._streams.keys())
    
    def get_stream_count(self, stream_name: str) -> int:
        """Get event count for stream."""
        return self._event_counts.get(stream_name, 0)
    
    # Window Methods
    def store_window(self, window: StreamWindow) -> StreamWindow:
        """Store window configuration."""
        with self._lock:
            self._windows[window.window_id] = window
        return window
    
    def get_window(self, window_id: str) -> Optional[StreamWindow]:
        """Get window by ID."""
        return self._windows.get(window_id)
    
    def get_all_windows(self) -> List[StreamWindow]:
        """Get all windows."""
        return list(self._windows.values())
    
    # Aggregation Methods
    def store_aggregation(self, aggregation: StreamAggregation) -> StreamAggregation:
        """Store aggregation result."""
        with self._lock:
            self._aggregations[aggregation.aggregation_id] = aggregation
        return aggregation
    
    def get_aggregation(self, aggregation_id: str) -> Optional[StreamAggregation]:
        """Get aggregation by ID."""
        return self._aggregations.get(aggregation_id)
    
    def get_recent_aggregations(self, stream_name: str, limit: int = 100) -> List[StreamAggregation]:
        """Get recent aggregations for stream."""
        aggregations = [
            a for a in self._aggregations.values()
            if a.stream_name == stream_name
        ]
        return sorted(aggregations, key=lambda a: a.computed_at, reverse=True)[:limit]
    
    # Pattern Methods
    def store_pattern(self, pattern: StreamPattern) -> StreamPattern:
        """Store pattern."""
        with self._lock:
            self._patterns[pattern.pattern_id] = pattern
        return pattern
    
    def get_pattern(self, pattern_id: str) -> Optional[StreamPattern]:
        """Get pattern by ID."""
        return self._patterns.get(pattern_id)
    
    def get_all_patterns(self) -> List[StreamPattern]:
        """Get all patterns."""
        return list(self._patterns.values())
    
    # Alert Methods
    def store_alert(self, alert: StreamAlert) -> StreamAlert:
        """Store alert."""
        with self._lock:
            self._alerts[alert.alert_id] = alert
        return alert
    
    def get_alert(self, alert_id: str) -> Optional[StreamAlert]:
        """Get alert by ID."""
        return self._alerts.get(alert_id)
    
    def get_recent_alerts(self, limit: int = 100) -> List[StreamAlert]:
        """Get recent alerts."""
        alerts = list(self._alerts.values())
        return sorted(alerts, key=lambda a: a.triggered_at, reverse=True)[:limit]
    
    def get_unacknowledged_alerts(self) -> List[StreamAlert]:
        """Get unacknowledged alerts."""
        return [a for a in self._alerts.values() if not a.acknowledged]
    
    # Subscription Methods
    def store_subscription(self, subscription: StreamSubscription) -> StreamSubscription:
        """Store subscription."""
        with self._lock:
            self._subscriptions[subscription.subscription_id] = subscription
        return subscription
    
    def get_subscriptions(self, stream_name: str) -> List[StreamSubscription]:
        """Get subscriptions for stream."""
        return [
            s for s in self._subscriptions.values()
            if s.stream_name == stream_name
        ]
    
    # Metrics Methods
    def store_metrics(self, metrics: StreamMetrics) -> StreamMetrics:
        """Store metrics."""
        with self._lock:
            self._metrics[metrics.metrics_id] = metrics
        return metrics
    
    def get_latest_metrics(self, stream_name: str) -> Optional[StreamMetrics]:
        """Get latest metrics for stream."""
        stream_metrics = [
            m for m in self._metrics.values()
            if m.stream_name == stream_name
        ]
        if not stream_metrics:
            return None
        return max(stream_metrics, key=lambda m: m.computed_at)
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "streams_count": len(self._streams),
            "total_events_ingested": sum(self._event_counts.values()),
            "windows_stored": len(self._windows),
            "aggregations_stored": len(self._aggregations),
            "patterns_stored": len(self._patterns),
            "alerts_stored": len(self._alerts),
            "unacknowledged_alerts": len(self.get_unacknowledged_alerts()),
            "subscriptions_stored": len(self._subscriptions),
            "metrics_stored": len(self._metrics),
        }


# Global singleton
_stream_store: Optional[StreamStore] = None


def get_stream_store() -> StreamStore:
    """Get or create the singleton stream store instance."""
    global _stream_store
    
    if _stream_store is None:
        _stream_store = StreamStore()
    return _stream_store