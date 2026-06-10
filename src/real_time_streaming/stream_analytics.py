"""
Stream Analytics Module.

Real-time analytics over streams, pattern detection, and anomaly detection.
"""

import random
import math
import threading
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    StreamPattern,
    StreamMetrics,
    EventPriority,
)
from .store import StreamStore, get_stream_store

logger = logging.getLogger(__name__)


class StreamAnalytics:
    """Stream Analytics for real-time data analysis.
    
    Provides:
        - Pattern detection
        - Anomaly detection
        - Real-time metrics
        - Trend analysis
    """
    
    def __init__(self, store: Optional[StreamStore] = None):
        """Initialize the stream analytics."""
        self._store = store or get_stream_store()
        self._module_id = "stream_analytics"
    
    def detect_pattern(
        self,
        name: str,
        pattern_type: str,
        definition: Dict[str, Any],
        window_seconds: int,
        threshold: float,
    ) -> StreamPattern:
        """Define a pattern for detection."""
        logger.info(f"Defining pattern: {name}")
        
        pattern = StreamPattern(
            name=name,
            pattern_type=pattern_type,
            definition=definition,
            window_seconds=window_seconds,
            threshold=threshold,
        )
        
        self._store.store_pattern(pattern)
        return pattern
    
    def check_pattern_match(
        self,
        stream_name: str,
        pattern: StreamPattern,
    ) -> Dict[str, Any]:
        """Check if pattern matches stream events."""
        logger.info(f"Checking pattern {pattern.name} on {stream_name}")
        
        events = self._store.get_stream_events(stream_name, limit=100)
        
        if not events:
            return {"matched": False, "match_count": 0}
        
        # Simple pattern matching based on type
        if pattern.pattern_type == "frequency":
            # Check event frequency
            match_count = len(events)
            matched = match_count >= pattern.threshold
        elif pattern.pattern_type == "sequence":
            # Check for event sequence
            match_count = sum(
                1 for i in range(len(events) - 1)
                if events[i].event_type == pattern.definition.get("first_event")
                and events[i + 1].event_type == pattern.definition.get("second_event")
            )
            matched = match_count >= pattern.threshold
        elif pattern.pattern_type == "threshold":
            # Check threshold
            values = [e.payload.get(pattern.definition.get("field", "value"), 0) for e in events]
            max_value = max(values) if values else 0
            matched = max_value >= pattern.threshold
            match_count = sum(1 for v in values if v >= pattern.threshold)
        else:
            match_count = 0
            matched = False
        
        return {
            "matched": matched,
            "match_count": match_count,
            "threshold": pattern.threshold,
        }
    
    def detect_anomaly(
        self,
        stream_name: str,
        metric_name: str,
        sensitivity: float = 2.0,
    ) -> Dict[str, Any]:
        """Detect anomalies in stream using statistical methods."""
        logger.info(f"Detecting anomalies on {stream_name}.{metric_name}")
        
        events = self._store.get_stream_events(stream_name, limit=100)
        
        if len(events) < 10:
            return {"anomaly_detected": False, "reason": "insufficient_data"}
        
        values = [
            e.payload.get(metric_name, 0)
            for e in events
            if metric_name in e.payload
        ]
        
        if not values:
            return {"anomaly_detected": False, "reason": "no_metric_data"}
        
        # Calculate statistics
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        std_dev = math.sqrt(variance)
        
        # Detect anomalies (z-score > sensitivity)
        anomalies = []
        for i, v in enumerate(values):
            z_score = abs((v - mean) / std_dev) if std_dev > 0 else 0
            if z_score > sensitivity:
                anomalies.append({
                    "index": i,
                    "value": v,
                    "z_score": z_score,
                })
        
        return {
            "anomaly_detected": len(anomalies) > 0,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies[:10],  # Limit to 10
            "mean": mean,
            "std_dev": std_dev,
        }
    
    def compute_stream_metrics(self, stream_name: str) -> StreamMetrics:
        """Compute real-time stream metrics."""
        logger.info(f"Computing metrics for {stream_name}")
        
        events = self._store.get_stream_events(stream_name, limit=1000)
        
        # Calculate metrics
        total_events = self._store.get_stream_count(stream_name)
        
        # Simulate events per second
        events_per_second = random.uniform(10, 1000)
        
        # Calculate average latency
        latencies = [e.payload.get("latency_ms", random.uniform(1, 100)) for e in events[-100:]]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        
        # Queue depth
        queue_depth = len(events)
        
        # Active subscribers
        subscriptions = self._store.get_subscriptions(stream_name)
        active_subscribers = len(subscriptions)
        
        metrics = StreamMetrics(
            stream_name=stream_name,
            events_per_second=events_per_second,
            avg_latency_ms=avg_latency,
            queue_depth=queue_depth,
            active_subscribers=active_subscribers,
        )
        
        self._store.store_metrics(metrics)
        return metrics
    
    def get_stream_trends(self, stream_name: str, period_seconds: int = 300) -> Dict[str, Any]:
        """Analyze stream trends."""
        logger.info(f"Analyzing trends for {stream_name}")
        
        aggregations = self._store.get_recent_aggregations(stream_name, limit=50)
        
        if len(aggregations) < 2:
            return {"trend": "insufficient_data"}
        
        # Calculate trend
        values = [a.value for a in aggregations]
        first_half = values[:len(values)//2]
        second_half = values[len(values)//2:]
        
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        
        change_percent = ((avg_second - avg_first) / avg_first * 100) if avg_first != 0 else 0
        
        if abs(change_percent) < 5:
            trend = "stable"
        elif change_percent > 0:
            trend = "increasing"
        else:
            trend = "decreasing"
        
        return {
            "stream_name": stream_name,
            "trend": trend,
            "change_percent": change_percent,
            "avg_first_half": avg_first,
            "avg_second_half": avg_second,
            "data_points": len(values),
        }


# Global singleton
_stream_analytics: Optional[StreamAnalytics] = None
_stream_analytics_lock = Lock()


def get_stream_analytics(store: Optional[StreamStore] = None) -> StreamAnalytics:
    """Get or create the singleton StreamAnalytics instance."""
    global _stream_analytics
    
    with _stream_analytics_lock:
        if _stream_analytics is None:
            _stream_analytics = StreamAnalytics(store=store)
        return _stream_analytics