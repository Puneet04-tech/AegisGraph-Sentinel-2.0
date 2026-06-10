"""
Performance Metrics Module.

Performance tracking and monitoring.
"""

import random
import threading
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import PerformanceMetric
from .store import ObservabilityStore, get_observability_store

logger = logging.getLogger(__name__)


class PerformanceTracker:
    """Performance Tracker for metrics monitoring.
    
    Provides:
        - Request latency tracking
        - Throughput monitoring
        - Resource utilization
        - Query performance
    """
    
    def __init__(self, store: Optional[ObservabilityStore] = None):
        """Initialize the performance tracker."""
        self._store = store or get_observability_store()
        self._module_id = "performance_metrics"
    
    def record_metric(
        self,
        metric_name: str,
        component: str,
        value: float,
        unit: str = "count",
        tags: Dict[str, str] = None,
    ) -> PerformanceMetric:
        """Record a performance metric."""
        logger.info(f"Recording metric: {metric_name} = {value}")
        
        metric = PerformanceMetric(
            metric_name=metric_name,
            component=component,
            value=value,
            unit=unit,
            tags=tags or {},
        )
        
        self._store.store_metric(metric)
        return metric
    
    def get_metrics(
        self,
        component: str = None,
        metric_name: str = None,
        limit: int = 100,
    ) -> List[PerformanceMetric]:
        """Get metrics with filters."""
        return self._store.get_metrics(component, metric_name, limit)
    
    def get_latency_stats(self, component: str) -> Dict[str, Any]:
        """Get latency statistics for component."""
        metrics = self._store.get_metrics(component=component, metric_name="latency_ms", limit=1000)
        
        if not metrics:
            return {"error": "No metrics found"}
        
        values = [m.value for m in metrics]
        values.sort()
        
        return {
            "component": component,
            "count": len(values),
            "min": min(values) if values else 0,
            "max": max(values) if values else 0,
            "avg": sum(values) / len(values) if values else 0,
            "p50": values[len(values) // 2] if values else 0,
            "p95": values[int(len(values) * 0.95)] if values else 0,
            "p99": values[int(len(values) * 0.99)] if values else 0,
        }
    
    def get_throughput_stats(self, component: str) -> Dict[str, Any]:
        """Get throughput statistics."""
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        
        metrics = self._store.get_metrics(component=component, metric_name="requests", limit=1000)
        recent_metrics = [m for m in metrics if m.timestamp > hour_ago]
        
        if not recent_metrics:
            return {
                "component": component,
                "requests_last_hour": 0,
                "avg_per_second": 0,
            }
        
        total_requests = sum(m.value for m in recent_metrics)
        
        return {
            "component": component,
            "requests_last_hour": int(total_requests),
            "avg_per_second": total_requests / 3600,
        }
    
    def get_error_rate(self, component: str) -> Dict[str, Any]:
        """Get error rate for component."""
        metrics = self._store.get_metrics(component=component, limit=1000)
        
        total_requests = sum(1 for m in metrics if m.metric_name == "requests")
        errors = sum(m.value for m in metrics if m.metric_name == "errors")
        
        error_rate = (errors / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "component": component,
            "total_requests": total_requests,
            "errors": errors,
            "error_rate_percent": error_rate,
        }
    
    def record_request_latency(
        self,
        component: str,
        endpoint: str,
        latency_ms: float,
    ) -> PerformanceMetric:
        """Record request latency."""
        return self.record_metric(
            metric_name="latency_ms",
            component=component,
            value=latency_ms,
            unit="ms",
            tags={"endpoint": endpoint},
        )
    
    def record_throughput(
        self,
        component: str,
        count: int,
    ) -> PerformanceMetric:
        """Record throughput."""
        return self.record_metric(
            metric_name="requests",
            component=component,
            value=count,
            unit="count",
        )
    
    def record_errors(
        self,
        component: str,
        count: int,
    ) -> PerformanceMetric:
        """Record error count."""
        return self.record_metric(
            metric_name="errors",
            component=component,
            value=count,
            unit="count",
        )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get overall performance summary."""
        components = ["api", "database", "cache", "queue", "worker"]
        
        summary = {
            "overall_health": 95.0,  # Placeholder
            "components": {},
        }
        
        for component in components:
            latency = self.get_latency_stats(component)
            throughput = self.get_throughput_stats(component)
            
            summary["components"][component] = {
                "latency_p50": latency.get("p50", 0),
                "latency_p95": latency.get("p95", 0),
                "requests_per_second": throughput.get("avg_per_second", 0),
            }
        
        return summary


# Global singleton
_performance_tracker: Optional[PerformanceTracker] = None
_performance_tracker_lock = Lock()


def get_performance_tracker(store: Optional[ObservabilityStore] = None) -> PerformanceTracker:
    """Get or create the singleton PerformanceTracker instance."""
    global _performance_tracker
    
    with _performance_tracker_lock:
        if _performance_tracker is None:
            _performance_tracker = PerformanceTracker(store=store)
        return _performance_tracker