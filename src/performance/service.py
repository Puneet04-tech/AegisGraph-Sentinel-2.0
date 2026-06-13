"""Performance Optimization Service"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from .models import PerformanceMetrics, OptimizationRule, Benchmark, PerformanceReport
from .store import get_performance_store, PerformanceStore


class PerformanceService:
    """Core performance service."""

    def __init__(self, store: Optional[PerformanceStore] = None):
        self._store = store or get_performance_store()

    def record_metrics(self, component: str, latency_ms: float, throughput: float) -> PerformanceMetrics:
        m = PerformanceMetrics(component=component, latency_ms=latency_ms, throughput=throughput)
        return self._store.store_metrics(m)

    def create_rule(self, name: str, condition: Dict[str, Any], action: Dict[str, Any]) -> OptimizationRule:
        r = OptimizationRule(name=name, condition=condition, action=action)
        return self._store.store_rule(r)

    def run_benchmark(self, name: str, config: Dict[str, Any]) -> Benchmark:
        b = Benchmark(name=name, score=95.0, config=config)
        return self._store.store_benchmark(b)

    def generate_report(self, title: str, recommendations: List[str]) -> PerformanceReport:
        r = PerformanceReport(title=title, recommendations=recommendations)
        return r

    def get_summary(self) -> Dict[str, Any]:
        return self._store.get_summary()


_service: Optional[PerformanceService] = None


def get_performance_service() -> PerformanceService:
    global _service
    if _service is None:
        _service = PerformanceService()
    return _service
