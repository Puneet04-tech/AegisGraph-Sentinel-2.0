"""Performance Optimization Store"""
from __future__ import annotations
from threading import Lock
from typing import Any, Dict, Optional
from .models import PerformanceMetrics, OptimizationRule, Benchmark, PerformanceReport


class PerformanceStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._metrics: Dict[str, PerformanceMetrics] = {}
        self._rules: Dict[str, OptimizationRule] = {}
        self._benchmarks: Dict[str, Benchmark] = {}
        self._reports: Dict[str, PerformanceReport] = {}

    def store_metrics(self, m: PerformanceMetrics) -> PerformanceMetrics:
        with self._lock:
            self._metrics[m.metrics_id] = m
        return m

    def get_metrics(self, metrics_id: str) -> Optional[PerformanceMetrics]:
        return self._metrics.get(metrics_id)

    def store_rule(self, r: OptimizationRule) -> OptimizationRule:
        with self._lock:
            self._rules[r.rule_id] = r
        return r

    def get_rule(self, rule_id: str) -> Optional[OptimizationRule]:
        return self._rules.get(rule_id)

    def store_benchmark(self, b: Benchmark) -> Benchmark:
        with self._lock:
            self._benchmarks[b.benchmark_id] = b
        return b

    def get_benchmark(self, benchmark_id: str) -> Optional[Benchmark]:
        return self._benchmarks.get(benchmark_id)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_metrics": len(self._metrics),
            "active_rules": sum(1 for r in self._rules.values() if r.enabled),
            "benchmarks": len(self._benchmarks),
        }


_store: Optional[PerformanceStore] = None


def get_performance_store() -> PerformanceStore:
    global _store
    if _store is None:
        _store = PerformanceStore()
    return _store
