"""Tests for Performance Optimization"""
import pytest
from src.performance.models import PerformanceMetrics, OptimizationRule
from src.performance.store import get_performance_store
from src.performance.service import PerformanceService


class TestPerformanceModels:
    def test_create_metrics(self):
        m = PerformanceMetrics(component="api", latency_ms=50.0, throughput=1000.0)
        assert m.component == "api"

    def test_create_rule(self):
        r = OptimizationRule(name="Reduce Latency", condition={"latency_ms": 100}, action={"cache": True})
        assert r.name == "Reduce Latency"


class TestPerformanceStore:
    def setup_method(self):
        self.store = get_performance_store()

    def test_store_metrics(self):
        m = PerformanceMetrics(component="test", latency_ms=10.0, throughput=500.0)
        self.store.store_metrics(m)
        assert self.store.get_metrics(m.metrics_id) is not None


class TestPerformanceService:
    def setup_method(self):
        self.service = PerformanceService()

    def test_record_metrics(self):
        m = self.service.record_metrics("api", 50.0, 1000.0)
        assert m.metrics_id is not None

    def test_create_rule(self):
        r = self.service.create_rule("Test Rule", {"latency": 100}, {"cache": True})
        assert r.rule_id is not None

    def test_get_summary(self):
        self.service.record_metrics("api", 50.0, 1000.0)
        s = self.service.get_summary()
        assert s["total_metrics"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
