"""Tests for Executive Command Dashboard"""
import pytest
from src.dashboard.models import Dashboard, Widget
from src.dashboard.store import get_dashboard_store
from src.dashboard.service import DashboardService


class TestDashboardModels:
    def test_create_dashboard(self):
        d = Dashboard(name="Security Ops", description="Security operations dashboard")
        assert d.name == "Security Ops"

    def test_create_widget(self):
        w = Widget(widget_type="chart", title="Threats")
        assert w.widget_type == "chart"


class TestDashboardStore:
    def setup_method(self):
        self.store = get_dashboard_store()

    def test_store_dashboard(self):
        d = Dashboard(name="Test", description="Test")
        self.store.store_dashboard(d)
        assert self.store.get_dashboard(d.dashboard_id) is not None


class TestDashboardService:
    def setup_method(self):
        self.service = DashboardService()

    def test_create_dashboard(self):
        d = self.service.create_dashboard("Test Dashboard", "Test description")
        assert d.dashboard_id is not None

    def test_add_widget(self):
        d = self.service.create_dashboard("Test", "Test")
        w = self.service.add_widget(d.dashboard_id, "chart", "Threats", {"type": "line"})
        assert w is not None

    def test_get_metrics(self):
        self.service.create_dashboard("Test", "Test")
        m = self.service.get_metrics()
        assert m.total_dashboards >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
