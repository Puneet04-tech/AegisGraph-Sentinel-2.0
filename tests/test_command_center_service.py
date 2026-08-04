"""Unit tests for the command center service.

Covers ``src.command_center.service.CommandCenterService``: metric
recording, threat tracking, dashboard configuration, and the aggregate
command-center dashboard with threat-level escalation.
"""

from __future__ import annotations

import pytest

from src.command_center.models import MetricType
from src.command_center.service import (
    CommandCenterService,
    get_command_center_service,
)


@pytest.fixture
def service() -> CommandCenterService:
    return CommandCenterService()


def _seed_threats(service: CommandCenterService, count: int) -> None:
    for i in range(count):
        service.add_threat(f"Threat {i}", "HIGH", "src", "desc")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


class TestMetrics:
    def test_default_metrics_initialized(self, service):
        assert len(service.metrics) == 2
        assert service.metrics["metric-001"].name == "Active Threats"
        assert service.metrics["metric-002"].name == "Fraud Alerts"

    def test_record_metric_parses_type_and_returns_dict(self, service):
        result = service.record_metric("OPERATIONAL", "CPU Load", 42.5, "%")

        assert result["metric_type"] == "OPERATIONAL"
        assert result["name"] == "CPU Load"
        assert result["value"] == 42.5
        assert result["unit"] == "%"

    def test_get_metrics_filters_by_type(self, service):
        service.record_metric("COMPLIANCE", "Findings", 3, "count")

        fraud_metrics = service.get_metrics(metric_type="FRAUD")
        compliance_metrics = service.get_metrics(metric_type="COMPLIANCE")

        assert len(fraud_metrics) == 1
        assert len(compliance_metrics) == 1
        assert compliance_metrics[0]["name"] == "Findings"

    def test_get_metrics_without_filter_returns_all(self, service):
        service.record_metric("COMPLIANCE", "Findings", 3, "count")
        assert len(service.get_metrics()) == 3


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------


class TestThreats:
    def test_add_threat_returns_serialized_event(self, service):
        result = service.add_threat("Ransomware", "CRITICAL", "edr", "desc")

        assert result["title"] == "Ransomware"
        assert result["severity"] == "CRITICAL"
        assert result["source"] == "edr"

    def test_get_active_threats_returns_all(self, service):
        _seed_threats(service, 3)

        threats = service.get_active_threats()
        assert len(threats) == 3
        assert all("event_id" in t for t in threats)


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------


class TestDashboards:
    def test_create_dashboard_default_refresh(self, service):
        config = service.create_dashboard("SOC Main", [{"type": "chart"}])

        assert config["name"] == "SOC Main"
        assert config["widgets"] == [{"type": "chart"}]
        assert config["refresh_interval"] == 60

    def test_create_dashboard_custom_refresh(self, service):
        config = service.create_dashboard("SOC Main", [], refresh_interval=15)
        assert config["refresh_interval"] == 15

    def test_get_dashboard_unknown_returns_none(self, service):
        assert service.get_dashboard("missing") is None

    def test_get_dashboard_round_trip(self, service):
        config = service.create_dashboard("SOC Main", [])
        fetched = service.get_dashboard(config["config_id"])

        assert fetched["config_id"] == config["config_id"]
        assert fetched["name"] == "SOC Main"


# ---------------------------------------------------------------------------
# Command center dashboard
# ---------------------------------------------------------------------------


class TestCommandCenterDashboard:
    def test_threat_level_green_when_no_threats(self, service):
        dashboard = service.get_command_center_dashboard()

        assert dashboard["threat_level"] == "GREEN"
        assert dashboard["active_threats"] == 0

    def test_threat_level_yellow_with_few_threats(self, service):
        _seed_threats(service, 3)

        dashboard = service.get_command_center_dashboard()
        assert dashboard["threat_level"] == "YELLOW"

    def test_threat_level_orange_boundary(self, service):
        _seed_threats(service, 6)

        dashboard = service.get_command_center_dashboard()
        assert dashboard["threat_level"] == "ORANGE"

    def test_threat_level_red_boundary(self, service):
        _seed_threats(service, 11)

        dashboard = service.get_command_center_dashboard()
        assert dashboard["threat_level"] == "RED"

    def test_dashboard_metric_type_breakdown(self, service):
        service.record_metric("OPERATIONAL", "CPU", 10.0, "%")

        dashboard = service.get_command_center_dashboard()

        assert dashboard["total_metrics"] == 3
        assert dashboard["metrics_by_type"]["SECURITY"] == 1
        assert dashboard["metrics_by_type"]["FRAUD"] == 1
        assert dashboard["metrics_by_type"]["OPERATIONAL"] == 1

    def test_dashboard_counters(self, service):
        _seed_threats(service, 2)
        service.create_dashboard("SOC Main", [])

        dashboard = service.get_command_center_dashboard()

        assert dashboard["active_threats"] == 2
        assert dashboard["dashboards_configured"] == 1
        assert "timestamp" in dashboard


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_command_center_service_singleton(self):
        first = get_command_center_service()
        second = get_command_center_service()

        assert first is second
        assert isinstance(first, CommandCenterService)
