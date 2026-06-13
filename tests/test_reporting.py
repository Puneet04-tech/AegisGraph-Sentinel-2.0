"""Tests for Enterprise Reporting"""
import pytest
from src.reporting.models import Report, ReportTemplate
from src.reporting.store import get_reporting_store
from src.reporting.service import ReportingService


class TestReportingModels:
    def test_create_report(self):
        r = Report(title="Weekly Summary", report_type="summary")
        assert r.title == "Weekly Summary"

    def test_create_template(self):
        t = ReportTemplate(name="Standard", report_type="weekly")
        assert t.name == "Standard"


class TestReportingStore:
    def setup_method(self):
        self.store = get_reporting_store()

    def test_store_report(self):
        r = Report(title="Test", report_type="daily")
        self.store.store_report(r)
        assert self.store.get_report(r.report_id) is not None


class TestReportingService:
    def setup_method(self):
        self.service = ReportingService()

    def test_create_report(self):
        r = self.service.create_report("Test Report", "daily", {"data": "test"})
        assert r.report_id is not None

    def test_create_template(self):
        t = self.service.create_template("Weekly", "weekly", {"sections": []})
        assert t.template_id is not None

    def test_get_metrics(self):
        self.service.create_report("Test", "daily", {})
        m = self.service.get_metrics()
        assert m.total_reports >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
