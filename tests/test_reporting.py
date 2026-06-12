"""Tests for Reporting Module"""
import pytest
from src.reporting import ReportingService

def test_service_init():
    service = ReportingService()
    assert service is not None
    assert len(service.templates) >= 2

def test_create_report():
    service = ReportingService()
    report = service.create_report(
        name="Test Report",
        report_type="EXECUTIVE",
        description="Test description"
    )
    assert report is not None
    assert report["name"] == "Test Report"
    assert report["status"] == "DRAFT"

def test_generate_report():
    service = ReportingService()
    report = service.create_report("Generate Test", "OPERATIONAL", "Desc")
    generated = service.generate_report(report["report_id"])
    assert generated is not None
    assert generated["status"] == "GENERATED"

def test_get_templates():
    service = ReportingService()
    templates = service.get_templates()
    assert len(templates) >= 2

def test_export_report():
    service = ReportingService()
    report = service.create_report("Export Test", "COMPLIANCE", "Desc")
    exported = service.export_report(report["report_id"], "PDF")
    assert exported is not None
    assert exported["format"] == "PDF"

def test_get_dashboard():
    service = ReportingService()
    service.create_report("Dashboard Test", "AUDIT", "Desc")
    dashboard = service.get_dashboard()
    assert "total_reports" in dashboard
    assert "reports_by_type" in dashboard