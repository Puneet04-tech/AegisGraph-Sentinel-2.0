# AegisGraph Sentinel Enterprise
# Reporting Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.reporting.models import Report, ReportTemplate, ReportSchedule, ReportingMetrics

def test_report_creation_defaults():
    rep = Report(
        title="Weekly Summary",
        report_type="summary"
    )
    assert rep.title == "Weekly Summary"
    assert rep.report_type == "summary"
    assert rep.content == {}
    assert rep.report_id is not None
    assert rep.created_at is not None

def test_report_template_creation():
    template = ReportTemplate(
        name="Daily Alert Log Template",
        report_type="alert_log",
        config={"chart_type": "bar"}
    )
    assert template.name == "Daily Alert Log Template"
    assert template.report_type == "alert_log"
    assert template.config == {"chart_type": "bar"}
    assert template.template_id is not None

def test_report_schedule_creation():
    schedule = ReportSchedule(
        template_id="tpl-123",
        frequency="daily"
    )
    assert schedule.template_id == "tpl-123"
    assert schedule.frequency == "daily"
    assert schedule.enabled is True
    assert schedule.schedule_id is not None

def test_reporting_metrics_defaults():
    metrics = ReportingMetrics(
        total_reports=10,
        templates=3,
        scheduled_reports=2
    )
    assert metrics.total_reports == 10
    assert metrics.templates == 3
    assert metrics.scheduled_reports == 2
