"""Enterprise Reporting Service"""
from __future__ import annotations
from typing import Any, Dict, Optional
from .models import Report, ReportTemplate, ReportSchedule, ReportingMetrics
from .store import get_reporting_store, ReportingStore


class ReportingService:
    """Core reporting service."""

    def __init__(self, store: Optional[ReportingStore] = None):
        self._store = store or get_reporting_store()

    def create_report(self, title: str, report_type: str, content: Dict[str, Any]) -> Report:
        r = Report(title=title, report_type=report_type, content=content)
        return self._store.store_report(r)

    def get_report(self, report_id: str) -> Optional[Report]:
        return self._store.get_report(report_id)

    def create_template(self, name: str, report_type: str, config: Dict[str, Any]) -> ReportTemplate:
        t = ReportTemplate(name=name, report_type=report_type, config=config)
        return self._store.store_template(t)

    def get_template(self, template_id: str) -> Optional[ReportTemplate]:
        return self._store.get_template(template_id)

    def create_schedule(self, template_id: str, frequency: str) -> ReportSchedule:
        s = ReportSchedule(template_id=template_id, frequency=frequency)
        return self._store.store_schedule(s)

    def get_metrics(self) -> ReportingMetrics:
        m = self._store.get_metrics()
        return ReportingMetrics(**m)


_service: Optional[ReportingService] = None


def get_reporting_service() -> ReportingService:
    global _service
    if _service is None:
        _service = ReportingService()
    return _service
