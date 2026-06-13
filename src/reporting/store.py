"""Enterprise Reporting Store"""
from __future__ import annotations
from threading import Lock
from typing import Any, Dict, Optional
from .models import Report, ReportTemplate, ReportSchedule


class ReportingStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._reports: Dict[str, Report] = {}
        self._templates: Dict[str, ReportTemplate] = {}
        self._schedules: Dict[str, ReportSchedule] = {}

    def store_report(self, r: Report) -> Report:
        with self._lock:
            self._reports[r.report_id] = r
        return r

    def get_report(self, report_id: str) -> Optional[Report]:
        return self._reports.get(report_id)

    def store_template(self, t: ReportTemplate) -> ReportTemplate:
        with self._lock:
            self._templates[t.template_id] = t
        return t

    def get_template(self, template_id: str) -> Optional[ReportTemplate]:
        return self._templates.get(template_id)

    def store_schedule(self, s: ReportSchedule) -> ReportSchedule:
        with self._lock:
            self._schedules[s.schedule_id] = s
        return s

    def get_schedule(self, schedule_id: str) -> Optional[ReportSchedule]:
        return self._schedules.get(schedule_id)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_reports": len(self._reports),
            "templates": len(self._templates),
            "scheduled_reports": sum(1 for s in self._schedules.values() if s.enabled),
        }


_store: Optional[ReportingStore] = None


def get_reporting_store() -> ReportingStore:
    global _store
    if _store is None:
        _store = ReportingStore()
    return _store
