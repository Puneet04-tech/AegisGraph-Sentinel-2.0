"""Advanced Forensics & Investigation Store"""
from __future__ import annotations
from threading import Lock
from typing import Any, Dict, Optional
from .models import Investigation, Evidence, ForensicReport, ChainOfCustody


class ForensicsStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._investigations: Dict[str, Investigation] = {}
        self._evidence: Dict[str, Evidence] = {}
        self._reports: Dict[str, ForensicReport] = {}
        self._custody: Dict[str, ChainOfCustody] = {}

    def store_investigation(self, inv: Investigation) -> Investigation:
        with self._lock:
            self._investigations[inv.investigation_id] = inv
        return inv

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        return self._investigations.get(investigation_id)

    def store_evidence(self, ev: Evidence) -> Evidence:
        with self._lock:
            self._evidence[ev.evidence_id] = ev
        return ev

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        return self._evidence.get(evidence_id)

    def store_report(self, r: ForensicReport) -> ForensicReport:
        with self._lock:
            self._reports[r.report_id] = r
        return r

    def get_report(self, report_id: str) -> Optional[ForensicReport]:
        return self._reports.get(report_id)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_investigations": len(self._investigations),
            "open_cases": sum(1 for i in self._investigations.values() if i.status == "OPEN"),
            "evidence_items": len(self._evidence),
        }


_store: Optional[ForensicsStore] = None


def get_forensics_store() -> ForensicsStore:
    global _store
    if _store is None:
        _store = ForensicsStore()
    return _store
