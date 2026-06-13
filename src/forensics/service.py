"""Advanced Forensics & Investigation Service"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from .models import Investigation, Evidence, ForensicReport, ChainOfCustody, ForensicsMetrics
from .store import get_forensics_store, ForensicsStore


class ForensicsService:
    """Core forensics service."""

    def __init__(self, store: Optional[ForensicsStore] = None):
        self._store = store or get_forensics_store()

    def create_investigation(self, title: str, description: str) -> Investigation:
        inv = Investigation(title=title, description=description)
        return self._store.store_investigation(inv)

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        return self._store.get_investigation(investigation_id)

    def add_evidence(self, investigation_id: str, evidence_type: str, content: Dict[str, Any]) -> Evidence:
        ev = Evidence(investigation_id=investigation_id, evidence_type=evidence_type, content=content)
        return self._store.store_evidence(ev)

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        return self._store.get_evidence(evidence_id)

    def create_report(self, investigation_id: str, findings: List[str], recommendations: List[str]) -> ForensicReport:
        r = ForensicReport(investigation_id=investigation_id, findings=findings, recommendations=recommendations)
        return self._store.store_report(r)

    def record_custody(self, evidence_id: str, custodian: str, action: str) -> ChainOfCustody:
        c = ChainOfCustody(evidence_id=evidence_id, custodian=custodian, action=action)
        return c

    def get_metrics(self) -> ForensicsMetrics:
        m = self._store.get_metrics()
        return ForensicsMetrics(**m)


_service: Optional[ForensicsService] = None


def get_forensics_service() -> ForensicsService:
    global _service
    if _service is None:
        _service = ForensicsService()
    return _service
