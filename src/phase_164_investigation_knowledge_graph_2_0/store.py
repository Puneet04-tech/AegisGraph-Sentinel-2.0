import threading
from typing import Dict, List, Optional
from .models import InvestigationKnowledgeGraph20Record, InvestigationKnowledgeGraph20Event, InvestigationKnowledgeGraph20Alert


class InvestigationKnowledgeGraph20Store:
    def __init__(self):
        self._lock = threading.RLock()
        self._records: Dict[str, Dict[str, InvestigationKnowledgeGraph20Record]] = {}
        self._events: Dict[str, List[InvestigationKnowledgeGraph20Event]] = {}
        self._alerts: Dict[str, List[InvestigationKnowledgeGraph20Alert]] = {}

    def save_record(self, tenant_id: str, record: InvestigationKnowledgeGraph20Record) -> None:
        with self._lock:
            if tenant_id not in self._records:
                self._records[tenant_id] = {}
            self._records[tenant_id][record.record_id] = record

    def get_record(self, tenant_id: str, record_id: str) -> Optional[InvestigationKnowledgeGraph20Record]:
        with self._lock:
            return self._records.get(tenant_id, {}).get(record_id)

    def list_records(self, tenant_id: str) -> List[InvestigationKnowledgeGraph20Record]:
        with self._lock:
            return list(self._records.get(tenant_id, {}).values())

    def save_event(self, event: InvestigationKnowledgeGraph20Event) -> None:
        with self._lock:
            key = event.record_id
            if key not in self._events:
                self._events[key] = []
            self._events[key].append(event)

    def get_events(self, record_id: str) -> List[InvestigationKnowledgeGraph20Event]:
        with self._lock:
            return list(self._events.get(record_id, []))

    def save_alert(self, tenant_id: str, alert: InvestigationKnowledgeGraph20Alert) -> None:
        with self._lock:
            if tenant_id not in self._alerts:
                self._alerts[tenant_id] = []
            self._alerts[tenant_id].append(alert)

    def list_alerts(self, tenant_id: str) -> List[InvestigationKnowledgeGraph20Alert]:
        with self._lock:
            return list(self._alerts.get(tenant_id, []))


_store_instance = InvestigationKnowledgeGraph20Store()

def get_store() -> InvestigationKnowledgeGraph20Store:
    return _store_instance
