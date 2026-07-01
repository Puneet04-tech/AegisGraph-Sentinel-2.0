import threading
from typing import Dict, List, Optional
from .models import SecurityWorkflowIntelligenceFabricRecord, SecurityWorkflowIntelligenceFabricEvent, SecurityWorkflowIntelligenceFabricAlert


class SecurityWorkflowIntelligenceFabricStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._records: Dict[str, Dict[str, SecurityWorkflowIntelligenceFabricRecord]] = {}
        self._events: Dict[str, List[SecurityWorkflowIntelligenceFabricEvent]] = {}
        self._alerts: Dict[str, List[SecurityWorkflowIntelligenceFabricAlert]] = {}

    def save_record(self, tenant_id: str, record: SecurityWorkflowIntelligenceFabricRecord) -> None:
        with self._lock:
            if tenant_id not in self._records:
                self._records[tenant_id] = {}
            self._records[tenant_id][record.record_id] = record

    def get_record(self, tenant_id: str, record_id: str) -> Optional[SecurityWorkflowIntelligenceFabricRecord]:
        with self._lock:
            return self._records.get(tenant_id, {}).get(record_id)

    def list_records(self, tenant_id: str) -> List[SecurityWorkflowIntelligenceFabricRecord]:
        with self._lock:
            return list(self._records.get(tenant_id, {}).values())

    def save_event(self, event: SecurityWorkflowIntelligenceFabricEvent) -> None:
        with self._lock:
            key = event.record_id
            if key not in self._events:
                self._events[key] = []
            self._events[key].append(event)

    def get_events(self, record_id: str) -> List[SecurityWorkflowIntelligenceFabricEvent]:
        with self._lock:
            return list(self._events.get(record_id, []))

    def save_alert(self, tenant_id: str, alert: SecurityWorkflowIntelligenceFabricAlert) -> None:
        with self._lock:
            if tenant_id not in self._alerts:
                self._alerts[tenant_id] = []
            self._alerts[tenant_id].append(alert)

    def list_alerts(self, tenant_id: str) -> List[SecurityWorkflowIntelligenceFabricAlert]:
        with self._lock:
            return list(self._alerts.get(tenant_id, []))


_store_instance = SecurityWorkflowIntelligenceFabricStore()

def get_store() -> SecurityWorkflowIntelligenceFabricStore:
    return _store_instance
