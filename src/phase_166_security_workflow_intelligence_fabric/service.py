import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import SecurityWorkflowIntelligenceFabricRecord, SecurityWorkflowIntelligenceFabricEvent, SecurityWorkflowIntelligenceFabricAlert
from .store import SecurityWorkflowIntelligenceFabricStore


class SecurityWorkflowIntelligenceFabricService:
    def __init__(self, store: SecurityWorkflowIntelligenceFabricStore):
        self.store = store

    def create_record(self, tenant_id: str, record_id: str, name: str,
                       status: str = "ACTIVE", metadata: Dict[str, Any] = None) -> SecurityWorkflowIntelligenceFabricRecord:
        record = SecurityWorkflowIntelligenceFabricRecord(
            record_id=record_id,
            tenant_id=tenant_id,
            name=name,
            status=status,
            created_at=datetime.utcnow(),
            metadata=metadata or {}
        )
        self.store.save_record(tenant_id, record)
        event = SecurityWorkflowIntelligenceFabricEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            record_id=record_id,
            event_type="CREATED",
            severity="INFO",
            timestamp=datetime.utcnow(),
            details={"name": name, "status": status}
        )
        self.store.save_event(event)
        return record

    def get_record(self, tenant_id: str, record_id: str) -> Optional[SecurityWorkflowIntelligenceFabricRecord]:
        return self.store.get_record(tenant_id, record_id)

    def list_records(self, tenant_id: str) -> List[SecurityWorkflowIntelligenceFabricRecord]:
        return self.store.list_records(tenant_id)

    def create_alert(self, tenant_id: str, alert_id: str, title: str,
                     severity: str) -> SecurityWorkflowIntelligenceFabricAlert:
        alert = SecurityWorkflowIntelligenceFabricAlert(
            alert_id=alert_id,
            tenant_id=tenant_id,
            title=title,
            severity=severity,
            is_active=True,
            created_at=datetime.utcnow()
        )
        self.store.save_alert(tenant_id, alert)
        return alert


def get_service() -> SecurityWorkflowIntelligenceFabricService:
    from .store import get_store
    return SecurityWorkflowIntelligenceFabricService(get_store())
