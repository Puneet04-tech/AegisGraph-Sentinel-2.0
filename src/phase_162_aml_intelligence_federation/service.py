import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from .models import AMLIntelligenceFederationRecord, AMLIntelligenceFederationEvent, AMLIntelligenceFederationAlert
from .store import AMLIntelligenceFederationStore


class AMLIntelligenceFederationService:
    def __init__(self, store: AMLIntelligenceFederationStore):
        self.store = store

    def create_record(self, tenant_id: str, record_id: str, name: str,
                       status: str = "ACTIVE", metadata: Dict[str, Any] = None) -> AMLIntelligenceFederationRecord:
        record = AMLIntelligenceFederationRecord(
            record_id=record_id,
            tenant_id=tenant_id,
            name=name,
            status=status,
            created_at=datetime.now(timezone.utc),
            metadata=metadata or {}
        )
        self.store.save_record(tenant_id, record)
        event = AMLIntelligenceFederationEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            record_id=record_id,
            event_type="CREATED",
            severity="INFO",
            timestamp=datetime.now(timezone.utc),
            details={"name": name, "status": status}
        )
        self.store.save_event(event)
        return record

    def get_record(self, tenant_id: str, record_id: str) -> Optional[AMLIntelligenceFederationRecord]:
        return self.store.get_record(tenant_id, record_id)

    def list_records(self, tenant_id: str) -> List[AMLIntelligenceFederationRecord]:
        return self.store.list_records(tenant_id)

    def create_alert(self, tenant_id: str, alert_id: str, title: str,
                     severity: str) -> AMLIntelligenceFederationAlert:
        alert = AMLIntelligenceFederationAlert(
            alert_id=alert_id,
            tenant_id=tenant_id,
            title=title,
            severity=severity,
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        self.store.save_alert(tenant_id, alert)
        return alert


def get_service() -> AMLIntelligenceFederationService:
    from .store import get_store
    return AMLIntelligenceFederationService(get_store())
