import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import AegisGraphSentinelGlobalAutonomousSecurityNetworkRecord, AegisGraphSentinelGlobalAutonomousSecurityNetworkEvent, AegisGraphSentinelGlobalAutonomousSecurityNetworkAlert
from .store import AegisGraphSentinelGlobalAutonomousSecurityNetworkStore


class AegisGraphSentinelGlobalAutonomousSecurityNetworkService:
    def __init__(self, store: AegisGraphSentinelGlobalAutonomousSecurityNetworkStore):
        self.store = store

    def create_record(self, tenant_id: str, record_id: str, name: str,
                       status: str = "ACTIVE", metadata: Dict[str, Any] = None) -> AegisGraphSentinelGlobalAutonomousSecurityNetworkRecord:
        record = AegisGraphSentinelGlobalAutonomousSecurityNetworkRecord(
            record_id=record_id,
            tenant_id=tenant_id,
            name=name,
            status=status,
            created_at=datetime.utcnow(),
            metadata=metadata or {}
        )
        self.store.save_record(tenant_id, record)
        event = AegisGraphSentinelGlobalAutonomousSecurityNetworkEvent(
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

    def get_record(self, tenant_id: str, record_id: str) -> Optional[AegisGraphSentinelGlobalAutonomousSecurityNetworkRecord]:
        return self.store.get_record(tenant_id, record_id)

    def list_records(self, tenant_id: str) -> List[AegisGraphSentinelGlobalAutonomousSecurityNetworkRecord]:
        return self.store.list_records(tenant_id)

    def create_alert(self, tenant_id: str, alert_id: str, title: str,
                     severity: str) -> AegisGraphSentinelGlobalAutonomousSecurityNetworkAlert:
        alert = AegisGraphSentinelGlobalAutonomousSecurityNetworkAlert(
            alert_id=alert_id,
            tenant_id=tenant_id,
            title=title,
            severity=severity,
            is_active=True,
            created_at=datetime.utcnow()
        )
        self.store.save_alert(tenant_id, alert)
        return alert


def get_service() -> AegisGraphSentinelGlobalAutonomousSecurityNetworkService:
    from .store import get_store
    return AegisGraphSentinelGlobalAutonomousSecurityNetworkService(get_store())
