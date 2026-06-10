import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from src.soar.models import Incident, IncidentStatus, ThreatSeverity
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.orchestrator")

class IncidentOrchestrator:
    def __init__(self, store: SOARStore, audit_logger: SOARAuditLogger, playbook_engine=None) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.playbook_engine = playbook_engine

    def create_incident(
        self,
        title: str,
        description: str,
        severity: ThreatSeverity,
        source: str,
        entities: List[str] = None,
        metadata: Dict[str, Any] = None
    ) -> Incident:
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()
        
        incident = Incident(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.NEW,
            source=source,
            created_at=now_str,
            updated_at=now_str,
            entities=entities or [],
            metadata=metadata or {}
        )
        
        self.store.add_incident(incident)
        
        self.audit_logger.log_action(
            action="CREATE_INCIDENT",
            user_id="SYSTEM",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"incident_id": incident_id, "title": title, "severity": severity}
        )
        
        # Trigger matching playbooks in background or inline for testing
        if self.playbook_engine:
            try:
                self.playbook_engine.trigger_playbooks_for_incident(incident)
            except Exception as e:
                logger.error(f"Error triggering playbooks for incident {incident_id}: {e}")
                
        return incident

    def update_incident_status(self, incident_id: str, status: IncidentStatus, user_id: str = "SYSTEM") -> Optional[Incident]:
        incident = self.store.get_incident(incident_id)
        if not incident:
            return None
            
        old_status = incident.status
        incident.status = status
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        self.store.update_incident(incident)
        
        self.audit_logger.log_action(
            action="UPDATE_INCIDENT_STATUS",
            user_id=user_id,
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"incident_id": incident_id, "old_status": old_status, "new_status": status}
        )
        
        return incident
