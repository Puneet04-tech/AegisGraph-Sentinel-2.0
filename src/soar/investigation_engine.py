import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from src.soar.models import Investigation, InvestigationStatus, Incident
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.investigation_engine")

class InvestigationEngine:
    def __init__(self, store: SOARStore, audit_logger: SOARAuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def start_investigation(self, incident_id: str) -> Optional[Investigation]:
        incident = self.store.get_incident(incident_id)
        if not incident:
            return None
            
        investigation_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()
        
        investigation = Investigation(
            investigation_id=investigation_id,
            incident_id=incident_id,
            status=InvestigationStatus.ACTIVE,
            findings=[],
            evidence=[],
            start_time=now_str,
            analyst_notes=[]
        )
        
        self.store.add_investigation(investigation)
        
        self.audit_logger.log_action(
            action="START_INVESTIGATION",
            user_id="SYSTEM",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"investigation_id": investigation_id, "incident_id": incident_id}
        )
        
        # Trigger automated evidence gathering
        self.gather_evidence(investigation_id)
        
        return investigation

    def gather_evidence(self, investigation_id: str) -> None:
        investigation = self.store.get_investigation(investigation_id)
        if not investigation:
            return
            
        incident = self.store.get_incident(investigation.incident_id)
        if not incident:
            return
            
        # Collect evidence from incident entities
        for entity_id in incident.entities:
            # Add to evidence log
            evidence_item = {
                "entity_id": entity_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "automated_gatherer",
                "details": f"Analyzed entity {entity_id} from incident {incident.incident_id}"
            }
            investigation.evidence.append(evidence_item)
            
            # Simple automatic findings based on entity characteristics
            if "malicious" in entity_id.lower() or "bad" in entity_id.lower():
                investigation.findings.append(f"Entity {entity_id} matches known malicious patterns")
            else:
                investigation.findings.append(f"Entity {entity_id} logged in the transaction graph")

        investigation.findings.append(f"Automated check completed for {len(incident.entities)} entities.")
        investigation.status = InvestigationStatus.COMPLETE
        investigation.end_time = datetime.now(timezone.utc).isoformat()
        self.store.update_investigation(investigation)
        
        self.audit_logger.log_action(
            action="GATHER_EVIDENCE",
            user_id="SYSTEM",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"investigation_id": investigation_id, "evidence_count": len(investigation.evidence)}
        )

    def add_analyst_note(self, investigation_id: str, note: str, user_id: str = "ANALYST") -> Optional[Investigation]:
        investigation = self.store.get_investigation(investigation_id)
        if not investigation:
            return None
            
        investigation.analyst_notes.append(note)
        self.store.update_investigation(investigation)
        
        self.audit_logger.log_action(
            action="ADD_ANALYST_NOTE",
            user_id=user_id,
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"investigation_id": investigation_id, "note": note}
        )
        
        return investigation
