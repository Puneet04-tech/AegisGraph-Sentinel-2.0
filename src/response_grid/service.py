"""Response Grid Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import Incident, Playbook, RemediationAction, PartnerOrganization
from .models import IncidentStatus, Severity, RemediationStatus

class ResponseGridService:
    """Global Incident Response Grid Service"""
    
    def __init__(self) -> None:
        self.incidents: Dict[str, Incident] = {}
        self.playbooks: Dict[str, Playbook] = {}
        self.remediations: Dict[str, RemediationAction] = {}
        self.partners: Dict[str, PartnerOrganization] = {}
        self._init_default_playbooks()
        self._init_default_partners()
    
    def _init_default_playbooks(self) -> None:
        """Initialize default response playbooks"""
        playbooks = [
            Playbook(
                playbook_id="pb-001",
                name="Critical Incident Response",
                description="Automated response for critical incidents",
                steps=[
                    {"step": 1, "action": "alert", "target": "SOC"},
                    {"step": 2, "action": "isolate", "target": "affected_systems"},
                    {"step": 3, "action": "notify", "target": "management"}
                ],
                applicable_severities=[Severity.CRITICAL]
            ),
            Playbook(
                playbook_id="pb-002",
                name="Ransomware Response",
                description="Response playbook for ransomware attacks",
                steps=[
                    {"step": 1, "action": "contain", "target": "network"},
                    {"step": 2, "action": "backup", "target": "critical_data"},
                    {"step": 3, "action": "notify", "target": "authorities"}
                ],
                applicable_severities=[Severity.HIGH, Severity.CRITICAL]
            )
        ]
        for pb in playbooks:
            self.playbooks[pb.playbook_id] = pb
    
    def _init_default_partners(self) -> None:
        """Initialize default partner organizations"""
        partners = [
            PartnerOrganization(org_id="org-001", name="Global Security Alliance", country="US"),
            PartnerOrganization(org_id="org-002", name="EU CERT Network", country="EU"),
            PartnerOrganization(org_id="org-003", name="APAC Security Hub", country="APAC")
        ]
        for partner in partners:
            self.partners[partner.org_id] = partner
    
    def create_incident(
        self,
        title: str,
        description: str,
        severity: str,
        organization_id: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create a new incident"""
        incident = Incident(
            incident_id=str(uuid4())[:8],
            title=title,
            description=description,
            severity=Severity(severity),
            organization_id=organization_id,
            tags=tags or []
        )
        self.incidents[incident.incident_id] = incident
        return incident.to_dict()
    
    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get an incident by ID"""
        incident = self.incidents.get(incident_id)
        return incident.to_dict() if incident else None
    
    def get_all_incidents(self) -> List[Dict[str, Any]]:
        """Get all incidents"""
        return [i.to_dict() for i in self.incidents.values()]
    
    def update_incident_status(self, incident_id: str, status: str) -> Optional[Dict[str, Any]]:
        """Update incident status"""
        incident = self.incidents.get(incident_id)
        if incident:
            incident.status = IncidentStatus(status)
            incident.updated_at = datetime.utcnow()
            return incident.to_dict()
        return None
    
    def link_incidents(self, incident_id: str, linked_id: str) -> bool:
        """Link two incidents together"""
        incident = self.incidents.get(incident_id)
        linked = self.incidents.get(linked_id)
        if incident and linked:
            if linked_id not in incident.linked_incidents:
                incident.linked_incidents.append(linked_id)
            if incident_id not in linked.linked_incidents:
                linked.linked_incidents.append(incident_id)
            return True
        return False
    
    def create_remediation(
        self,
        incident_id: str,
        action_type: str,
        description: str,
        assigned_to: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a remediation action"""
        action = RemediationAction(
            action_id=str(uuid4())[:8],
            incident_id=incident_id,
            action_type=action_type,
            description=description,
            status=RemediationStatus.PENDING,
            assigned_to=assigned_to
        )
        self.remediations[action.action_id] = action
        return action.to_dict()
    
    def execute_remediation(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Execute a remediation action"""
        action = self.remediations.get(action_id)
        if action:
            action.status = RemediationStatus.IN_PROGRESS
            action.executed_at = datetime.utcnow()
            # Simulate execution
            action.status = RemediationStatus.COMPLETED
            action.result = {"success": True, "action": action.action_type}
            return action.to_dict()
        return None
    
    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get a playbook"""
        playbook = self.playbooks.get(playbook_id)
        return playbook.to_dict() if playbook else None
    
    def get_all_playbooks(self) -> List[Dict[str, Any]]:
        """Get all playbooks"""
        return [p.to_dict() for p in self.playbooks.values()]
    
    def add_partner(self, name: str, country: str, trust_level: float = 0.5) -> Dict[str, Any]:
        """Add a partner organization"""
        partner = PartnerOrganization(
            org_id=str(uuid4())[:8],
            name=name,
            country=country,
            trust_level=trust_level
        )
        self.partners[partner.org_id] = partner
        return partner.to_dict()
    
    def get_partners(self) -> List[Dict[str, Any]]:
        """Get all partners"""
        return [p.to_dict() for p in self.partners.values()]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get response grid dashboard"""
        status_counts: Dict[str, int] = {}
        for inc in self.incidents.values():
            status_counts[inc.status.value] = status_counts.get(inc.status.value, 0) + 1
        
        return {
            "total_incidents": len(self.incidents),
            "total_playbooks": len(self.playbooks),
            "total_partners": len(self.partners),
            "incidents_by_status": status_counts
        }


# Global service instance
_response_grid_service: Optional[ResponseGridService] = None

def get_response_grid_service() -> ResponseGridService:
    """Get the global service instance"""
    global _response_grid_service
    if _response_grid_service is None:
        _response_grid_service = ResponseGridService()
    return _response_grid_service