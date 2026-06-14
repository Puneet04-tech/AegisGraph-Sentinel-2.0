"""Security Universe Workflow Engine"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import (
    Team, UnifiedIncident, CollaborationRecord, Workflow,
    TeamType, WorkflowStatus, IncidentSeverity
)

class WorkflowEngine:
    """Cross-team workflow orchestration engine"""
    
    def __init__(self) -> None:
        self.teams: Dict[str, Team] = {}
        self.incidents: Dict[str, UnifiedIncident] = {}
        self.collaborations: Dict[str, CollaborationRecord] = {}
        self.workflows: Dict[str, Workflow] = {}
        self._init_default_teams()
    
    def _init_default_teams(self) -> None:
        """Initialize default security teams"""
        default_teams = [
            Team(
                team_id="soc-001",
                name="Security Operations Center",
                team_type=TeamType.SOC,
                members=["analyst1", "analyst2", "manager1"],
                responsibilities=["Threat monitoring", "Incident response"],
                contact_email="soc@company.com"
            ),
            Team(
                team_id="fraud-001",
                name="Fraud Operations",
                team_type=TeamType.FRAUD_OPS,
                members=["fraud_analyst1", "fraud_analyst2"],
                responsibilities=["Fraud detection", "Transaction monitoring"],
                contact_email="fraud@company.com"
            ),
            Team(
                team_id="aml-001",
                name="AML Operations",
                team_type=TeamType.AML_OPS,
                members=["aml_analyst1", "aml_analyst2"],
                responsibilities=["AML monitoring", "SAR filing"],
                contact_email="aml@company.com"
            )
        ]
        for team in default_teams:
            self.teams[team.team_id] = team
    
    def add_team(self, team: Team) -> str:
        """Add a team to the universe"""
        self.teams[team.team_id] = team
        return team.team_id
    
    def get_team(self, team_id: str) -> Optional[Team]:
        """Get a team by ID"""
        return self.teams.get(team_id)
    
    def get_teams_by_type(self, team_type: TeamType) -> List[Team]:
        """Get teams by type"""
        return [t for t in self.teams.values() if t.team_type == team_type]
    
    def create_incident(
        self,
        title: str,
        description: str,
        severity: str,
        source_teams: List[str],
        assigned_teams: Optional[List[str]] = None
    ) -> UnifiedIncident:
        """Create a cross-team unified incident"""
        incident = UnifiedIncident(
            incident_id=str(uuid4()),
            title=title,
            description=description,
            severity=IncidentSeverity(severity),
            source_teams=[TeamType(t) for t in source_teams],
            assigned_teams=[TeamType(t) for t in (assigned_teams or source_teams)],
            status=WorkflowStatus.PENDING,
            related_incidents=[]
        )
        self.incidents[incident.incident_id] = incident
        return incident
    
    def link_incidents(self, incident_id: str, related_id: str) -> bool:
        """Link two incidents as related"""
        incident = self.incidents.get(incident_id)
        related = self.incidents.get(related_id)
        if incident and related:
            incident.related_incidents.append(related_id)
            related.related_incidents.append(incident_id)
            return True
        return False
    
    def create_collaboration(
        self,
        incident_id: str,
        from_team: str,
        to_team: str,
        action: str,
        notes: str,
        created_by: str
    ) -> Optional[CollaborationRecord]:
        """Create a collaboration record"""
        if incident_id not in self.incidents:
            return None
        
        collaboration = CollaborationRecord(
            record_id=str(uuid4()),
            incident_id=incident_id,
            from_team=TeamType(from_team),
            to_team=TeamType(to_team),
            action=action,
            notes=notes,
            created_by=created_by
        )
        self.collaborations[collaboration.record_id] = collaboration
        return collaboration
    
    def get_incident_collaborations(self, incident_id: str) -> List[CollaborationRecord]:
        """Get all collaborations for an incident"""
        return [c for c in self.collaborations.values() if c.incident_id == incident_id]
    
    def update_incident_status(
        self,
        incident_id: str,
        status: str
    ) -> Optional[UnifiedIncident]:
        """Update incident status"""
        incident = self.incidents.get(incident_id)
        if incident:
            incident.status = WorkflowStatus(status)
            incident.updated_at = datetime.utcnow()
        return incident
    
    def get_incident_summary(self) -> Dict[str, Any]:
        """Get incident summary across all teams"""
        status_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        team_counts: Dict[str, int] = {}
        
        for incident in self.incidents.values():
            status_counts[incident.status.value] = status_counts.get(incident.status.value, 0) + 1
            severity_counts[incident.severity.value] = severity_counts.get(incident.severity.value, 0) + 1
            for team in incident.assigned_teams:
                team_counts[team.value] = team_counts.get(team.value, 0) + 1
        
        return {
            "total_incidents": len(self.incidents),
            "by_status": status_counts,
            "by_severity": severity_counts,
            "by_team": team_counts
        }