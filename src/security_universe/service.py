"""Security Universe Service"""
from typing import Any, Dict, List, Optional
from .models import Team, UnifiedIncident, CollaborationRecord, Workflow, TeamType
from .workflow_engine import WorkflowEngine

class SecurityUniverseService:
    """Main service for Security Operations Universe"""
    
    def __init__(self) -> None:
        self.engine = WorkflowEngine()
    
    def add_team(self, team_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a team to the universe"""
        team = Team(
            team_id=team_data.get("team_id", str(team_data.get("name", "team").lower().replace(" ", "-"))),
            name=team_data["name"],
            team_type=TeamType(team_data["team_type"]),
            members=team_data.get("members", []),
            responsibilities=team_data.get("responsibilities", []),
            contact_email=team_data.get("contact_email", "")
        )
        self.engine.add_team(team)
        return team.to_dict()
    
    def get_teams(self) -> List[Dict[str, Any]]:
        """Get all teams"""
        return [t.to_dict() for t in self.engine.teams.values()]
    
    def get_team(self, team_id: str) -> Optional[Dict[str, Any]]:
        """Get a team by ID"""
        team = self.engine.get_team(team_id)
        return team.to_dict() if team else None
    
    def create_incident(
        self,
        title: str,
        description: str,
        severity: str,
        source_teams: List[str],
        assigned_teams: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create a unified incident"""
        incident = self.engine.create_incident(
            title=title,
            description=description,
            severity=severity,
            source_teams=source_teams,
            assigned_teams=assigned_teams
        )
        return incident.to_dict()
    
    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get an incident by ID"""
        incident = self.engine.incidents.get(incident_id)
        return incident.to_dict() if incident else None
    
    def get_all_incidents(self) -> List[Dict[str, Any]]:
        """Get all incidents"""
        return [i.to_dict() for i in self.engine.incidents.values()]
    
    def link_incidents(self, incident_id: str, related_id: str) -> bool:
        """Link two incidents"""
        return self.engine.link_incidents(incident_id, related_id)
    
    def create_collaboration(
        self,
        incident_id: str,
        from_team: str,
        to_team: str,
        action: str,
        notes: str,
        created_by: str
    ) -> Optional[Dict[str, Any]]:
        """Create a collaboration record"""
        collaboration = self.engine.create_collaboration(
            incident_id=incident_id,
            from_team=from_team,
            to_team=to_team,
            action=action,
            notes=notes,
            created_by=created_by
        )
        return collaboration.to_dict() if collaboration else None
    
    def get_incident_collaborations(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get collaborations for an incident"""
        return [c.to_dict() for c in self.engine.get_incident_collaborations(incident_id)]
    
    def update_incident_status(self, incident_id: str, status: str) -> Optional[Dict[str, Any]]:
        """Update incident status"""
        incident = self.engine.update_incident_status(incident_id, status)
        return incident.to_dict() if incident else None
    
    def get_incident_summary(self) -> Dict[str, Any]:
        """Get incident summary"""
        return self.engine.get_incident_summary()
    
    def get_universe_analytics(self) -> Dict[str, Any]:
        """Get universe-wide analytics"""
        summary = self.engine.get_incident_summary()
        return {
            "total_teams": len(self.engine.teams),
            "total_incidents": summary["total_incidents"],
            "incident_breakdown": summary,
            "total_collaborations": len(self.engine.collaborations)
        }


# Global service instance
_universe_service: Optional[SecurityUniverseService] = None

def get_universe_service() -> SecurityUniverseService:
    """Get the global service instance"""
    global _universe_service
    if _universe_service is None:
        _universe_service = SecurityUniverseService()
    return _universe_service