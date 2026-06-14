"""
Autonomous Investigation Engine.

Handles autonomous security investigations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import Incident, Severity
from .store import AutonomousSecOpsStore, get_secops_store


class InvestigationEngine:
    """Engine for autonomous investigations."""

    def __init__(self, store: Optional[AutonomousSecOpsStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_secops_store()

    def start_investigation(
        self,
        incident_id: str,
    ) -> Dict[str, Any]:
        """Start an investigation."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return {"success": False, "error": "Incident not found"}
        
        from .models import IncidentStatus
        incident.status = IncidentStatus.INVESTIGATING
        
        self._add_investigation_event(incident_id, "investigation_started", "Investigation initiated")
        
        self.store.log_audit(
            user_id="system",
            action="investigation_started",
            resource_type="incident",
            resource_id=incident_id,
        )
        
        return {
            "success": True,
            "incident_id": incident_id,
            "status": "investigating",
        }

    def _add_investigation_event(
        self,
        incident_id: str,
        event_type: str,
        description: str,
    ) -> None:
        """Add an investigation event."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return
        
        event = {
            "type": event_type,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "investigation_engine",
        }
        
        incident.timeline.append(event)

    def gather_evidence(
        self,
        incident_id: str,
    ) -> Dict[str, Any]:
        """Gather evidence for an incident."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return {"success": False, "error": "Incident not found"}
        
        evidence = {
            "alert_count": len(incident.alerts),
            "affected_assets": incident.affected_assets,
            "timeline_events": len(incident.timeline),
            "duration_minutes": self._calculate_duration(incident),
        }
        
        self._add_investigation_event(
            incident_id,
            "evidence_gathered",
            f"Evidence gathered: {evidence}",
        )
        
        return {
            "success": True,
            "evidence": evidence,
        }

    def _calculate_duration(self, incident: Incident) -> int:
        """Calculate incident duration in minutes."""
        delta = datetime.now(timezone.utc) - incident.created_at
        return int(delta.total_seconds() / 60)

    def analyze_impact(
        self,
        incident_id: str,
    ) -> Dict[str, Any]:
        """Analyze incident impact."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return {"success": False, "error": "Incident not found"}
        
        impact_factors = {
            "severity": incident.severity.value,
            "asset_count": len(incident.affected_assets),
            "alert_count": len(incident.alerts),
            "duration_minutes": self._calculate_duration(incident),
        }
        
        impact_score = self._calculate_impact_score(impact_factors)
        
        self._add_investigation_event(
            incident_id,
            "impact_analyzed",
            f"Impact score: {impact_score}",
        )
        
        return {
            "success": True,
            "impact_score": impact_score,
            "impact_factors": impact_factors,
        }

    def _calculate_impact_score(self, factors: Dict[str, Any]) -> float:
        """Calculate impact score."""
        score = 0.0
        
        severity_scores = {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25,
        }
        score = severity_scores.get(factors["severity"], 0.5)
        
        asset_weight = min(1.0, factors["asset_count"] * 0.1)
        score = max(score, asset_weight)
        
        return min(1.0, score)

    def identify_affected_systems(
        self,
        incident_id: str,
    ) -> List[Dict[str, Any]]:
        """Identify affected systems."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return []
        
        affected = []
        for asset in incident.affected_assets:
            affected.append({
                "asset_id": asset,
                "risk_level": "high",
                "recommendation": "isolate",
            })
        
        return affected

    def generate_investigation_report(
        self,
        incident_id: str,
    ) -> Dict[str, Any]:
        """Generate investigation report."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return {"success": False, "error": "Incident not found"}
        
        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "summary": incident.description,
            "timeline": incident.timeline,
            "affected_assets": incident.affected_assets,
            "duration_minutes": self._calculate_duration(incident),
            "created_at": incident.created_at.isoformat(),
        }


# Singleton instance
_engine: Optional[InvestigationEngine] = None


def get_investigation_engine() -> InvestigationEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = InvestigationEngine()
    return _engine


def reset_investigation_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None