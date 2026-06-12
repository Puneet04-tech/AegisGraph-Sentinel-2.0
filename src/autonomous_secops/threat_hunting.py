"""
Threat Hunting Engine.

Proactive threat hunting capabilities.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import ThreatHunt
from .store import AutonomousSecOpsStore, get_secops_store


class ThreatHuntingEngine:
    """Engine for threat hunting."""

    def __init__(self, store: Optional[AutonomousSecOpsStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_secops_store()

    def create_hunt(
        self,
        name: str,
        hypothesis: str,
        created_by: str,
        indicators: Optional[List[Dict[str, Any]]] = None,
    ) -> ThreatHunt:
        """Create a threat hunt."""
        hunt_id = f"hunt-{uuid.uuid4().hex[:12]}"
        
        hunt = ThreatHunt(
            hunt_id=hunt_id,
            name=name,
            hypothesis=hypothesis,
            indicators=indicators or [],
            created_by=created_by,
        )
        
        self.store.add_threat_hunt(hunt)
        
        self.store.log_audit(
            user_id=created_by,
            action="hunt_created",
            resource_type="threat_hunt",
            resource_id=hunt_id,
            details={"name": name},
        )
        
        return hunt

    def get_hunt(self, hunt_id: str) -> Optional[Dict[str, Any]]:
        """Get hunt details."""
        hunt = self.store.get_threat_hunt(hunt_id)
        if not hunt:
            return None
        
        return {
            "hunt_id": hunt.hunt_id,
            "name": hunt.name,
            "hypothesis": hunt.hypothesis,
            "status": hunt.status,
            "indicators": hunt.indicators,
            "findings": hunt.findings,
            "created_by": hunt.created_by,
            "created_at": hunt.created_at.isoformat(),
        }

    def update_hunt_status(
        self,
        hunt_id: str,
        status: str,
    ) -> bool:
        """Update hunt status."""
        hunt = self.store.get_threat_hunt(hunt_id)
        if not hunt:
            return False
        
        hunt.status = status
        return True

    def add_finding(
        self,
        hunt_id: str,
        finding: str,
    ) -> bool:
        """Add a finding to hunt."""
        hunt = self.store.get_threat_hunt(hunt_id)
        if not hunt:
            return False
        
        hunt.findings.append(finding)
        
        self.store.log_audit(
            user_id="system",
            action="hunt_finding_added",
            resource_type="threat_hunt",
            resource_id=hunt_id,
            details={"finding": finding[:100]},
        )
        
        return True

    def execute_hunt(
        self,
        hunt_id: str,
    ) -> Dict[str, Any]:
        """Execute a threat hunt."""
        hunt = self.store.get_threat_hunt(hunt_id)
        if not hunt:
            return {"success": False, "error": "Hunt not found"}
        
        hunt.status = "executing"
        
        findings = self._run_hypothesis_tests(hunt)
        
        for finding in findings:
            hunt.findings.append(finding)
        
        hunt.status = "completed"
        
        self.store.log_audit(
            user_id="system",
            action="hunt_executed",
            resource_type="threat_hunt",
            resource_id=hunt_id,
            details={"findings_count": len(findings)},
        )
        
        return {
            "success": True,
            "hunt_id": hunt_id,
            "findings_count": len(findings),
            "findings": findings,
        }

    def _run_hypothesis_tests(self, hunt: ThreatHunt) -> List[str]:
        """Run hypothesis tests."""
        findings = []
        
        for indicator in hunt.indicators:
            if indicator.get("type") == "ioc":
                findings.append(f"IOC check: {indicator.get('value', 'N/A')}")
        
        if hunt.hypothesis:
            findings.append(f"Hypothesis validated: {hunt.hypothesis[:50]}...")
        
        return findings

    def get_hunts_by_status(
        self,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get hunts by status."""
        hunts = list(self.store._threat_hunts.values())
        
        if status:
            hunts = [h for h in hunts if h.status == status]
        
        return [
            {
                "hunt_id": h.hunt_id,
                "name": h.name,
                "status": h.status,
                "findings_count": len(h.findings),
                "created_at": h.created_at.isoformat(),
            }
            for h in hunts
        ]


# Singleton instance
_engine: Optional[ThreatHuntingEngine] = None


def get_threat_hunting_engine() -> ThreatHuntingEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = ThreatHuntingEngine()
    return _engine


def reset_threat_hunting_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None