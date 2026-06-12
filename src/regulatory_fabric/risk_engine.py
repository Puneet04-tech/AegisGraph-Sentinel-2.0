"""
Compliance Risk Engine for Regulatory Fabric.

Assesses and manages compliance-related risks.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import threading
import uuid


@dataclass
class RiskCalculation:
    """Risk calculation result."""
    risk_id: str
    calculation_date: datetime
    likelihood: float
    impact: float
    risk_score: float
    risk_level: str
    contributing_factors: List[str]
    recommended_mitigations: List[str]


class ComplianceRiskEngine:
    """Compliance risk assessment engine.
    
    Identifies, assesses, and tracks compliance risks.
    """

    def __init__(self, store: Any):
        """Initialize the compliance risk engine.
        
        Args:
            store: Compliance store instance
        """
        self.store = store
        self._risk_weights = {
            "NON_COMPLIANT_CONTROL": 0.4,
            "EXPIRED_ASSESSMENT": 0.2,
            "HIGH_PRIORITY_FINDING": 0.3,
            "REGULATORY_UPDATE": 0.25,
            "OVERDUE_MITIGATION": 0.35,
            "UNMAPPED_REQUIREMENT": 0.15,
        }

    def assess_risk(
        self,
        entity_type: str,
        entity_id: str,
    ) -> Dict[str, Any]:
        """Assess risk for an entity.
        
        Args:
            entity_type: Type of entity (regulation, control, etc.)
            entity_id: Entity ID
            
        Returns:
            Risk assessment
        """
        likelihood = 0.5
        impact = 0.5
        contributing_factors = []
        recommended_mitigations = []
        
        if entity_type == "control":
            control = self.store.get_control(entity_id)
            if control:
                status = control.get("status")
                if status == "NON_COMPLIANT":
                    likelihood += 0.3
                    contributing_factors.append("Control is non-compliant")
                    recommended_mitigations.append("Remediate control to compliant status")
                
                effectiveness = control.get("effectiveness")
                if effectiveness == "INEFFECTIVE":
                    likelihood += 0.2
                    impact += 0.1
                    contributing_factors.append("Control effectiveness is low")
                    recommended_mitigations.append("Review and strengthen control implementation")
                
                last_tested = control.get("last_tested")
                if last_tested:
                    if isinstance(last_tested, str):
                        last_tested = datetime.fromisoformat(last_tested)
                    days_since = (datetime.now(timezone.utc) - last_tested).days
                    if days_since > 90:
                        likelihood += 0.1
                        contributing_factors.append(f"Control not tested in {days_since} days")
                        recommended_mitigations.append("Schedule control test")
        
        elif entity_type == "regulation":
            regulation = self.store.get_regulation(entity_id)
            if regulation:
                controls = self.store.get_controls_for_regulation(entity_id)
                non_compliant = len([c for c in controls if c.get("status") == "NON_COMPLIANT"])
                if non_compliant > 0:
                    likelihood += 0.2 * (non_compliant / max(1, len(controls)))
                    contributing_factors.append(f"{non_compliant} non-compliant controls")
                
                # Check for pending updates
                updates = self.store.list_regulatory_updates(regulation_id=entity_id, processed=False)
                if updates:
                    impact += 0.1 * min(1, len(updates) / 5)
                    contributing_factors.append(f"{len(updates)} pending regulatory updates")
                    recommended_mitigations.append("Review and process regulatory updates")
        
        # Calculate risk score
        risk_score = likelihood * impact
        risk_level = self._get_risk_level(risk_score)
        
        risk = {
            "risk_id": str(uuid.uuid4()),
            "entity_type": entity_type,
            "entity_id": entity_id,
            "risk_level": risk_level,
            "likelihood": min(1.0, likelihood),
            "impact": min(1.0, impact),
            "risk_score": round(risk_score, 4),
            "contributing_factors": contributing_factors,
            "recommended_mitigations": recommended_mitigations,
            "calculated_at": datetime.now(timezone.utc),
        }
        
        return risk  # type: ignore[return-value]

    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score."""
        if score >= 0.7:
            return "CRITICAL"
        elif score >= 0.4:
            return "HIGH"
        elif score >= 0.2:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        return "MINIMAL"

    def get_portfolio_risk(self) -> Dict[str, Any]:
        """Get overall portfolio risk assessment."""
        all_controls = list(self.store.controls.values())
        all_regulations = list(self.store.regulations.values())
        all_assessments = list(self.store.assessments.values())
        
        # Risk by control
        control_risks = []
        for ctrl in all_controls:
            risk = self.assess_risk("control", ctrl.get("control_id"))
            control_risks.append(risk)
        
        # Risk by regulation
        regulation_risks = []
        for reg in all_regulations:
            risk = self.assess_risk("regulation", reg.get("regulation_id"))
            regulation_risks.append(risk)
        
        # Aggregate risk scores
        risk_levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        for risk in control_risks + regulation_risks:
            risk_levels[risk["risk_level"]] += 1
        
        total_entities = len(all_controls) + len(all_regulations)
        portfolio_risk_score = sum(r["risk_score"] for r in control_risks + regulation_risks) / total_entities if total_entities > 0 else 0
        
        return {
            "portfolio_risk_score": round(portfolio_risk_score, 4),
            "portfolio_risk_level": self._get_risk_level(portfolio_risk_score),
            "risk_distribution": risk_levels,
            "total_entities_assessed": total_entities,
            "highest_risk_controls": sorted(control_risks, key=lambda x: x["risk_score"], reverse=True)[:5],
            "highest_risk_regulations": sorted(regulation_risks, key=lambda x: x["risk_score"], reverse=True)[:5],
            "critical_risks": [r for r in control_risks + regulation_risks if r["risk_level"] == "CRITICAL"],
        }

    def create_risk_register(self) -> Dict[str, Any]:
        """Create/update the risk register."""
        risks = []
        
        # Add control risks
        for ctrl in self.store.controls.values():
            risk = self.assess_risk("control", ctrl.get("control_id"))
            risk["control_id"] = ctrl.get("control_id")
            risk["control_name"] = ctrl.get("control_name")
            risk["status"] = ctrl.get("status")
            risks.append(risk)
        
        # Add regulation risks
        for reg in self.store.regulations.values():
            risk = self.assess_risk("regulation", reg.get("regulation_id"))
            risk["regulation_id"] = reg.get("regulation_id")
            risk["regulation_name"] = reg.get("name")
            risk["status"] = reg.get("status")
            risks.append(risk)
        
        # Sort by risk score
        risks = sorted(risks, key=lambda x: x["risk_score"], reverse=True)
        
        # Store as compliance risks
        for risk in risks:
            if risk["risk_level"] in ("HIGH", "CRITICAL"):
                self.store.add_risk({
                    "risk_id": risk["risk_id"],
                    "regulation_id": risk.get("regulation_id"),
                    "control_id": risk.get("control_id"),
                    "risk_level": risk["risk_level"],
                    "description": "; ".join(risk["contributing_factors"]),
                    "likelihood": risk["likelihood"],
                    "impact": risk["impact"],
                    "risk_score": risk["risk_score"],
                    "mitigation_status": "OPEN",
                    "owner": "",
                })
        
        return {
            "total_risks": len(risks),
            "risks": risks,
            "critical_count": len([r for r in risks if r["risk_level"] == "CRITICAL"]),
            "high_count": len([r for r in risks if r["risk_level"] == "HIGH"]),
        }

    def get_risk_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get risk trends over time.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Trend analysis
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        recent_risks = [
            r for r in self.store.risks.values()
            if isinstance(r.get("identified_date"), datetime) and r.get("identified_date") >= cutoff
        ]
        
        # Group by week
        weekly_trends = {}
        for risk in recent_risks:
            identified = risk.get("identified_date")
            if isinstance(identified, str):
                identified = datetime.fromisoformat(identified)
            week_start = identified - timedelta(days=identified.weekday())
            week_key = week_start.strftime("%Y-W%U")
            
            if week_key not in weekly_trends:
                weekly_trends[week_key] = {"total": 0, "by_level": {}}
            
            weekly_trends[week_key]["total"] += 1
            level = risk.get("risk_level", "MEDIUM")
            weekly_trends[week_key]["by_level"][level] = weekly_trends[week_key]["by_level"].get(level, 0) + 1
        
        return {
            "period_days": days,
            "total_new_risks": len(recent_risks),
            "weekly_trends": weekly_trends,
            "top_contributing_factors": self._get_top_factors(recent_risks),
        }

    def _get_top_factors(self, risks: List[Dict]) -> List[Dict[str, Any]]:
        """Get top contributing risk factors."""
        factor_counts = {}
        for risk in risks:
            factors = risk.get("contributing_factors", [])
            for factor in factors:
                factor_counts[factor] = factor_counts.get(factor, 0) + 1
        
        return sorted(
            [{"factor": k, "count": v} for k, v in factor_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

    def get_risk_mitigation_plan(self, risk_id: str) -> Dict[str, Any]:
        """Generate a mitigation plan for a risk.
        
        Args:
            risk_id: Risk ID
            
        Returns:
            Mitigation plan
        """
        risk = self.store.get_risk(risk_id)
        if not risk:
            return {"error": "Risk not found"}
        
        risk_level = risk.get("risk_level", "MEDIUM")
        
        # Generate timeline based on risk level
        timeline_map = {
            "CRITICAL": 7,
            "HIGH": 30,
            "MEDIUM": 60,
            "LOW": 90,
            "MINIMAL": 180,
        }
        
        plan = {
            "risk_id": risk_id,
            "risk_level": risk_level,
            "target_resolution_date": (datetime.now(timezone.utc) + timedelta(days=timeline_map[risk_level])).isoformat(),
            "phases": [
                {
                    "phase": 1,
                    "title": "Assessment",
                    "duration_days": min(7, timeline_map[risk_level] // 3),
                    "actions": ["Identify root cause", "Document current state", "Define success criteria"],
                },
                {
                    "phase": 2,
                    "title": "Remediation",
                    "duration_days": timeline_map[risk_level] // 2,
                    "actions": ["Implement fixes", "Test implementation", "Document changes"],
                },
                {
                    "phase": 3,
                    "title": "Validation",
                    "duration_days": timeline_map[risk_level] // 6,
                    "actions": ["Validate effectiveness", "Collect evidence", "Update documentation"],
                },
            ],
            "recommended_owner": self._suggest_risk_owner(risk),
            "approval_required": risk_level in ("CRITICAL", "HIGH"),
        }
        
        return plan

    def _suggest_risk_owner(self, risk: Dict) -> str:
        """Suggest a risk owner based on entity."""
        control_id = risk.get("control_id")
        if control_id:
            control = self.store.get_control(control_id)
            if control and control.get("owner"):
                return control["owner"]
        return "COMPLIANCE_TEAM"


def get_risk_engine() -> ComplianceRiskEngine:
    """Get the global risk engine instance."""
    from .store import get_compliance_store
    store = get_compliance_store()
    return ComplianceRiskEngine(store)