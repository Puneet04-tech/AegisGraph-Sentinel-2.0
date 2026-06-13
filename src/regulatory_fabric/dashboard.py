"""
Executive Compliance Dashboard for Regulatory Fabric.

Provides real-time compliance metrics and insights for executives.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from .models import ComplianceDashboard


class ComplianceDashboardService:
    """Executive compliance dashboard service.
    
    Aggregates compliance data and provides executive-level insights.
    """

    def __init__(
        self,
        store: Any,
        drift_detector: Any,
        risk_engine: Any,
        change_tracker: Any,
    ):
        """Initialize the dashboard service.
        
        Args:
            store: Compliance store instance
            drift_detector: Drift detector instance
            risk_engine: Risk engine instance
            change_tracker: Change tracker instance
        """
        self.store = store
        self.drift_detector = drift_detector
        self.risk_engine = risk_engine
        self.change_tracker = change_tracker

    def generate_dashboard(self) -> ComplianceDashboard:
        """Generate the executive compliance dashboard.
        
        Returns:
            Dashboard data
        """
        now = datetime.now(timezone.utc)
        
        # Calculate overall compliance score
        overall_score = self._calculate_overall_score()
        
        # Calculate domain scores
        domain_scores = self._calculate_domain_scores()
        
        # Get findings summary
        findings = self._get_findings_summary()
        
        # Get recent assessments
        recent_assessments = self._get_recent_assessments()
        
        # Get upcoming deadlines
        upcoming_deadlines = self._get_upcoming_deadlines()
        
        # Get risk summary
        risk_summary = self._get_risk_summary()
        
        # Calculate trend direction
        trend_direction = self._calculate_trend_direction()
        
        return ComplianceDashboard(
            dashboard_id=f"dash_{now.timestamp()}",
            generated_at=now,
            overall_score=overall_score,
            domain_scores=domain_scores,
            open_findings=findings["total"],
            critical_findings=findings.get("CRITICAL", 0),
            high_findings=findings.get("HIGH", 0),
            medium_findings=findings.get("MEDIUM", 0),
            low_findings=findings.get("LOW", 0),
            recent_assessments=recent_assessments,
            upcoming_deadlines=upcoming_deadlines,
            risk_summary=risk_summary,
            trend_direction=trend_direction,
        )

    def _calculate_overall_score(self) -> float:
        """Calculate overall compliance score."""
        assessments = self.store.list_assessments(status="COMPLETED")
        
        if not assessments:
            # Calculate based on control compliance
            controls = list(self.store.controls.values())
            if not controls:
                return 0.0
            
            compliant = len([c for c in controls if c.get("status") == "COMPLIANT"])
            return (compliant / len(controls)) * 100
        
        # Use assessment scores
        total_score = sum(a.get("overall_score", 0) for a in assessments)
        return total_score / len(assessments)

    def _calculate_domain_scores(self) -> Dict[str, float]:
        """Calculate compliance scores by domain."""
        domain_scores = {}
        
        for reg in self.store.regulations.values():
            domain = reg.get("domain", "UNKNOWN")
            reg_id = reg.get("regulation_id")
            
            controls = self.store.get_controls_for_regulation(reg_id)
            if not controls:
                continue
            
            compliant = len([c for c in controls if c.get("status") == "COMPLIANT"])
            score = (compliant / len(controls)) * 100
            
            domain_scores[domain] = domain_scores.get(domain, 0) + score
        
        # Average scores for domains with multiple regulations
        # (Simplified - in production, would track regulation count per domain)
        return domain_scores

    def _get_findings_summary(self) -> Dict[str, Any]:
        """Get summary of findings."""
        findings = {
            "total": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        
        # From assessments
        for assess in self.store.assessments.values():
            for finding in assess.get("findings", []):
                findings["total"] += 1
                severity = finding.get("severity", "MEDIUM")
                findings[severity] = findings.get(severity, 0) + 1
        
        # From risks
        for risk in self.store.risks.values():
            if risk.get("mitigation_status") == "OPEN":
                level = risk.get("risk_level", "MEDIUM")
                findings[level] = findings.get(level, 0) + 1
        
        return findings

    def _get_recent_assessments(self) -> List[Dict[str, Any]]:
        """Get recent assessments for dashboard."""
        assessments = self.store.list_assessments(status="COMPLETED")[:5]
        
        return [
            {
                "assessment_id": a.get("assessment_id"),
                "regulation_id": a.get("regulation_id"),
                "score": a.get("overall_score", 0),
                "date": a.get("assessment_date"),
                "status": a.get("status"),
            }
            for a in assessments
        ]

    def _get_upcoming_deadlines(self) -> List[Dict[str, Any]]:
        """Get upcoming compliance deadlines."""
        now = datetime.now(timezone.utc)
        deadline = now + timedelta(days=30)
        
        deadlines = []
        
        # From controls
        for ctrl in self.store.controls.values():
            next_test = ctrl.get("next_test")
            if next_test:
                if isinstance(next_test, str):
                    next_test = datetime.fromisoformat(next_test)
                if now <= next_test <= deadline:
                    deadlines.append({
                        "type": "control_test",
                        "entity_id": ctrl.get("control_id"),
                        "title": f"Control Test: {ctrl.get('control_name', 'Unknown')}",
                        "due_date": next_test.isoformat(),
                        "days_remaining": (next_test - now).days,
                    })
        
        # Sort by days remaining
        deadlines = sorted(deadlines, key=lambda x: x["days_remaining"])
        return deadlines[:10]

    def _get_risk_summary(self) -> Dict[str, int]:
        """Get risk summary counts."""
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        
        for risk in self.store.risks.values():
            if risk.get("mitigation_status") == "OPEN":
                level = risk.get("risk_level", "MEDIUM")
                risk_counts[level] = risk_counts.get(level, 0) + 1
        
        return risk_counts

    def _calculate_trend_direction(self) -> str:
        """Calculate compliance trend direction."""
        # Compare recent assessments to older ones
        assessments = self.store.list_assessments(status="COMPLETED")
        
        if len(assessments) < 2:
            return "STABLE"
        
        # Split into recent (last 30 days) and older
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        recent = [a for a in assessments if a.get("assessment_date", "") >= cutoff.isoformat()]
        older = [a for a in assessments if a.get("assessment_date", "") < cutoff.isoformat()]
        
        if not recent or not older:
            return "STABLE"
        
        recent_avg = sum(a.get("overall_score", 0) for a in recent) / len(recent)
        older_avg = sum(a.get("overall_score", 0) for a in older) / len(older)
        
        delta = recent_avg - older_avg
        
        if delta > 5:
            return "IMPROVING"
        elif delta < -5:
            return "DECLINING"
        return "STABLE"

    def get_executive_summary(self) -> Dict[str, Any]:
        """Get executive summary for board reporting."""
        dashboard = self.generate_dashboard()
        
        # Key metrics
        metrics = {
            "overall_compliance_score": dashboard.overall_score,
            "trend": dashboard.trend_direction,
            "open_findings": dashboard.open_findings,
            "critical_findings": dashboard.critical_findings,
            "risk_distribution": dashboard.risk_summary,
        }
        
        # Top concerns
        concerns = []
        
        if dashboard.critical_findings > 0:
            concerns.append({
                "priority": "CRITICAL",
                "message": f"{dashboard.critical_findings} critical findings require immediate attention",
            })
        
        if dashboard.trend_direction == "DECLINING":
            concerns.append({
                "priority": "HIGH",
                "message": "Compliance posture is declining - review recent changes",
            })
        
        # Opportunities
        opportunities = []
        
        if dashboard.overall_score >= 90:
            opportunities.append("Excellent compliance posture - focus on maintaining")
        elif dashboard.overall_score >= 80:
            opportunities.append("Good compliance - target areas for improvement")
        
        # Upcoming actions
        actions = []
        for deadline in dashboard.upcoming_deadlines[:3]:
            actions.append({
                "type": deadline.get("type"),
                "title": deadline.get("title"),
                "due_date": deadline.get("due_date"),
                "days_remaining": deadline.get("days_remaining"),
            })
        
        return {
            "report_date": datetime.now(timezone.utc).isoformat(),
            "executive_summary": {
                "compliance_score": metrics,
                "top_concerns": concerns,
                "opportunities": opportunities,
                "recommended_actions": actions,
            },
            "detailed_metrics": dashboard.to_dict(),
        }

    def get_domain_drilldown(self, domain: str) -> Dict[str, Any]:
        """Get detailed drilldown for a specific domain.
        
        Args:
            domain: Regulatory domain
            
        Returns:
            Domain drilldown data
        """
        # Find regulations in this domain
        regulations = [
            r for r in self.store.regulations.values()
            if r.get("domain") == domain
        ]
        
        domain_data = []
        
        for reg in regulations:
            reg_id = reg.get("regulation_id")
            controls = self.store.get_controls_for_regulation(reg_id)
            
            compliant = len([c for c in controls if c.get("status") == "COMPLIANT"])
            non_compliant = len([c for c in controls if c.get("status") == "NON_COMPLIANT"])
            partial = len([c for c in controls if c.get("status") == "PARTIALLY_COMPLIANT"])
            
            # Get latest assessment
            assessments = self.store.list_assessments(regulation_id=reg_id, status="COMPLETED")
            latest_score = assessments[0].get("overall_score", 0) if assessments else 0
            
            domain_data.append({
                "regulation_id": reg_id,
                "regulation_name": reg.get("name"),
                "version": reg.get("version"),
                "status": reg.get("status"),
                "control_count": len(controls),
                "compliant_controls": compliant,
                "non_compliant_controls": non_compliant,
                "partially_compliant_controls": partial,
                "compliance_rate": (compliant / len(controls) * 100) if controls else 0,
                "latest_assessment_score": latest_score,
                "next_assessment_due": assessments[0].get("next_assessment") if assessments else None,
            })
        
        # Calculate domain totals
        total_controls = sum(d["control_count"] for d in domain_data)
        total_compliant = sum(d["compliant_controls"] for d in domain_data)
        
        return {
            "domain": domain,
            "regulation_count": len(domain_data),
            "total_controls": total_controls,
            "domain_compliance_rate": (total_compliant / total_controls * 100) if total_controls > 0 else 0,
            "regulations": domain_data,
        }

    def export_board_report(self, format: str = "json") -> Dict[str, Any]:
        """Export board-ready compliance report.
        
        Args:
            format: Export format
            
        Returns:
            Board report data
        """
        dashboard = self.generate_dashboard()
        executive = self.get_executive_summary()
        
        report = {
            "report_metadata": {
                "title": "Quarterly Compliance Report",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "period": "Q2 2024",
                "prepared_for": "Board of Directors",
            },
            "key_metrics": {
                "overall_score": dashboard.overall_score,
                "trend": dashboard.trend_direction,
                "domain_scores": dashboard.domain_scores,
            },
            "findings_summary": {
                "total_open": dashboard.open_findings,
                "critical": dashboard.critical_findings,
                "high": dashboard.high_findings,
                "medium": dashboard.medium_findings,
                "low": dashboard.low_findings,
            },
            "risk_posture": dashboard.risk_summary,
            "top_concerns": executive["executive_summary"]["top_concerns"],
            "recommended_actions": executive["executive_summary"]["recommended_actions"],
            "appendix": {
                "recent_assessments": dashboard.recent_assessments,
                "upcoming_deadlines": dashboard.upcoming_deadlines,
            },
        }
        
        return report


def get_dashboard_service() -> ComplianceDashboardService:
    """Get the global dashboard service instance."""
    from .store import get_compliance_store
    from .drift_detector import get_drift_detector
    from .risk_engine import get_risk_engine
    from .change_tracker import get_change_tracker
    
    store = get_compliance_store()
    drift_detector = get_drift_detector()
    risk_engine = get_risk_engine()
    change_tracker = get_change_tracker()
    
    return ComplianceDashboardService(store, drift_detector, risk_engine, change_tracker)