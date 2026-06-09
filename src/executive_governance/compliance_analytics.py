"""
Compliance Analytics Module.

Provides compliance tracking, framework management, and regulatory reporting.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    ComplianceFramework,
    ControlAssessment,
    ComplianceStatus,
    AuditFinding,
    AuditFindingSeverity,
)
from .store import GovernanceStore, get_governance_store

logger = logging.getLogger(__name__)


class ComplianceAnalyticsModule:
    """Compliance Analytics for regulatory and framework management.
    
    Provides:
        - Compliance framework tracking
        - Control assessment management
        - Regulatory reporting
        - Gap analysis
    """
    
    def __init__(self, store: Optional[GovernanceStore] = None):
        """Initialize the compliance analytics module.
        
        Args:
            store: Optional governance store
        """
        self._store = store or get_governance_store()
        self._module_id = "compliance_analytics"
    
    def assess_control(
        self,
        control_id: str,
        control_name: str,
        framework: str,
        test_results: Dict[str, Any],
    ) -> ControlAssessment:
        """Assess a control's effectiveness.
        
        Args:
            control_id: Control identifier
            control_name: Control name
            framework: Compliance framework
            test_results: Results of control testing
            
        Returns:
            ControlAssessment
        """
        logger.info(f"Assessing control {control_id} for {framework}")
        
        # Determine status based on test results
        effectiveness = test_results.get("effectiveness_score", random.uniform(0.6, 1.0))
        
        if effectiveness >= 0.9:
            status = ComplianceStatus.COMPLIANT
        elif effectiveness >= 0.7:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        assessment = ControlAssessment(
            control_id=control_id,
            control_name=control_name,
            framework=framework,
            status=status,
            effectiveness_score=effectiveness,
            last_tested=datetime.now(timezone.utc),
            next_test_date=datetime.now(timezone.utc) + timedelta(days=90),
            findings=test_results.get("findings", []),
            recommendations=self._generate_control_recommendations(status, effectiveness),
        )
        
        self._store.store_assessment(assessment)
        return assessment
    
    def get_framework_status(self, framework_name: str) -> Dict[str, Any]:
        """Get compliance status for a framework.
        
        Args:
            framework_name: Name of the framework
            
        Returns:
            Framework status data
        """
        frameworks = self._store.get_all_frameworks()
        framework = next((f for f in frameworks if framework_name.lower() in f.framework_name.lower()), None)
        
        if not framework:
            return {"error": "Framework not found"}
        
        return {
            "framework_id": framework.framework_id,
            "framework_name": framework.framework_name,
            "version": framework.version,
            "status": framework.status.value,
            "compliance_percentage": framework.compliance_percentage,
            "controls_count": len(framework.controls),
            "effective_controls": sum(1 for c in framework.controls if c.get("status") == "EFFECTIVE"),
            "findings_count": framework.findings_count,
            "open_findings": framework.open_findings,
            "critical_findings": framework.critical_findings,
            "last_audit": framework.last_audit_date.isoformat() if framework.last_audit_date else None,
            "next_audit": framework.next_audit_date.isoformat() if framework.next_audit_date else None,
        }
    
    def perform_gap_analysis(self, framework_name: str) -> Dict[str, Any]:
        """Perform compliance gap analysis.
        
        Args:
            framework_name: Framework to analyze
            
        Returns:
            Gap analysis results
        """
        logger.info(f"Performing gap analysis for {framework_name}")
        
        framework_status = self.get_framework_status(framework_name)
        
        if "error" in framework_status:
            return framework_status
        
        gaps = []
        if framework_status["compliance_percentage"] < 95:
            gaps.append({
                "category": "Compliance Coverage",
                "gap": f"Compliance at {framework_status['compliance_percentage']:.1f}%",
                "severity": "HIGH" if framework_status["compliance_percentage"] < 85 else "MEDIUM",
                "recommendation": "Complete missing control implementations",
            })
        
        if framework_status["open_findings"] > 0:
            gaps.append({
                "category": "Open Findings",
                "gap": f"{framework_status['open_findings']} open findings",
                "severity": "HIGH" if framework_status["critical_findings"] > 0 else "MEDIUM",
                "recommendation": "Remediate findings within SLA",
            })
        
        if framework_status["next_audit"]:
            days_until = (datetime.fromisoformat(framework_status["next_audit"]) - datetime.now(timezone.utc)).days
            if days_until < 30:
                gaps.append({
                    "category": "Audit Preparation",
                    "gap": f"Audit in {days_until} days",
                    "severity": "MEDIUM",
                    "recommendation": "Begin audit preparation activities",
                })
        
        return {
            "framework": framework_name,
            "overall_gap_score": 100 - framework_status["compliance_percentage"],
            "gaps_identified": len(gaps),
            "gaps": gaps,
            "compliance_percentage": framework_status["compliance_percentage"],
        }
    
    def track_regulatory_change(
        self,
        regulation: str,
        effective_date: datetime,
        requirements: List[str],
    ) -> Dict[str, Any]:
        """Track regulatory changes.
        
        Args:
            regulation: Regulation name
            effective_date: When regulation becomes effective
            requirements: List of requirements
            
        Returns:
            Change tracking data
        """
        days_until = (effective_date - datetime.now(timezone.utc)).days
        
        return {
            "regulation": regulation,
            "effective_date": effective_date.isoformat(),
            "days_until_effective": max(0, days_until),
            "requirements_count": len(requirements),
            "requirements": requirements,
            "impact_level": "HIGH" if days_until < 90 else "MEDIUM" if days_until < 180 else "LOW",
            "action_required": True,
            "status": "TRACKING",
        }
    
    def generate_compliance_report(
        self,
        framework_name: str,
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, Any]:
        """Generate compliance report.
        
        Args:
            framework_name: Framework to report on
            period_start: Report period start
            period_end: Report period end
            
        Returns:
            Compliance report data
        """
        logger.info(f"Generating compliance report for {framework_name}")
        
        framework_status = self.get_framework_status(framework_name)
        
        return {
            "report_metadata": {
                "framework": framework_name,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "executive_summary": {
                "compliance_status": framework_status.get("status", "UNKNOWN"),
                "compliance_percentage": framework_status.get("compliance_percentage", 0),
                "findings_total": framework_status.get("findings_count", 0),
                "findings_open": framework_status.get("open_findings", 0),
                "findings_critical": framework_status.get("critical_findings", 0),
            },
            "control_summary": {
                "total_controls": framework_status.get("controls_count", 0),
                "effective_controls": framework_status.get("effective_controls", 0),
                "controls_requiring_attention": framework_status.get("controls_count", 0) - framework_status.get("effective_controls", 0),
            },
            "recommendations": [
                "Continue regular control testing",
                "Remediate open findings within SLA",
                "Update documentation for audit readiness",
            ],
        }
    
    def calculate_compliance_score(self, framework_name: str) -> float:
        """Calculate overall compliance score.
        
        Args:
            framework_name: Framework to calculate for
            
        Returns:
            Compliance score (0-100)
        """
        framework_status = self.get_framework_status(framework_name)
        
        if "error" in framework_status:
            return 0.0
        
        base_score = framework_status.get("compliance_percentage", 0)
        
        # Adjust for open findings
        open_penalty = framework_status.get("open_findings", 0) * 0.5
        critical_penalty = framework_status.get("critical_findings", 0) * 2.0
        
        adjusted_score = max(0, base_score - open_penalty - critical_penalty)
        
        return round(adjusted_score, 2)
    
    def get_remediation_plan(self, framework_name: str) -> Dict[str, Any]:
        """Generate remediation plan for compliance gaps.
        
        Args:
            framework_name: Framework to generate plan for
            
        Returns:
            Remediation plan
        """
        framework_status = self.get_framework_status(framework_name)
        
        if "error" in framework_status:
            return framework_status
        
        plan_items = []
        
        # Critical findings
        if framework_status.get("critical_findings", 0) > 0:
            plan_items.append({
                "priority": "CRITICAL",
                "action": "Remediate critical findings immediately",
                "timeline": "Within 7 days",
                "owner": "CISO",
            })
        
        # Open findings
        if framework_status.get("open_findings", 0) > 0:
            plan_items.append({
                "priority": "HIGH",
                "action": f"Remediate {framework_status['open_findings']} open findings",
                "timeline": "Within 30 days",
                "owner": "Compliance Team",
            })
        
        # Control improvements
        compliance_gap = 100 - framework_status.get("compliance_percentage", 0)
        if compliance_gap > 5:
            plan_items.append({
                "priority": "MEDIUM",
                "action": "Implement missing controls",
                "timeline": "Within 90 days",
                "owner": "IT Security",
            })
        
        return {
            "framework": framework_name,
            "plan_items": plan_items,
            "estimated_completion": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        }
    
    def _generate_control_recommendations(self, status: ComplianceStatus, effectiveness: float) -> List[str]:
        """Generate recommendations based on control status."""
        recommendations = []
        
        if status == ComplianceStatus.NON_COMPLIANT:
            recommendations.append("Immediate remediation required")
            recommendations.append("Implement compensating controls")
            recommendations.append("Schedule emergency review")
        elif status == ComplianceStatus.PARTIAL:
            recommendations.append("Complete control implementation")
            recommendations.append("Increase testing frequency")
            recommendations.append("Document exceptions")
        else:
            recommendations.append("Continue regular monitoring")
            recommendations.append("Annual comprehensive review")
        
        return recommendations
    
    def get_compliance_overview(self) -> Dict[str, Any]:
        """Get overall compliance overview."""
        frameworks = self._store.get_all_frameworks()
        
        total_compliance = sum(f.compliance_percentage for f in frameworks) / len(frameworks) if frameworks else 0
        total_findings = sum(f.findings_count for f in frameworks)
        open_findings = sum(f.open_findings for f in frameworks)
        critical_findings = sum(f.critical_findings for f in frameworks)
        
        return {
            "overall_compliance": round(total_compliance, 2),
            "frameworks_tracked": len(frameworks),
            "compliant_frameworks": sum(1 for f in frameworks if f.status == ComplianceStatus.COMPLIANT),
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "framework_summary": [
                {
                    "name": f.framework_name,
                    "status": f.status.value,
                    "compliance": f.compliance_percentage,
                }
                for f in frameworks
            ],
        }


# Global singleton
_compliance_analytics: Optional[ComplianceAnalyticsModule] = None


def get_compliance_analytics_module(store: Optional[GovernanceStore] = None) -> ComplianceAnalyticsModule:
    """Get or create the singleton ComplianceAnalyticsModule instance."""
    global _compliance_analytics
    
    if _compliance_analytics is None:
        _compliance_analytics = ComplianceAnalyticsModule(store=store)
    return _compliance_analytics