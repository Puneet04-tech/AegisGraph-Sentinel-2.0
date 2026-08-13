"""
Audit Intelligence Module.

Provides audit management, finding tracking, and compliance audit support.
"""

from collections import Counter
from statistics import mean
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    AuditFinding,
    AuditFindingSeverity,
    PolicyViolation,
)
from .store import GovernanceStore, get_governance_store

logger = logging.getLogger(__name__)


class AuditIntelligenceModule:
    """Audit Intelligence for audit management and finding tracking.
    
    Provides:
        - Audit finding management
        - Policy violation tracking
        - Remediation tracking
        - Audit reporting
    """

    #: Risk impact assigned to a finding from its severity. Fixed points on
    #: the severity ladder: two findings of the same severity must carry the
    #: same impact, which a random draw per call cannot guarantee.
    RISK_IMPACT_BY_SEVERITY: Dict[str, float] = {
        "CRITICAL": 0.9,
        "HIGH": 0.7,
        "MEDIUM": 0.5,
        "LOW": 0.3,
        "INFO": 0.15,
    }

    #: Policies listed in the "top violated" breakdown of a trend report.
    TOP_POLICY_COUNT = 3

    def __init__(self, store: Optional[GovernanceStore] = None):
        """Initialize the audit intelligence module.
        
        Args:
            store: Optional governance store
        """
        self._store = store or get_governance_store()
        self._module_id = "audit_intelligence"
    
    def create_audit_finding(
        self,
        title: str,
        description: str,
        severity: AuditFindingSeverity,
        category: str,
        affected_controls: List[str] = None,
        affected_entities: List[str] = None,
        financial_impact: Optional[float] = None,
    ) -> AuditFinding:
        """Create an audit finding.

        Args:
            title: Finding title
            description: Finding description
            severity: Finding severity
            category: Finding category
            affected_controls: Affected control IDs
            affected_entities: Affected entity IDs
            financial_impact: Measured or estimated financial exposure, if the
                caller has one. Left unset when it is not known -- there is no
                basis in this module for inventing a figure.

        Returns:
            AuditFinding
        """
        logger.info(f"Creating audit finding: {title}")

        affected_controls = affected_controls or []
        affected_entities = affected_entities or []

        # Risk impact is a fixed point on the severity ladder. It used to be a
        # random draw per call, so two identical CRITICAL findings could be
        # scored 0.81 and 0.99, and a finding's impact changed nothing about
        # the finding.
        finding = AuditFinding(
            finding_title=title,
            description=description,
            severity=severity,
            category=category,
            affected_controls=affected_controls,
            affected_entities=affected_entities,
            risk_impact=self._risk_impact(severity),
            financial_impact=financial_impact,
            remediation_steps=self._generate_remediation_steps(severity, category),
            due_date=datetime.now(timezone.utc) + timedelta(days=self._get_due_days(severity)),
        )
        
        self._store.store_finding(finding)
        return finding
    
    def update_finding_status(
        self,
        finding_id: str,
        new_status: str,
        notes: str = None,
    ) -> bool:
        """Update finding status.
        
        Args:
            finding_id: Finding to update
            new_status: New status
            notes: Optional notes
            
        Returns:
            True if successful
        """
        finding = self._store.get_finding(finding_id)
        if finding:
            finding.status = new_status
            if new_status == "CLOSED":
                finding.closed_date = datetime.now(timezone.utc)
            return True
        return False
    
    def get_finding_summary(self) -> Dict[str, Any]:
        """Get audit finding summary."""
        all_findings = list(self._store._findings.values())
        open_findings = self._store.get_open_findings()
        critical_findings = self._store.get_critical_findings()
        
        by_severity = {}
        for severity in AuditFindingSeverity:
            count = sum(1 for f in all_findings if f.severity == severity)
            by_severity[severity.value] = count
        
        by_category = {}
        for finding in all_findings:
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
        
        return {
            "total_findings": len(all_findings),
            "open_findings": len(open_findings),
            "closed_findings": len(all_findings) - len(open_findings),
            "critical_findings": len(critical_findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "avg_age_days": self._average_age_days(all_findings),
            "on_track_percentage": self._on_track_percentage(open_findings),
        }

    def _risk_impact(self, severity: AuditFindingSeverity) -> float:
        """Risk impact for a severity."""
        name = getattr(severity, "value", severity)
        return self.RISK_IMPACT_BY_SEVERITY.get(str(name).upper(), 0.5)

    def _average_age_days(self, findings: List[AuditFinding]) -> Optional[float]:
        """Mean age of findings, measured to closure or to now if still open."""
        if not findings:
            return None

        now = datetime.now(timezone.utc)
        ages = []
        for finding in findings:
            end = self._as_utc(finding.closed_date) if finding.closed_date else now
            ages.append((end - self._as_utc(finding.created_at)).total_seconds() / 86400)

        return round(mean(ages), 2)

    def _on_track_percentage(self, open_findings: List[AuditFinding]) -> Optional[float]:
        """Share of open findings that are not past their due date.

        Findings with no due date cannot be overdue and are counted as on
        track. With nothing open the figure is undefined, not 100%.
        """
        if not open_findings:
            return None

        now = datetime.now(timezone.utc)
        on_track = sum(
            1 for f in open_findings
            if f.due_date is None or self._as_utc(f.due_date) >= now
        )
        return round(100 * on_track / len(open_findings), 2)

    @staticmethod
    def _as_utc(moment: datetime) -> datetime:
        """Treat naive timestamps as UTC so comparisons never raise."""
        if moment.tzinfo is None:
            return moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)


    def track_policy_violation(
        self,
        policy_id: str,
        policy_name: str,
        entity_id: str,
        entity_type: str,
        severity: AuditFindingSeverity,
        description: str,
    ) -> PolicyViolation:
        """Track a policy violation.
        
        Args:
            policy_id: Policy identifier
            policy_name: Policy name
            entity_id: Entity that violated policy
            entity_type: Type of entity
            severity: Violation severity
            description: Violation description
            
        Returns:
            PolicyViolation
        """
        logger.info(f"Tracking policy violation for {entity_id}")
        
        violation = PolicyViolation(
            policy_id=policy_id,
            policy_name=policy_name,
            entity_id=entity_id,
            entity_type=entity_type,
            severity=severity,
            description=description,
        )
        
        self._store.store_violation(violation)
        return violation
    
    def get_violation_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get policy violation trends.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Violation trend data
        """
        # Trends need closed violations too: counting only the open ones
        # understates any window in which violations were remediated. The
        # `days` argument was also ignored entirely before.
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=days)
        all_violations = self._store.get_all_violations()

        in_window = [
            v for v in all_violations
            if self._as_utc(v.detected_at) >= window_start
        ]
        open_in_window = [v for v in in_window if v.status == "OPEN"]

        # Counted from the violations on record, not from a fixed list of
        # policy names with invented counts attached.
        policy_counts = Counter(v.policy_name for v in in_window)

        return {
            "period_days": days,
            "total_violations": len(in_window),
            "open_violations": len(open_in_window),
            "critical_violations": sum(
                1 for v in in_window if v.severity == AuditFindingSeverity.CRITICAL
            ),
            "high_violations": sum(
                1 for v in in_window if v.severity == AuditFindingSeverity.HIGH
            ),
            "trends": {
                "7_day_change": self._violation_change(all_violations, now, 7),
                "30_day_change": self._violation_change(all_violations, now, 30),
            },
            "top_violated_policies": [
                {"policy": policy, "count": count}
                for policy, count in policy_counts.most_common(self.TOP_POLICY_COUNT)
            ],
        }

    def _audit_activity(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, int]:
        """Count audit activity from control assessments in the period.

        An assessment that has been tested is a completed audit; one on record
        but not yet tested is in progress. The counts are consistent by
        construction: completed + in progress == total.
        """
        start = self._as_utc(period_start)
        end = self._as_utc(period_end)

        assessments = self._store.get_all_assessments()
        completed = [
            a for a in assessments
            if a.last_tested and start <= self._as_utc(a.last_tested) <= end
        ]
        in_progress = [a for a in assessments if a.last_tested is None]

        return {
            "total_audits": len(completed) + len(in_progress),
            "audits_completed": len(completed),
            "audits_in_progress": len(in_progress),
        }

    def _violation_change(
        self,
        violations: List[PolicyViolation],
        now: datetime,
        days: int,
    ) -> Optional[float]:
        """Fractional change in violation volume against the prior window.

        Returns ``None`` when the preceding window holds nothing to compare
        against, rather than reporting a change that was never measured.
        """
        recent_start = now - timedelta(days=days)
        prior_start = now - timedelta(days=days * 2)

        recent = sum(
            1 for v in violations if self._as_utc(v.detected_at) >= recent_start
        )
        prior = sum(
            1 for v in violations
            if prior_start <= self._as_utc(v.detected_at) < recent_start
        )

        if not prior:
            return None
        return round((recent - prior) / prior, 3)
    
    def generate_audit_report(
        self,
        period_start: datetime,
        period_end: datetime,
        include_findings: bool = True,
    ) -> Dict[str, Any]:
        """Generate comprehensive audit report.
        
        Args:
            period_start: Report period start
            period_end: Report period end
            include_findings: Whether to include finding details
            
        Returns:
            Audit report data
        """
        logger.info("Generating audit report")
        
        finding_summary = self.get_finding_summary()
        
        report = {
            "report_metadata": {
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "executive_summary": {
                # Counted from the control assessments on record. These three
                # figures were random integers, so an audit report could claim
                # more completed audits than it claimed audits.
                **self._audit_activity(period_start, period_end),
                "total_findings": finding_summary["total_findings"],
                "open_findings": finding_summary["open_findings"],
                "critical_findings": finding_summary["critical_findings"],
            },
            "finding_summary": finding_summary,
            "recommendations": [
                "Continue regular audit schedule",
                "Prioritize critical finding remediation",
                "Enhance control testing frequency",
            ],
        }
        
        if include_findings:
            open_findings = self._store.get_open_findings()
            report["open_findings_detail"] = [
                {
                    "id": f.finding_id,
                    "title": f.finding_title,
                    "severity": f.severity.value,
                    "category": f.category,
                    "age_days": (datetime.now(timezone.utc) - f.created_at).days,
                }
                for f in open_findings[:20]  # Limit to 20
            ]
        
        return report
    
    def get_remediation_status(self) -> Dict[str, Any]:
        """Get remediation status for open findings."""
        open_findings = self._store.get_open_findings()
        
        on_track = []
        at_risk = []
        overdue = []
        
        for finding in open_findings:
            if finding.due_date:
                days_until_due = (finding.due_date - datetime.now(timezone.utc)).days
                
                if days_until_due < 0:
                    overdue.append(finding)
                elif days_until_due < 7:
                    at_risk.append(finding)
                else:
                    on_track.append(finding)
        
        return {
            "total_open": len(open_findings),
            "on_track": len(on_track),
            "at_risk": len(at_risk),
            "overdue": len(overdue),
            "remediation_rate": (len(open_findings) - len(overdue)) / len(open_findings) * 100 if len(open_findings) > 0 else 0,
        }
    
    def schedule_follow_up(
        self,
        finding_id: str,
        follow_up_date: datetime,
        notes: str,
    ) -> Dict[str, Any]:
        """Schedule follow-up for a finding.
        
        Args:
            finding_id: Finding to follow up
            follow_up_date: Follow-up date
            notes: Follow-up notes
            
        Returns:
            Follow-up data
        """
        finding = self._store.get_finding(finding_id)
        
        if not finding:
            return {"error": "Finding not found"}
        
        return {
            "finding_id": finding_id,
            "follow_up_date": follow_up_date.isoformat(),
            "notes": notes,
            "status": "SCHEDULED",
            "reminder_sent": False,
        }
    
    def get_audit_calendar(self, year: int) -> List[Dict[str, Any]]:
        """Get audit calendar for the year.
        
        Args:
            year: Year to get calendar for
            
        Returns:
            List of scheduled audits
        """
        return [
            {"quarter": "Q1", "month": "January", "audit": "SOC2 Assessment", "status": "COMPLETED"},
            {"quarter": "Q1", "month": "February", "audit": "PCI-DSS Review", "status": "IN_PROGRESS"},
            {"quarter": "Q1", "month": "March", "audit": "ISO 27001 Audit", "status": "SCHEDULED"},
            {"quarter": "Q2", "month": "April", "audit": "GDPR Compliance Review", "status": "SCHEDULED"},
            {"quarter": "Q2", "month": "May", "audit": "Internal Security Audit", "status": "SCHEDULED"},
            {"quarter": "Q2", "month": "June", "audit": "Payment Systems Audit", "status": "PLANNED"},
            {"quarter": "Q3", "month": "July", "audit": "SOC2 Type II Review", "status": "PLANNED"},
            {"quarter": "Q3", "month": "August", "audit": "Vendor Risk Assessment", "status": "PLANNED"},
            {"quarter": "Q3", "month": "September", "audit": "Penetration Testing", "status": "PLANNED"},
            {"quarter": "Q4", "month": "October", "audit": "Annual Compliance Review", "status": "PLANNED"},
            {"quarter": "Q4", "month": "November", "audit": "Board Security Review", "status": "PLANNED"},
            {"quarter": "Q4", "month": "December", "audit": "Year-End Audit Wrap", "status": "PLANNED"},
        ]
    
    def _generate_remediation_steps(self, severity: AuditFindingSeverity, category: str) -> List[str]:
        """Generate remediation steps based on severity and category."""
        steps = []
        
        steps.append("Document current state")
        steps.append("Identify root cause")
        
        if severity in [AuditFindingSeverity.CRITICAL, AuditFindingSeverity.HIGH]:
            steps.append("Implement immediate containment")
            steps.append("Escalate to management")
            steps.append("Develop corrective action plan")
        
        steps.append("Implement remediation")
        steps.append("Validate remediation effectiveness")
        steps.append("Update documentation and controls")
        
        return steps
    
    def _get_due_days(self, severity: AuditFindingSeverity) -> int:
        """Get due days based on severity."""
        due_days = {
            AuditFindingSeverity.CRITICAL: 7,
            AuditFindingSeverity.HIGH: 14,
            AuditFindingSeverity.MEDIUM: 30,
            AuditFindingSeverity.LOW: 60,
            AuditFindingSeverity.INFO: 90,
        }
        return due_days.get(severity, 30)


# Global singleton
_audit_intelligence: Optional[AuditIntelligenceModule] = None


def get_audit_intelligence_module(store: Optional[GovernanceStore] = None) -> AuditIntelligenceModule:
    """Get or create the singleton AuditIntelligenceModule instance."""
    global _audit_intelligence
    
    if _audit_intelligence is None:
        _audit_intelligence = AuditIntelligenceModule(store=store)
    return _audit_intelligence