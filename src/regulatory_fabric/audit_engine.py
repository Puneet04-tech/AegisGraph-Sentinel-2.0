"""
Audit Automation Engine for Regulatory Fabric.

Automates audit preparation, execution, and reporting.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import threading
import hashlib
import json


@dataclass
class AuditPlan:
    """Audit execution plan."""
    plan_id: str
    regulation_id: str
    title: str
    scope: List[str]
    start_date: datetime
    end_date: datetime
    status: str = "DRAFT"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    auditor: str = "SYSTEM"


@dataclass
class AuditFinding:
    """Audit finding."""
    finding_id: str
    assessment_id: str
    control_id: Optional[str]
    severity: str
    title: str
    description: str
    evidence_ids: List[str] = field(default_factory=list)
    remediation_plan: str = ""
    owner: str = ""
    due_date: Optional[datetime] = None
    status: str = "OPEN"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None


class AuditAutomationEngine:
    """Automated audit engine.
    
    Plans, executes, and reports on compliance audits.
    """

    def __init__(self, store: Any, evidence_collector: Any):
        """Initialize the audit automation engine.
        
        Args:
            store: Compliance store instance
            evidence_collector: Evidence collector instance
        """
        self.store = store
        self.evidence_collector = evidence_collector
        self._audit_plans: Dict[str, AuditPlan] = {}
        self._audit_findings: Dict[str, AuditFinding] = {}
        self._lock = threading.Lock()

    def create_audit_plan(
        self,
        regulation_id: str,
        title: str,
        scope: List[str],
        start_date: datetime,
        end_date: datetime,
        auditor: str = "SYSTEM",
    ) -> Dict[str, Any]:
        """Create an audit plan.
        
        Args:
            regulation_id: Regulation to audit
            title: Audit title
            scope: List of control IDs in scope
            start_date: Audit start date
            end_date: Audit end date
            auditor: Assigned auditor
            
        Returns:
            Created audit plan
        """
        regulation = self.store.get_regulation(regulation_id)
        if not regulation:
            return {"error": "Regulation not found"}
        
        plan = AuditPlan(
            plan_id=hashlib.md5(f"{regulation_id}{title}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16],
            regulation_id=regulation_id,
            title=title,
            scope=scope,
            start_date=start_date,
            end_date=end_date,
            auditor=auditor,
        )
        
        with self._lock:
            self._audit_plans[plan.plan_id] = plan
        
        return {
            "plan_id": plan.plan_id,
            "regulation_id": plan.regulation_id,
            "title": plan.title,
            "scope": plan.scope,
            "start_date": plan.start_date.isoformat(),
            "end_date": plan.end_date.isoformat(),
            "status": plan.status,
            "auditor": plan.auditor,
        }

    def execute_audit(self, plan_id: str) -> Dict[str, Any]:
        """Execute an audit plan.
        
        Args:
            plan_id: Audit plan ID
            
        Returns:
            Audit execution results
        """
        plan = self._audit_plans.get(plan_id)
        if not plan:
            return {"error": "Audit plan not found"}
        
        plan.status = "IN_PROGRESS"
        results = {
            "plan_id": plan_id,
            "controls_tested": 0,
            "controls_passed": 0,
            "controls_failed": 0,
            "findings": [],
            "evidence_collected": 0,
        }
        
        for control_id in plan.scope:
            control = self.store.get_control(control_id)
            if not control:
                continue
            
            results["controls_tested"] += 1
            
            # Test control
            test_result = self._test_control(control_id)
            
            if test_result["passed"]:
                results["controls_passed"] += 1
            else:
                results["controls_failed"] += 1
                results["findings"].append(test_result["finding"])
            
            # Collect evidence
            evidence_job = self.evidence_collector.collect_evidence(
                control_id=control_id,
                evidence_type="AUDIT_TEST",
                description=f"Audit test for {control.get('control_name', control_id)}",
            )
            if evidence_job.status == "COMPLETED":
                results["evidence_collected"] += 1
        
        # Create assessment
        assessment = {
            "assessment_id": str(hashlib.md5(f"{plan_id}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16]),
            "regulation_id": plan.regulation_id,
            "assessment_date": datetime.now(timezone.utc),
            "status": "COMPLETED",
            "overall_score": (results["controls_passed"] / results["controls_tested"] * 100) if results["controls_tested"] > 0 else 0,
            "controls_assessed": results["controls_tested"],
            "controls_passed": results["controls_passed"],
            "controls_failed": results["controls_failed"],
            "findings": results["findings"],
            "assessor": plan.auditor,
        }
        
        self.store.add_assessment(assessment)
        plan.status = "COMPLETED"
        
        return {
            **results,
            "assessment_id": assessment["assessment_id"],
            "score": assessment["overall_score"],
        }

    def _test_control(self, control_id: str) -> Dict[str, Any]:
        """Test a control and return results.
        
        Args:
            control_id: Control to test
            
        Returns:
            Test result
        """
        control = self.store.get_control(control_id)
        
        # Check control status
        status = control.get("status", "UNDER_REVIEW")
        
        if status == "COMPLIANT":
            return {"passed": True}
        
        finding = {
            "finding_id": str(hashlib.md5(f"{control_id}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16]),
            "control_id": control_id,
            "severity": "HIGH" if status == "NON_COMPLIANT" else "MEDIUM",
            "title": f"Control {control_id} not compliant",
            "description": f"Control status is {status}",
            "remediation_plan": "Review and remediate control",
        }
        
        return {"passed": False, "finding": finding}

    def generate_audit_report(
        self,
        plan_id: str,
        format: str = "json",
    ) -> Dict[str, Any]:
        """Generate an audit report.
        
        Args:
            plan_id: Audit plan ID
            format: Report format (json, pdf, html)
            
        Returns:
            Generated report data
        """
        plan = self._audit_plans.get(plan_id)
        if not plan:
            return {"error": "Audit plan not found"}
        
        regulation = self.store.get_regulation(plan.regulation_id)
        assessments = self.store.list_assessments(regulation_id=plan.regulation_id)
        
        # Calculate summary statistics
        total_controls = len(plan.scope)
        passed = len([a for a in assessments if a.get("controls_passed", 0) > 0])
        failed = len([a for a in assessments if a.get("controls_failed", 0) > 0])
        
        return {
            "report_id": str(hashlib.md5(f"report{plan_id}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16]),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "plan": {
                "plan_id": plan.plan_id,
                "title": plan.title,
                "regulation": regulation.get("name") if regulation else "Unknown",
                "start_date": plan.start_date.isoformat(),
                "end_date": plan.end_date.isoformat(),
                "auditor": plan.auditor,
            },
            "summary": {
                "total_controls": total_controls,
                "controls_tested": passed + failed,
                "controls_passed": passed,
                "controls_failed": failed,
                "pass_rate": (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0,
            },
            "assessments": assessments,
            "format": format,
        }

    def schedule_audit(
        self,
        regulation_id: str,
        frequency_days: int = 90,
    ) -> Dict[str, Any]:
        """Schedule recurring audits.
        
        Args:
            regulation_id: Regulation to audit
            frequency_days: Audit frequency in days
            
        Returns:
            Schedule details
        """
        schedule_id = hashlib.md5(f"schedule{regulation_id}{frequency_days}".encode()).hexdigest()[:16]
        
        controls = self.store.get_controls_for_regulation(regulation_id)
        control_ids = [c.get("control_id") for c in controls]
        
        next_audit = datetime.now(timezone.utc) + timedelta(days=frequency_days)
        
        return {
            "schedule_id": schedule_id,
            "regulation_id": regulation_id,
            "frequency_days": frequency_days,
            "controls_in_scope": len(control_ids),
            "next_audit_date": next_audit.isoformat(),
        }

    def get_upcoming_deadlines(
        self,
        days_ahead: int = 30,
    ) -> List[Dict[str, Any]]:
        """Get upcoming audit deadlines.
        
        Args:
            days_ahead: Number of days to look ahead
            
        Returns:
            List of upcoming deadlines
        """
        now = datetime.now(timezone.utc)
        deadline = now + timedelta(days=days_ahead)
        
        deadlines = []
        
        # Check control test dates
        for ctrl in self.store.controls.values():
            next_test = ctrl.get("next_test")
            if next_test:
                if isinstance(next_test, str):
                    next_test = datetime.fromisoformat(next_test)
                if now <= next_test <= deadline:
                    deadlines.append({
                        "type": "control_test",
                        "entity_id": ctrl.get("control_id"),
                        "entity_name": ctrl.get("control_name"),
                        "due_date": next_test.isoformat(),
                        "days_until": (next_test - now).days,
                    })
        
        # Check assessment schedules
        for assess in self.store.assessments.values():
            next_assess = assess.get("next_assessment")
            if next_assess:
                if isinstance(next_assess, str):
                    next_assess = datetime.fromisoformat(next_assess)
                if now <= next_assess <= deadline:
                    deadlines.append({
                        "type": "assessment",
                        "entity_id": assess.get("assessment_id"),
                        "regulation_id": assess.get("regulation_id"),
                        "due_date": next_assess.isoformat(),
                        "days_until": (next_assess - now).days,
                    })
        
        return sorted(deadlines, key=lambda x: x["days_until"])

    def get_audit_dashboard(self) -> Dict[str, Any]:
        """Get audit dashboard data."""
        plans = list(self._audit_plans.values())
        assessments = list(self.store.assessments.values())
        
        status_counts = {"DRAFT": 0, "IN_PROGRESS": 0, "COMPLETED": 0}
        for plan in plans:
            status_counts[plan.status] = status_counts.get(plan.status, 0) + 1
        
        return {
            "total_plans": len(plans),
            "plans_by_status": status_counts,
            "total_assessments": len(assessments),
            "average_score": sum(a.get("overall_score", 0) for a in assessments) / len(assessments) if assessments else 0,
            "upcoming_deadlines": self.get_upcoming_deadlines(30),
            "recent_audits": [
                {
                    "plan_id": p.plan_id,
                    "title": p.title,
                    "status": p.status,
                    "end_date": p.end_date.isoformat(),
                }
                for p in sorted(plans, key=lambda x: x.end_date, reverse=True)[:5]
            ],
        }


def get_audit_engine() -> AuditAutomationEngine:
    """Get the global audit engine instance."""
    from .store import get_compliance_store
    from .evidence_collector import get_evidence_collector
    
    store = get_compliance_store()
    evidence_collector = get_evidence_collector()
    return AuditAutomationEngine(store, evidence_collector)