"""
Reporting Agent.

Generates SOC reports, metrics dashboards, and compliance documentation.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    AgentTask,
    AgentType,
    TaskPriority,
    InvestigationStatus,
    SOCReport,
)
from .store import SOCStore, get_soc_store

logger = logging.getLogger(__name__)


class ReportingAgent:
    """Reporting Agent for SOC reporting and analytics.
    
    Capabilities:
        - SOC summary report generation
        - Metrics calculation and tracking
        - Trend analysis
        - Compliance reporting
        - Executive dashboard data
    """
    
    #: Risk score at or above which an investigated entity is counted as high
    #: risk on the dashboard.
    HIGH_RISK_THRESHOLD = 0.7

    #: Severity labels recognised on stored threat reports, in the order they
    #: are presented on the dashboard.
    SEVERITY_LEVELS = ("critical", "high", "medium", "low")

    #: Controls assessed by `generate_compliance_report`, keyed by framework.
    #: Each entry names the control and the store-backed signal that evidences
    #: it. A control with no available signal is reported as not assessed
    #: rather than as compliant.
    COMPLIANCE_CONTROLS = {
        "SOC2": (
            ("CC6.1", "Logical access controls", "access_investigations"),
            ("CC6.2", "Authentication controls", "authentication_threats"),
            ("CC7.2", "Security monitoring", "monitoring_coverage"),
            ("CC7.3", "Incident evaluation and response", "incident_resolution"),
        ),
        "PCI-DSS": (
            ("10.2", "Audit trail for access to cardholder data", "monitoring_coverage"),
            ("12.10", "Incident response plan execution", "incident_resolution"),
        ),
    }

    #: Proportion of investigations left unresolved above which a monitoring or
    #: response control is reported as needing attention.
    CONTROL_ATTENTION_THRESHOLD = 0.25

    def __init__(self, store: Optional[SOCStore] = None):
        """Initialize the reporting agent.

        Args:
            store: Optional SOC store
        """
        self._store = store or get_soc_store()
        self._agent_id = "reporting_agent"
    
    def generate_summary_report(
        self,
        period_start: datetime,
        period_end: datetime,
        report_type: str = "daily",
    ) -> SOCReport:
        """Generate a SOC summary report.
        
        Args:
            period_start: Report period start
            period_end: Report period end
            report_type: Type of report (daily, weekly, monthly)
            
        Returns:
            SOCReport
        """
        logger.info(f"Generating {report_type} summary report")
        
        # Calculate metrics
        metrics = self._calculate_metrics(period_start, period_end)
        
        # Get threats identified
        threats = self._get_threats_summary(period_start, period_end)
        
        # Get investigations summary
        investigations = self._get_investigations_summary(period_start, period_end)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(metrics, threats, investigations)
        
        report = SOCReport(
            report_type=report_type,
            period_start=period_start,
            period_end=period_end,
            summary=self._generate_summary_text(metrics, threats, investigations),
            metrics=metrics,
            threats_identified=threats,
            investigations_summary=investigations,
            recommendations=recommendations,
            generated_by=self._agent_id,
        )
        
        # Store report
        self._store.store_report(report)
        
        logger.info(f"Report generated: {report.report_id}")
        return report
    
    def generate_executive_dashboard(self) -> Dict[str, Any]:
        """Generate executive dashboard data.
        
        Returns:
            Dashboard data
        """
        stats = self._store.get_stats()

        # Every figure below is counted from the store over an explicit window.
        # Alert volumes, high-risk entity counts, trend deltas, task throughput
        # and the severity breakdown were all `random` draws, so the executive
        # dashboard reported a different security posture on each refresh and
        # the severity buckets never summed to the alert total.
        now = datetime.now(timezone.utc)
        day_start = now - timedelta(days=1)
        previous_day_start = day_start - timedelta(days=1)

        todays_threats = self._store.get_threats_between(day_start, now)
        previous_threats = self._store.get_threats_between(previous_day_start, day_start)

        todays_investigations = self._store.get_investigations_between(day_start, now)
        risk_scores = [inv.risk_score for inv in todays_investigations]

        investigation_tasks = self._store.get_tasks_by_agent(AgentType.INVESTIGATION)

        completed_today = []
        resolution_minutes = []
        response_minutes = []

        for task in investigation_tasks:
            started_at = task.started_at
            completed_at = task.completed_at

            if completed_at is not None and day_start <= completed_at <= now:
                completed_today.append(task)
                # A task completed without a recorded start contributes to
                # throughput but cannot contribute a duration.
                if started_at is not None:
                    resolution_minutes.append(
                        (completed_at - started_at).total_seconds() / 60
                    )

            if started_at is not None and day_start <= started_at <= now:
                response_minutes.append(
                    (started_at - task.created_at).total_seconds() / 60
                )

        # High-risk entities are counted distinctly; one entity investigated
        # repeatedly is one entity at risk, not several.
        high_risk_entities = {
            inv.entity_id
            for inv in todays_investigations
            if inv.risk_score >= self.HIGH_RISK_THRESHOLD
        }

        return {
            "overview": {
                "total_alerts_today": len(todays_threats),
                "high_risk_entities": len(high_risk_entities),
                "active_investigations": stats.get("pending_tasks", 0),
                "fraud_rings_detected": len(self._store.get_all_fraud_rings()),
            },
            "trends": {
                "alert_volume_change": self._change_ratio(
                    len(todays_threats), len(previous_threats)
                ),
                "risk_score_trend": (
                    round(sum(risk_scores) / len(risk_scores), 4) if risk_scores else 0.0
                ),
                "investigation_resolution_time": (
                    round(sum(resolution_minutes) / len(resolution_minutes), 2)
                    if resolution_minutes else 0.0
                ),
            },
            "performance": {
                "agents_online": len(self._store.get_all_agents()),
                "tasks_completed_today": len(completed_today),
                "average_response_time": (
                    round(sum(response_minutes) / len(response_minutes), 2)
                    if response_minutes else 0.0
                ),
            },
            "alerts_by_severity": self._count_by_severity(todays_threats),
            "timestamp": now.isoformat(),
        }

    @staticmethod
    def _change_ratio(current: int, previous: int) -> float:
        """Ratio of change between two counts.

        Returns 0.0 when there is no prior period to compare against, matching
        how `generate_threat_trend_report` treats the same situation, rather
        than reporting an infinite increase.
        """
        if not previous:
            return 0.0
        return round((current - previous) / previous, 4)

    def _count_by_severity(self, threats: List[Any]) -> Dict[str, int]:
        """Count threat reports into severity buckets.

        Unrecognised severities are counted under ``low`` so the buckets always
        sum to the reported alert total; the random buckets they replace could
        not be reconciled against it at all.
        """
        counts = {level: 0 for level in self.SEVERITY_LEVELS}

        for threat in threats:
            level = str(getattr(threat, "severity", "") or "").strip().lower()
            if level in counts:
                counts[level] += 1
            else:
                counts["low"] += 1

        return counts
    
    def generate_compliance_report(
        self,
        framework: str = "SOC2",
        period_start: datetime = None,
        period_end: datetime = None,
    ) -> Dict[str, Any]:
        """Generate compliance report.
        
        Args:
            framework: Compliance framework (SOC2, PCI-DSS, etc.)
            period_start: Optional period start
            period_end: Optional period end
            
        Returns:
            Compliance report data
        """
        period_end = period_end or datetime.now(timezone.utc)
        period_start = period_start or (period_end - timedelta(days=30))
        
        # Control status is evaluated against stored activity for the period.
        # Each status was previously a `random.choice` over a weighted list, so
        # a control could be reported as compliant on one run and needing
        # attention on the next with no change in the underlying system, and
        # `findings` was a `random.randint(0, 5)` unconnected to the controls
        # above it. An attestation produced this way asserts a compliance
        # posture that was never assessed.
        reviewed_at = datetime.now(timezone.utc).isoformat()
        definitions = self.COMPLIANCE_CONTROLS.get(framework)

        if definitions is None:
            logger.warning(
                "No control definitions for framework %s; reporting as not assessed",
                framework,
            )
            definitions = ()

        signals = self._gather_control_signals(period_start, period_end)

        controls = []
        for control_id, description, signal_name in definitions:
            status, basis = self._evaluate_control(signal_name, signals)
            controls.append({
                "control_id": control_id,
                "description": description,
                "status": status,
                "basis": basis,
                "last_reviewed": reviewed_at,
            })

        findings = [
            {
                "control_id": control["control_id"],
                "description": control["description"],
                "detail": control["basis"],
            }
            for control in controls
            if control["status"] == "needs_attention"
        ]

        return {
            "framework": framework,
            "period": {
                "start": period_start.isoformat(),
                "end": period_end.isoformat(),
            },
            "controls": controls,
            # Reported as the count of controls that actually failed, and the
            # findings themselves so the number can be reconciled.
            "findings": len(findings),
            "findings_detail": findings,
            "controls_assessed": sum(
                1 for c in controls if c["status"] != "not_assessed"
            ),
            "recommendations": self._compliance_recommendations(controls),
            "generated_at": reviewed_at,
        }

    def _gather_control_signals(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, Any]:
        """Collect the store-backed signals that compliance controls rest on."""
        investigations = self._store.get_investigations_between(period_start, period_end)
        threats = self._store.get_threats_between(period_start, period_end)

        unresolved = [
            inv for inv in investigations
            if inv.status != InvestigationStatus.CLOSED
        ]

        authentication_threats = [
            threat for threat in threats
            if "auth" in threat.threat_type.lower()
            or "credential" in threat.threat_type.lower()
        ]

        return {
            "investigation_count": len(investigations),
            "unresolved_count": len(unresolved),
            "unresolved_ratio": (
                len(unresolved) / len(investigations) if investigations else 0.0
            ),
            "threat_count": len(threats),
            "authentication_threat_count": len(authentication_threats),
            "high_risk_count": sum(
                1 for inv in investigations if inv.risk_score >= self.HIGH_RISK_THRESHOLD
            ),
        }

    def _evaluate_control(
        self,
        signal_name: str,
        signals: Dict[str, Any],
    ) -> tuple:
        """Evaluate one control against the gathered signals.

        Returns:
            Tuple of (status, basis). A control whose evidencing signal recorded
            no activity is reported as ``not_assessed`` rather than as
            ``compliant``: an absence of evidence is not evidence of control
            effectiveness, and reporting it as compliant is what made the
            original attestation unsound.
        """
        if signal_name in ("access_investigations", "incident_resolution"):
            if not signals["investigation_count"]:
                return "not_assessed", "No investigations recorded in the period"

            ratio = signals["unresolved_ratio"]
            if ratio > self.CONTROL_ATTENTION_THRESHOLD:
                return (
                    "needs_attention",
                    f"{signals['unresolved_count']} of {signals['investigation_count']} "
                    f"investigations remain unresolved ({ratio:.0%})",
                )
            return (
                "compliant",
                f"{signals['investigation_count'] - signals['unresolved_count']} of "
                f"{signals['investigation_count']} investigations resolved",
            )

        if signal_name == "authentication_threats":
            if not signals["threat_count"]:
                return "not_assessed", "No threat reports recorded in the period"

            if signals["authentication_threat_count"]:
                return (
                    "needs_attention",
                    f"{signals['authentication_threat_count']} authentication-related "
                    "threats reported in the period",
                )
            return (
                "compliant",
                f"No authentication-related threats among {signals['threat_count']} reports",
            )

        if signal_name == "monitoring_coverage":
            if not signals["threat_count"] and not signals["investigation_count"]:
                return "not_assessed", "No monitoring activity recorded in the period"
            return (
                "compliant",
                f"{signals['threat_count']} threat reports and "
                f"{signals['investigation_count']} investigations recorded",
            )

        return "not_assessed", f"No signal available for {signal_name}"

    def _compliance_recommendations(
        self,
        controls: List[Dict[str, Any]],
    ) -> List[str]:
        """Derive recommendations from the controls that actually failed."""
        recommendations = []

        for control in controls:
            if control["status"] == "needs_attention":
                recommendations.append(
                    f"Remediate {control['control_id']} ({control['description']}): "
                    f"{control['basis']}"
                )

        unassessed = [c for c in controls if c["status"] == "not_assessed"]
        if unassessed:
            recommendations.append(
                "Extend monitoring coverage so the following controls can be "
                "evidenced: " + ", ".join(c["control_id"] for c in unassessed)
            )

        if not recommendations:
            recommendations.append("Continue monitoring access patterns")

        return recommendations
    
    def generate_threat_trend_report(self, days: int = 30) -> Dict[str, Any]:
        """Generate threat trend analysis from stored threat reports.

        Args:
            days: Number of days to analyze

        Returns:
            Trend analysis data
        """
        now = datetime.now(timezone.utc)
        current_start = now - timedelta(days=days)
        previous_start = current_start - timedelta(days=days)

        current_threats = self._store.get_threats_between(current_start, now)
        previous_threats = self._store.get_threats_between(previous_start, current_start)

        current_volume = len(current_threats)
        previous_volume = len(previous_threats)
        change_percent = (
            (current_volume - previous_volume) / previous_volume
            if previous_volume else 0.0
        )

        threat_counts: Dict[str, int] = {}
        for threat in current_threats:
            threat_counts[threat.threat_type] = threat_counts.get(threat.threat_type, 0) + 1

        top_threats = [
            {"type": threat_type, "count": count}
            for threat_type, count in sorted(
                threat_counts.items(), key=lambda item: item[1], reverse=True
            )[:5]
        ]

        if change_percent > 0.05:
            predicted_trend = "increasing"
        elif change_percent < -0.05:
            predicted_trend = "decreasing"
        else:
            predicted_trend = "stable"

        confidences = [threat.confidence for threat in current_threats]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        return {
            "period_days": days,
            "threat_volume": {
                "current": current_volume,
                "previous": previous_volume,
                "change_percent": change_percent,
            },
            "top_threats": top_threats,
            "geographic_distribution": [],
            "predicted_trend": predicted_trend,
            "confidence": avg_confidence,
        }
    
    def create_reporting_task(
        self,
        report_type: str,
        priority: TaskPriority = TaskPriority.MEDIUM,
    ) -> AgentTask:
        """Create a reporting task.
        
        Args:
            report_type: Type of report to generate
            priority: Task priority
            
        Returns:
            AgentTask
        """
        task = AgentTask(
            agent_type=AgentType.REPORTING,
            title=f"Generate {report_type} Report",
            description=f"Generate {report_type} summary report for SOC",
            priority=priority,
            context={
                "report_type": report_type,
                "type": "reporting",
            },
        )
        
        self._store.store_task(task)
        logger.info(f"Created reporting task: {task.task_id}")
        
        return task
    
    def get_recent_reports(self, hours: int = 24) -> List[SOCReport]:
        """Get recent reports."""
        return self._store.get_recent_reports(hours)
    
    def _calculate_metrics(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, float]:
        """Calculate SOC metrics from stored activity within the period.

        All values are derived from the SOC store; no fabricated data.
        Metrics that require tracking not present in the store (e.g. false
        positive and detection rates) are reported as zero when unavailable.
        """
        threats = self._store.get_threats_between(period_start, period_end)
        investigations = self._store.get_investigations_between(period_start, period_end)
        fraud_rings = [
            ring for ring in self._store.get_all_fraud_rings()
            if period_start <= ring.created_at <= period_end
        ]

        completed_tasks = [
            task for task in self._store.get_tasks_by_agent(AgentType.INVESTIGATION)
            if task.started_at is not None
            and task.completed_at is not None
            and period_start <= task.completed_at <= period_end
        ]

        resolution_minutes = [
            (task.completed_at - task.started_at).total_seconds() / 60
            for task in completed_tasks
        ]
        analyst_hours = sum(
            (task.completed_at - task.started_at).total_seconds() / 3600
            for task in completed_tasks
        )

        return {
            "total_alerts": float(len(threats)),
            "alerts_processed": float(len(threats)),
            "high_risk_alerts": float(
                sum(1 for t in threats if t.severity.upper() in ("HIGH", "CRITICAL"))
            ),
            "investigations_started": float(len(investigations)),
            "investigations_completed": float(
                sum(1 for inv in investigations if inv.status == InvestigationStatus.CLOSED)
            ),
            "fraud_rings_detected": float(len(fraud_rings)),
            "average_resolution_time_minutes": (
                sum(resolution_minutes) / len(resolution_minutes)
                if resolution_minutes else 0.0
            ),
            "analyst_hours": analyst_hours,
            "false_positive_rate": 0.0,
            "detection_rate": 0.0,
        }
    
    def _get_threats_summary(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> List[Dict[str, Any]]:
        """Get threats summary aggregated from stored threat reports."""
        threats = self._store.get_threats_between(period_start, period_end)

        grouped: Dict[str, List[str]] = {}
        for threat in threats:
            grouped.setdefault(threat.threat_type, []).append(threat.severity)

        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        return [
            {
                "threat_type": threat_type,
                "count": len(severities),
                "severity": max(severities, key=lambda s: severity_rank.get(s, 0)),
            }
            for threat_type, severities in sorted(grouped.items())
        ]
    
    def _get_investigations_summary(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, Any]:
        """Get investigations summary aggregated from stored investigations."""
        investigations = self._store.get_investigations_between(period_start, period_end)

        by_status: Dict[str, int] = {}
        for inv in investigations:
            key = inv.status.value.lower()
            by_status[key] = by_status.get(key, 0) + 1

        risk_scores = [inv.risk_score for inv in investigations]

        return {
            "total_investigations": len(investigations),
            "by_status": {
                "new": by_status.get("new", 0),
                "in_progress": by_status.get("in_progress", 0),
                "requires_review": by_status.get("requires_review", 0),
                "escalated": by_status.get("escalated", 0),
                "closed": by_status.get("closed", 0),
            },
            "average_risk_score": (
                sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
            ),
            "high_risk_count": sum(1 for score in risk_scores if score >= 0.7),
        }
    
    def _generate_recommendations(
        self,
        metrics: Dict[str, float],
        threats: List[Dict[str, Any]],
        investigations: Dict[str, Any],
    ) -> List[str]:
        """Generate report recommendations."""
        recommendations = []
        
        if metrics.get("false_positive_rate", 0) > 0.3:
            recommendations.append("Consider tuning detection rules to reduce false positives")
        
        if investigations.get("high_risk_count", 0) > 10:
            recommendations.append("Review high-risk investigations for pattern analysis")
        
        if metrics.get("average_resolution_time_minutes", 0) > 120:
            recommendations.append("Consider adding analyst resources to reduce resolution time")
        
        recommendations.append("Continue monitoring for emerging threats")
        recommendations.append("Update threat intelligence feeds regularly")
        
        return recommendations
    
    def _generate_summary_text(
        self,
        metrics: Dict[str, float],
        threats: List[Dict[str, Any]],
        investigations: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate summary text."""
        return {
            "highlights": [
                f"Processed {metrics.get('total_alerts', 0)} alerts",
                f"Detected {metrics.get('fraud_rings_detected', 0)} fraud rings",
                f"Average resolution time: {metrics.get('average_resolution_time_minutes', 0):.0f} minutes",
            ],
            "key_concerns": [
                f"{len(threats)} threat types active",
                f"{investigations.get('high_risk_count', 0)} high-risk investigations pending",
            ],
        }


# Global singleton
_reporting_agent: Optional[ReportingAgent] = None


def get_reporting_agent(store: Optional[SOCStore] = None) -> ReportingAgent:
    """Get or create the singleton ReportingAgent instance."""
    global _reporting_agent
    
    if _reporting_agent is None:
        _reporting_agent = ReportingAgent(store=store)
    return _reporting_agent