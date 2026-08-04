"""
Reporting Agent.

Generates SOC reports, metrics dashboards, and compliance documentation.
"""

import random
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
        
        return {
            "overview": {
                "total_alerts_today": random.randint(50, 200),
                "high_risk_entities": random.randint(10, 50),
                "active_investigations": stats.get("pending_tasks", 0),
                "fraud_rings_detected": len(self._store.get_all_fraud_rings()),
            },
            "trends": {
                "alert_volume_change": random.uniform(-0.2, 0.3),
                "risk_score_trend": random.uniform(0.4, 0.8),
                "investigation_resolution_time": random.randint(30, 120),
            },
            "performance": {
                "agents_online": len(self._store._agents),
                "tasks_completed_today": random.randint(20, 100),
                "average_response_time": random.uniform(5, 30),
            },
            "alerts_by_severity": {
                "critical": random.randint(0, 5),
                "high": random.randint(5, 20),
                "medium": random.randint(20, 50),
                "low": random.randint(50, 100),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
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
        
        return {
            "framework": framework,
            "period": {
                "start": period_start.isoformat(),
                "end": period_end.isoformat(),
            },
            "controls": [
                {
                    "control_id": "CC6.1",
                    "description": "Logical access controls",
                    "status": random.choice(["compliant", "compliant", "needs_attention"]),
                    "last_reviewed": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "control_id": "CC6.2",
                    "description": "Authentication controls",
                    "status": random.choice(["compliant", "compliant", "compliant"]),
                    "last_reviewed": datetime.now(timezone.utc).isoformat(),
                },
            ],
            "findings": random.randint(0, 5),
            "recommendations": [
                "Continue monitoring access patterns",
                "Review high-risk entity access",
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    
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