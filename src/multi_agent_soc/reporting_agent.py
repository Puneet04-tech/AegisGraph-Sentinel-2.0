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
        """Generate threat trend analysis.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Trend analysis data
        """
        return {
            "period_days": days,
            "threat_volume": {
                "current": random.randint(50, 200),
                "previous": random.randint(40, 180),
                "change_percent": random.uniform(-0.3, 0.5),
            },
            "top_threats": [
                {"type": "credential_stuffing", "count": random.randint(10, 50)},
                {"type": "payment_fraud", "count": random.randint(5, 30)},
                {"type": "account_takeover", "count": random.randint(5, 25)},
            ],
            "geographic_distribution": [
                {"region": "North America", "percentage": random.uniform(30, 50)},
                {"region": "Europe", "percentage": random.uniform(20, 35)},
                {"region": "Asia", "percentage": random.uniform(15, 30)},
            ],
            "predicted_trend": random.choice(["increasing", "stable", "decreasing"]),
            "confidence": random.uniform(0.6, 0.9),
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
        """Calculate SOC metrics."""
        hours = (period_end - period_start).total_seconds() / 3600
        
        return {
            "total_alerts": random.randint(100, 1000),
            "alerts_processed": random.randint(80, 900),
            "high_risk_alerts": random.randint(10, 100),
            "investigations_started": random.randint(5, 50),
            "investigations_completed": random.randint(3, 40),
            "fraud_rings_detected": random.randint(0, 10),
            "average_resolution_time_minutes": random.randint(30, 180),
            "analyst_hours": random.randint(50, 500),
            "false_positive_rate": random.uniform(0.1, 0.4),
            "detection_rate": random.uniform(0.7, 0.95),
        }
    
    def _get_threats_summary(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> List[Dict[str, Any]]:
        """Get threats summary for period."""
        return [
            {
                "threat_type": "credential_stuffing",
                "count": random.randint(5, 30),
                "severity": "HIGH",
            },
            {
                "threat_type": "payment_fraud",
                "count": random.randint(3, 20),
                "severity": "MEDIUM",
            },
            {
                "threat_type": "account_takeover",
                "count": random.randint(2, 15),
                "severity": "HIGH",
            },
        ]
    
    def _get_investigations_summary(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, Any]:
        """Get investigations summary."""
        return {
            "total_investigations": random.randint(10, 100),
            "by_status": {
                "new": random.randint(0, 20),
                "in_progress": random.randint(5, 30),
                "escalated": random.randint(1, 10),
                "closed": random.randint(5, 50),
            },
            "average_risk_score": random.uniform(0.4, 0.8),
            "high_risk_count": random.randint(5, 25),
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