"""
Executive Dashboard Module.

Provides executive-level dashboard data, KPIs, and summaries.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    ExecutiveDashboard,
    BoardMetric,
    GovernanceMetric,
    RiskLevel,
)
from .store import GovernanceStore, get_governance_store

logger = logging.getLogger(__name__)


class ExecutiveDashboardModule:
    """Executive Dashboard for risk governance visibility.
    
    Provides:
        - Executive KPI summaries
        - Risk overview
        - Compliance status
        - Performance metrics
        - Trend analysis
    """
    
    def __init__(self, store: Optional[GovernanceStore] = None):
        """Initialize the executive dashboard module.
        
        Args:
            store: Optional governance store
        """
        self._store = store or get_governance_store()
        self._module_id = "executive_dashboard"
    
    def generate_dashboard(
        self,
        title: str = "Executive Risk Dashboard",
        period: str = "daily",
    ) -> ExecutiveDashboard:
        """Generate executive dashboard.
        
        Args:
            title: Dashboard title
            period: Reporting period
            
        Returns:
            ExecutiveDashboard
        """
        logger.info(f"Generating executive dashboard: {title}")
        
        # Generate risk summary
        risk_summary = self._generate_risk_summary()
        
        # Generate compliance summary
        compliance_summary = self._generate_compliance_summary()
        
        # Generate performance summary
        performance_summary = self._generate_performance_summary()
        
        # Generate key metrics
        key_metrics = self._generate_key_metrics()
        
        # Generate alerts
        alerts = self._generate_alerts()
        
        # Generate trends
        trends = self._generate_trends()
        
        dashboard = ExecutiveDashboard(
            title=title,
            period=period,
            risk_summary=risk_summary,
            compliance_summary=compliance_summary,
            performance_summary=performance_summary,
            key_metrics=key_metrics,
            alerts=alerts,
            trends=trends,
        )
        
        # Store dashboard
        self._store.store_dashboard(dashboard)
        
        logger.info(f"Dashboard generated: {dashboard.dashboard_id}")
        return dashboard
    
    def get_risk_kpis(self) -> Dict[str, Any]:
        """Get risk KPIs for executive view."""
        return {
            "total_risk_exposure": random.uniform(1000000, 5000000),
            "risk_score": random.uniform(0.3, 0.7),
            "risk_level": random.choice(["LOW", "MEDIUM", "HIGH"]),
            "trend": random.choice(["increasing", "stable", "decreasing"]),
            "change_percent": random.uniform(-0.15, 0.15),
            "top_risk_categories": [
                {"category": "Fraud", "score": random.uniform(0.5, 0.9)},
                {"category": "Cyber", "score": random.uniform(0.4, 0.8)},
                {"category": "Compliance", "score": random.uniform(0.3, 0.7)},
            ],
            "risk_distribution": {
                "critical": random.randint(0, 5),
                "high": random.randint(5, 20),
                "medium": random.randint(20, 50),
                "low": random.randint(50, 100),
            },
        }
    
    def get_compliance_kpis(self) -> Dict[str, Any]:
        """Get compliance KPIs for executive view."""
        return {
            "overall_compliance": random.uniform(85, 98),
            "frameworks_count": 3,
            "compliant_frameworks": random.randint(2, 3),
            "controls_effective": random.uniform(85, 95),
            "open_findings": random.randint(5, 20),
            "critical_findings": random.randint(0, 3),
            "audit_completion_rate": random.uniform(90, 100),
            "policy_violations": random.randint(0, 10),
        }
    
    def get_performance_kpis(self) -> Dict[str, Any]:
        """Get performance KPIs."""
        return {
            "investigations_completed": random.randint(100, 500),
            "avg_resolution_time_hours": random.uniform(24, 72),
            "detection_rate": random.uniform(0.85, 0.98),
            "false_positive_rate": random.uniform(0.05, 0.15),
            " analyst_utilization": random.uniform(0.6, 0.9),
            "system_uptime": random.uniform(99.5, 99.99),
            "alerts_processed": random.randint(1000, 10000),
            "auto_resolution_rate": random.uniform(0.4, 0.7),
        }
    
    def _generate_risk_summary(self) -> Dict[str, Any]:
        """Generate risk summary section."""
        return {
            "overall_risk_score": random.uniform(0.3, 0.7),
            "risk_level": random.choice(["LOW", "MEDIUM", "HIGH"]),
            "trend": random.choice(["increasing", "stable", "decreasing"]),
            "change_7d": random.uniform(-0.1, 0.15),
            "change_30d": random.uniform(-0.2, 0.25),
            "critical_risks": random.randint(0, 5),
            "high_risks": random.randint(5, 20),
            "risk_categories": {
                "fraud": random.uniform(0.4, 0.8),
                "cyber": random.uniform(0.3, 0.7),
                "operational": random.uniform(0.2, 0.6),
                "compliance": random.uniform(0.1, 0.5),
            },
        }
    
    def _generate_compliance_summary(self) -> Dict[str, Any]:
        """Generate compliance summary section."""
        return {
            "overall_compliance": random.uniform(90, 98),
            "framework_status": {
                "SOC2": random.choice(["COMPLIANT", "PARTIAL"]),
                "PCI-DSS": random.choice(["COMPLIANT", "PARTIAL", "NON_COMPLIANT"]),
                "ISO27001": random.choice(["COMPLIANT", "PARTIAL"]),
            },
            "open_findings": random.randint(5, 15),
            "critical_findings": random.randint(0, 2),
            "last_audit_date": (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 180))).isoformat(),
            "next_audit_date": (datetime.now(timezone.utc) + timedelta(days=random.randint(30, 180))).isoformat(),
        }
    
    def _generate_performance_summary(self) -> Dict[str, Any]:
        """Generate performance summary section."""
        return {
            "investigations_this_month": random.randint(100, 500),
            "avg_resolution_time_hours": random.uniform(24, 72),
            "detection_rate": random.uniform(0.85, 0.98),
            "alerts_processed_today": random.randint(500, 2000),
            "active_analysts": random.randint(10, 50),
            "cases_closed_today": random.randint(10, 50),
        }
    
    def _generate_key_metrics(self) -> List[BoardMetric]:
        """Generate key board metrics."""
        metrics = []
        
        metric_definitions = [
            {"category": "Risk", "name": "Overall Risk Score", "target": 0.3},
            {"category": "Compliance", "name": "Compliance Rate", "target": 95.0},
            {"category": "Performance", "name": "Detection Rate", "target": 95.0},
            {"category": "Efficiency", "name": "Resolution Time (hrs)", "target": 48.0},
            {"category": "Quality", "name": "False Positive Rate", "target": 10.0},
        ]
        
        for defn in metric_definitions:
            current = defn["target"] + random.uniform(-0.2, 0.2) * defn["target"]
            variance = ((current - defn["target"]) / defn["target"]) * 100
            
            metrics.append(BoardMetric(
                category=defn["category"],
                metric_name=defn["name"],
                current_value=round(current, 2),
                target_value=defn["target"],
                variance=round(variance, 2),
                trend=random.choice(["improving", "stable", "declining"]),
                period="current_month",
            ))
        
        return metrics
    
    def _generate_alerts(self) -> List[Dict[str, Any]]:
        """Generate executive alerts."""
        alert_types = [
            {"type": "critical_finding", "severity": "CRITICAL", "count": random.randint(0, 3)},
            {"type": "compliance_expiring", "severity": "HIGH", "count": random.randint(1, 5)},
            {"type": "risk_threshold_breach", "severity": "HIGH", "count": random.randint(1, 3)},
            {"type": "audit_due", "severity": "MEDIUM", "count": random.randint(2, 8)},
            {"type": "policy_violation", "severity": "MEDIUM", "count": random.randint(3, 10)},
        ]
        
        alerts = []
        for at in alert_types:
            if at["count"] > 0:
                alerts.append({
                    "type": at["type"],
                    "severity": at["severity"],
                    "count": at["count"],
                    "message": f"{at['count']} {at['type'].replace('_', ' ')} require attention",
                    "action_required": True,
                })
        
        return alerts
    
    def _generate_trends(self) -> Dict[str, Any]:
        """Generate trend analysis."""
        return {
            "risk_trend": {
                "direction": random.choice(["increasing", "stable", "decreasing"]),
                "change_7d": random.uniform(-0.1, 0.15),
                "change_30d": random.uniform(-0.2, 0.25),
            },
            "fraud_trend": {
                "direction": random.choice(["increasing", "stable", "decreasing"]),
                "change_7d": random.uniform(-0.15, 0.2),
                "change_30d": random.uniform(-0.25, 0.3),
            },
            "compliance_trend": {
                "direction": random.choice(["improving", "stable", "declining"]),
                "change_7d": random.uniform(-0.05, 0.1),
                "change_30d": random.uniform(-0.1, 0.15),
            },
            "performance_trend": {
                "direction": random.choice(["improving", "stable", "declining"]),
                "change_7d": random.uniform(-0.1, 0.1),
                "change_30d": random.uniform(-0.15, 0.2),
            },
        }
    
    def get_kpi_summary(self) -> Dict[str, Any]:
        """Get consolidated KPI summary."""
        return {
            "risk_kpis": self.get_risk_kpis(),
            "compliance_kpis": self.get_compliance_kpis(),
            "performance_kpis": self.get_performance_kpis(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Global singleton
_dashboard_module: Optional[ExecutiveDashboardModule] = None


def get_executive_dashboard_module(store: Optional[GovernanceStore] = None) -> ExecutiveDashboardModule:
    """Get or create the singleton ExecutiveDashboardModule instance."""
    global _dashboard_module
    
    if _dashboard_module is None:
        _dashboard_module = ExecutiveDashboardModule(store=store)
    return _dashboard_module