"""
Dashboard Module.

Platform dashboard and reporting.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    DashboardSnapshot,
    AuditEntry,
    Incident,
    AlertSeverity,
)
from .store import ObservabilityStore, get_observability_store
from .health_monitor import HealthMonitor, get_health_monitor
from .alert_manager import AlertManager, get_alert_manager

logger = logging.getLogger(__name__)


class PlatformDashboard:
    """Platform Dashboard for unified observability.
    
    Provides:
        - Unified health overview
        - Real-time metrics
        - Trend analysis
        - Incident management
    """
    
    def __init__(self, store: Optional[ObservabilityStore] = None):
        """Initialize the platform dashboard."""
        self._store = store or get_observability_store()
        self._health_monitor = get_health_monitor(self._store)
        self._alert_manager = get_alert_manager(self._store)
        self._module_id = "dashboard"
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data."""
        logger.info("Generating dashboard data")
        
        # Health summary
        health_summary = self._health_monitor.get_health_summary()
        overall_health = self._health_monitor.calculate_overall_health()
        
        # Alert summary
        active_alerts = self._alert_manager.get_active_alerts()
        critical_alerts = [a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]
        high_alerts = [a for a in active_alerts if a.severity == AlertSeverity.HIGH]
        
        # Open incidents
        open_incidents = self._store.get_open_incidents()
        
        # Create snapshot
        snapshot = DashboardSnapshot(
            overall_health_score=overall_health,
            active_alerts=len(active_alerts),
            critical_alerts=len(critical_alerts),
            total_requests=1000,  # Placeholder
            avg_response_time_ms=50.0,  # Placeholder
            components_summary=health_summary,
        )
        self._store.store_snapshot(snapshot)
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_health_score": overall_health,
            "health": health_summary,
            "alerts": {
                "active": len(active_alerts),
                "critical": len(critical_alerts),
                "high": len(high_alerts),
                "recent": [
                    {
                        "id": a.alert_id,
                        "title": a.title,
                        "severity": a.severity.value,
                        "component": a.component,
                    }
                    for a in active_alerts[:10]
                ],
            },
            "incidents": {
                "open": len(open_incidents),
                "recent": [
                    {
                        "id": i.incident_id,
                        "title": i.title,
                        "severity": i.severity.value,
                        "status": i.status,
                    }
                    for i in open_incidents[:5]
                ],
            },
            "components": [
                {
                    "id": h.component_id,
                    "name": h.component_name,
                    "type": h.component_type,
                    "status": h.status.value,
                    "health_score": h.health_score,
                    "last_check": h.last_check.isoformat(),
                }
                for h in self._health_monitor.get_all_components()
            ],
        }
    
    def create_incident(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        affected_components: List[str] = None,
        created_by: str = None,
    ) -> Incident:
        """Create an incident."""
        logger.info(f"Creating incident: {title}")
        
        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            affected_components=affected_components or [],
            created_by=created_by,
        )
        
        self._store.store_incident(incident)
        
        # Create audit entry
        self.log_audit(
            action="incident_created",
            resource_type="incident",
            resource_id=incident.incident_id,
            details={"title": title, "severity": severity.value},
        )
        
        return incident
    
    def update_incident_status(
        self,
        incident_id: str,
        status: str,
    ) -> Incident:
        """Update incident status."""
        incident = self._store.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        incident.status = status
        
        if status == "RESOLVED":
            incident.resolved_at = datetime.now(timezone.utc)
        
        self._store.store_incident(incident)
        
        self.log_audit(
            action="incident_updated",
            resource_type="incident",
            resource_id=incident_id,
            details={"status": status},
        )
        
        return incident
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID."""
        return self._store.get_incident(incident_id)
    
    def get_open_incidents(self) -> List[Incident]:
        """Get open incidents."""
        return self._store.get_open_incidents()
    
    def log_audit(
        self,
        action: str,
        resource_type: str,
        user: str = None,
        resource_id: str = None,
        details: Dict[str, Any] = None,
        ip_address: str = None,
        result: str = "SUCCESS",
    ) -> AuditEntry:
        """Log an audit entry."""
        entry = AuditEntry(
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            result=result,
        )
        
        self._store.store_audit_entry(entry)
        return entry
    
    def get_audit_trail(
        self,
        user: str = None,
        action: str = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get audit trail."""
        return self._store.get_audit_entries(user, action, limit)
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report."""
        audit_entries = self._store.get_audit_entries(limit=10000)
        
        # Count by action type
        action_counts = {}
        for entry in audit_entries:
            action_counts[entry.action] = action_counts.get(entry.action, 0) + 1
        
        # Count by result
        success_count = sum(1 for e in audit_entries if e.result == "SUCCESS")
        failure_count = len(audit_entries) - success_count
        
        return {
            "report_date": datetime.now(timezone.utc).isoformat(),
            "total_audit_entries": len(audit_entries),
            "action_breakdown": action_counts,
            "success_count": success_count,
            "failure_count": failure_count,
            "failure_rate_percent": (failure_count / len(audit_entries) * 100) if audit_entries else 0,
        }
    
    def get_trend_analysis(self, days: int = 7) -> Dict[str, Any]:
        """Get trend analysis over time."""
        snapshots = list(self._store._snapshots)
        
        if not snapshots:
            return {"error": "No historical data"}
        
        health_scores = [s.overall_health_score for s in snapshots]
        alert_counts = [s.active_alerts for s in snapshots]
        
        return {
            "period_days": days,
            "health_trend": {
                "min": min(health_scores) if health_scores else 0,
                "max": max(health_scores) if health_scores else 0,
                "avg": sum(health_scores) / len(health_scores) if health_scores else 0,
            },
            "alert_trend": {
                "min": min(alert_counts) if alert_counts else 0,
                "max": max(alert_counts) if alert_counts else 0,
                "avg": sum(alert_counts) / len(alert_counts) if alert_counts else 0,
            },
            "data_points": len(snapshots),
        }


# Global singleton
_platform_dashboard: Optional[PlatformDashboard] = None


def get_platform_dashboard(store: Optional[ObservabilityStore] = None) -> PlatformDashboard:
    """Get or create the singleton PlatformDashboard instance."""
    global _platform_dashboard
    
    if _platform_dashboard is None:
        _platform_dashboard = PlatformDashboard(store=store)
    return _platform_dashboard