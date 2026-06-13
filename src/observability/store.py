"""
Observability Storage Engine.

Thread-safe storage for health, metrics, alerts, and audits.
"""

from collections import deque
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    ComponentHealth,
    PerformanceMetric,
    AlertRule,
    Alert,
    AuditEntry,
    DashboardSnapshot,
    Incident,
    ComponentStatus,
    AlertStatus,
)

logger = logging.getLogger(__name__)


class ObservabilityStore:
    """Thread-safe storage for observability data.
    
    Provides:
        - O(1) lookup by ID
        - Thread-safe operations
        - Metrics retention
        - Alert management
    """
    
    def __init__(self, max_metrics: int = 10000):
        """Initialize the observability store."""
        self._max_metrics = max_metrics
        self._lock = Lock()
        
        # Component health
        self._health: Dict[str, ComponentHealth] = {}
        
        # Metrics (bounded)
        self._metrics: deque = deque(maxlen=max_metrics)
        
        # Alert rules
        self._alert_rules: Dict[str, AlertRule] = {}
        
        # Alerts
        self._alerts: Dict[str, Alert] = {}
        
        # Audit entries
        self._audit: deque = deque(maxlen=max_metrics)
        
        # Incidents
        self._incidents: Dict[str, Incident] = {}
        
        # Dashboard snapshots
        self._snapshots: deque = deque(maxlen=100)
        
        # Initialize defaults
        self._initialize_defaults()
    
    def _initialize_defaults(self):
        """Initialize default components."""
        default_components = [
            ComponentHealth(
                component_name="API Gateway",
                component_type="api",
                status=ComponentStatus.HEALTHY,
                health_score=100.0,
            ),
            ComponentHealth(
                component_name="Database",
                component_type="database",
                status=ComponentStatus.HEALTHY,
                health_score=95.0,
            ),
            ComponentHealth(
                component_name="Cache",
                component_type="cache",
                status=ComponentStatus.HEALTHY,
                health_score=98.0,
            ),
        ]
        
        for component in default_components:
            self._health[component.component_id] = component
    
    # Health Methods
    def store_health(self, health: ComponentHealth) -> ComponentHealth:
        """Store component health."""
        with self._lock:
            self._health[health.component_id] = health
        return health
    
    def get_health(self, component_id: str) -> Optional[ComponentHealth]:
        """Get component health."""
        return self._health.get(component_id)
    
    def get_all_health(self) -> List[ComponentHealth]:
        """Get all component health."""
        return list(self._health.values())
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary."""
        healths = self.get_all_health()
        
        healthy = sum(1 for h in healths if h.status == ComponentStatus.HEALTHY)
        degraded = sum(1 for h in healths if h.status == ComponentStatus.DEGRADED)
        unhealthy = sum(1 for h in healths if h.status == ComponentStatus.UNHEALTHY)
        
        avg_score = sum(h.health_score for h in healths) / len(healths) if healths else 0
        
        return {
            "total_components": len(healths),
            "healthy": healthy,
            "degraded": degraded,
            "unhealthy": unhealthy,
            "average_health_score": avg_score,
        }
    
    # Metric Methods
    def store_metric(self, metric: PerformanceMetric) -> PerformanceMetric:
        """Store performance metric."""
        with self._lock:
            self._metrics.append(metric)
        return metric
    
    def get_metrics(
        self,
        component: str = None,
        metric_name: str = None,
        limit: int = 1000,
    ) -> List[PerformanceMetric]:
        """Get metrics with filters."""
        metrics = list(self._metrics)
        
        if component:
            metrics = [m for m in metrics if m.component == component]
        if metric_name:
            metrics = [m for m in metrics if m.metric_name == metric_name]
        
        return sorted(metrics, key=lambda m: m.timestamp, reverse=True)[:limit]
    
    # Alert Rule Methods
    def store_alert_rule(self, rule: AlertRule) -> AlertRule:
        """Store alert rule."""
        with self._lock:
            self._alert_rules[rule.rule_id] = rule
        return rule
    
    def get_alert_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get alert rule by ID."""
        return self._alert_rules.get(rule_id)
    
    def get_all_alert_rules(self) -> List[AlertRule]:
        """Get all alert rules."""
        return list(self._alert_rules.values())
    
    # Alert Methods
    def store_alert(self, alert: Alert) -> Alert:
        """Store alert."""
        with self._lock:
            self._alerts[alert.alert_id] = alert
        return alert
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID."""
        return self._alerts.get(alert_id)
    
    def get_active_alerts(self) -> List[Alert]:
        """Get active alerts."""
        return [a for a in self._alerts.values() if a.status == AlertStatus.ACTIVE]
    
    def get_recent_alerts(self, limit: int = 100) -> List[Alert]:
        """Get recent alerts."""
        alerts = list(self._alerts.values())
        return sorted(alerts, key=lambda a: a.triggered_at, reverse=True)[:limit]
    
    # Audit Methods
    def store_audit_entry(self, entry: AuditEntry) -> AuditEntry:
        """Store audit entry."""
        with self._lock:
            self._audit.append(entry)
        return entry
    
    def get_audit_entries(
        self,
        user: str = None,
        action: str = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get audit entries with filters."""
        entries = list(self._audit)
        
        if user:
            entries = [e for e in entries if e.user == user]
        if action:
            entries = [e for e in entries if e.action == action]
        
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)[:limit]
    
    # Incident Methods
    def store_incident(self, incident: Incident) -> Incident:
        """Store incident."""
        with self._lock:
            self._incidents[incident.incident_id] = incident
        return incident
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID."""
        return self._incidents.get(incident_id)
    
    def get_open_incidents(self) -> List[Incident]:
        """Get open incidents."""
        return [i for i in self._incidents.values() if i.status in ["OPEN", "INVESTIGATING"]]
    
    # Snapshot Methods
    def store_snapshot(self, snapshot: DashboardSnapshot) -> DashboardSnapshot:
        """Store dashboard snapshot."""
        with self._lock:
            self._snapshots.append(snapshot)
        return snapshot
    
    def get_latest_snapshot(self) -> Optional[DashboardSnapshot]:
        """Get latest dashboard snapshot."""
        if not self._snapshots:
            return None
        return self._snapshots[-1]
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "components_monitored": len(self._health),
            "metrics_stored": len(self._metrics),
            "alert_rules_count": len(self._alert_rules),
            "active_alerts": len(self.get_active_alerts()),
            "total_alerts": len(self._alerts),
            "audit_entries": len(self._audit),
            "open_incidents": len(self.get_open_incidents()),
            "snapshots_count": len(self._snapshots),
        }


# Global singleton
_observability_store: Optional[ObservabilityStore] = None
_observability_store_lock = Lock()


def get_observability_store() -> ObservabilityStore:
    """Get or create the singleton observability store instance."""
    global _observability_store
    
    with _observability_store_lock:
        if _observability_store is None:
            _observability_store = ObservabilityStore()
        return _observability_store