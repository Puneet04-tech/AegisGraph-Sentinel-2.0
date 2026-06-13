"""
Alert Manager Module.

Alert management and routing.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AlertRule,
    Alert,
    AlertSeverity,
    AlertStatus,
)
from .store import ObservabilityStore, get_observability_store

logger = logging.getLogger(__name__)


class AlertManager:
    """Alert Manager for alert handling.
    
    Provides:
        - Alert rule management
        - Alert generation
        - Alert routing
        - Alert deduplication
    """
    
    def __init__(self, store: Optional[ObservabilityStore] = None):
        """Initialize the alert manager."""
        self._store = store or get_observability_store()
        self._module_id = "alert_manager"
        self._recent_alerts: Dict[str, datetime] = {}
        self._dedup_window_seconds = 300  # 5 minutes
    
    def create_rule(
        self,
        name: str,
        description: str,
        condition: Dict[str, Any],
        severity: AlertSeverity,
        cooldown_seconds: int = 300,
    ) -> AlertRule:
        """Create an alert rule."""
        logger.info(f"Creating alert rule: {name}")
        
        rule = AlertRule(
            name=name,
            description=description,
            condition=condition,
            severity=severity,
            cooldown_seconds=cooldown_seconds,
        )
        
        self._store.store_alert_rule(rule)
        return rule
    
    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get alert rule by ID."""
        return self._store.get_alert_rule(rule_id)
    
    def list_rules(self) -> List[AlertRule]:
        """List all alert rules."""
        return self._store.get_all_alert_rules()
    
    def enable_rule(self, rule_id: str) -> AlertRule:
        """Enable an alert rule."""
        rule = self._store.get_alert_rule(rule_id)
        if not rule:
            raise ValueError(f"Rule {rule_id} not found")
        
        rule.enabled = True
        self._store.store_alert_rule(rule)
        return rule
    
    def disable_rule(self, rule_id: str) -> AlertRule:
        """Disable an alert rule."""
        rule = self._store.get_alert_rule(rule_id)
        if not rule:
            raise ValueError(f"Rule {rule_id} not found")
        
        rule.enabled = False
        self._store.store_alert_rule(rule)
        return rule
    
    def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        component: str,
        rule_id: str = None,
        metric_value: float = None,
        threshold: float = None,
    ) -> Alert:
        """Create an alert."""
        logger.info(f"Creating alert: {title}")
        
        # Check deduplication
        alert_key = f"{component}:{title}"
        if alert_key in self._recent_alerts:
            last_alert_time = self._recent_alerts[alert_key]
            if (datetime.now(timezone.utc) - last_alert_time).total_seconds() < self._dedup_window_seconds:
                logger.info(f"Alert deduplicated: {alert_key}")
                return None
        
        alert = Alert(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            component=component,
            metric_value=metric_value,
            threshold=threshold,
        )
        
        self._store.store_alert(alert)
        self._recent_alerts[alert_key] = alert.triggered_at
        
        return alert
    
    def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
    ) -> Alert:
        """Acknowledge an alert."""
        alert = self._store.get_alert(alert_id)
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")
        
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = datetime.now(timezone.utc)
        alert.acknowledged_by = acknowledged_by
        self._store.store_alert(alert)
        
        return alert
    
    def resolve_alert(self, alert_id: str) -> Alert:
        """Resolve an alert."""
        alert = self._store.get_alert(alert_id)
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")
        
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.now(timezone.utc)
        self._store.store_alert(alert)
        
        return alert
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID."""
        return self._store.get_alert(alert_id)
    
    def get_active_alerts(self) -> List[Alert]:
        """Get active alerts."""
        return self._store.get_active_alerts()
    
    def get_recent_alerts(self, limit: int = 100) -> List[Alert]:
        """Get recent alerts."""
        return self._store.get_recent_alerts(limit)
    
    def get_alerts_by_severity(self, severity: AlertSeverity) -> List[Alert]:
        """Get alerts by severity."""
        alerts = self._store.get_recent_alerts(limit=1000)
        return [a for a in alerts if a.severity == severity]
    
    def evaluate_rules(self, metrics: Dict[str, float], component: str) -> List[Alert]:
        """Evaluate alert rules against metrics."""
        alerts = []
        rules = self.list_rules()
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            condition = rule.condition
            metric_name = condition.get("metric")
            threshold = condition.get("threshold")
            operator = condition.get("operator", "gt")
            
            if metric_name not in metrics:
                continue
            
            value = metrics[metric_name]
            
            # Evaluate condition
            triggered = False
            if operator == "gt" and value > threshold:
                triggered = True
            elif operator == "gte" and value >= threshold:
                triggered = True
            elif operator == "lt" and value < threshold:
                triggered = True
            elif operator == "lte" and value <= threshold:
                triggered = True
            elif operator == "eq" and value == threshold:
                triggered = True
            
            if triggered:
                alert = self.create_alert(
                    title=f"{rule.name}: {metric_name} {operator} {threshold}",
                    description=rule.description,
                    severity=rule.severity,
                    component=component,
                    rule_id=rule.rule_id,
                    metric_value=value,
                    threshold=threshold,
                )
                if alert:
                    alerts.append(alert)
        
        return alerts


# Global singleton
_alert_manager: Optional[AlertManager] = None


def get_alert_manager(store: Optional[ObservabilityStore] = None) -> AlertManager:
    """Get or create the singleton AlertManager instance."""
    global _alert_manager
    
    if _alert_manager is None:
        _alert_manager = AlertManager(store=store)
    return _alert_manager