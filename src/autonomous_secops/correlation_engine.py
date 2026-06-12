"""
Threat Correlation Engine.

Correlates security events and alerts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import Alert, CorrelationRule, Severity
from .store import AutonomousSecOpsStore, get_secops_store


class ThreatCorrelationEngine:
    """Engine for threat correlation."""

    def __init__(self, store: Optional[AutonomousSecOpsStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_secops_store()

    def add_correlation_rule(
        self,
        name: str,
        conditions: List[Dict[str, Any]],
        severity: str,
    ) -> CorrelationRule:
        """Add a correlation rule."""
        rule_id = f"rule-{uuid.uuid4().hex[:12]}"
        
        rule = CorrelationRule(
            rule_id=rule_id,
            name=name,
            conditions=conditions,
            severity=Severity(severity),
        )
        
        self.store.add_correlation_rule(rule)
        
        self.store.log_audit(
            user_id="system",
            action="rule_added",
            resource_type="correlation_rule",
            resource_id=rule_id,
            details={"name": name},
        )
        
        return rule

    def evaluate_alerts(self) -> List[Dict[str, Any]]:
        """Evaluate all new alerts against correlation rules."""
        new_alerts = self.store.get_new_alerts()
        enabled_rules = self.store.get_enabled_rules()
        
        matches = []
        
        for rule in enabled_rules:
            for alert in new_alerts:
                if self._matches_rule(alert, rule):
                    matches.append({
                        "alert_id": alert.alert_id,
                        "rule_id": rule.rule_id,
                        "rule_name": rule.name,
                        "severity": alert.severity.value,
                    })
                    rule.match_count += 1
        
        return matches

    def _matches_rule(self, alert: Alert, rule: CorrelationRule) -> bool:
        """Check if alert matches rule."""
        for condition in rule.conditions:
            condition_type = condition.get("type")
            
            if condition_type == "severity":
                target = condition.get("value")
                if alert.severity.value != target:
                    return False
            
            elif condition_type == "source":
                target = condition.get("value")
                if alert.source != target:
                    return False
            
            elif condition_type == "indicator_type":
                target = condition.get("value")
                if not any(ind.get("type") == target for ind in alert.indicators):
                    return False
            
            elif condition_type == "keyword":
                target = condition.get("value", "").lower()
                if target not in alert.title.lower() and target not in alert.description.lower():
                    return False
        
        return True

    def find_related_alerts(
        self,
        alert_id: str,
    ) -> List[Dict[str, Any]]:
        """Find related alerts."""
        source_alert = self.store.get_alert(alert_id)
        if not source_alert:
            return []
        
        related = []
        all_alerts = list(self.store._alerts.values())
        
        for alert in all_alerts:
            if alert.alert_id == alert_id:
                continue
            
            if self._are_related(source_alert, alert):
                related.append({
                    "alert_id": alert.alert_id,
                    "title": alert.title,
                    "severity": alert.severity.value,
                    "created_at": alert.created_at.isoformat(),
                })
        
        return related

    def _are_related(self, alert1: Alert, alert2: Alert) -> bool:
        """Check if two alerts are related."""
        if alert1.source == alert2.source:
            return True
        
        for ind1 in alert1.indicators:
            for ind2 in alert2.indicators:
                if ind1.get("value") == ind2.get("value"):
                    return True
        
        return False

    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get correlation summary."""
        rules = list(self.store._correlation_rules.values())
        enabled = [r for r in rules if r.enabled]
        
        return {
            "total_rules": len(rules),
            "enabled_rules": len(enabled),
            "total_matches": sum(r.match_count for r in rules),
            "top_rules": [
                {"name": r.name, "matches": r.match_count}
                for r in sorted(rules, key=lambda x: x.match_count, reverse=True)[:5]
            ],
        }


# Singleton instance
_engine: Optional[ThreatCorrelationEngine] = None


def get_correlation_engine() -> ThreatCorrelationEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = ThreatCorrelationEngine()
    return _engine


def reset_correlation_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None