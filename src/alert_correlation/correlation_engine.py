"""Alert Correlation Engine"""
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4
from datetime import datetime
from .models import Alert, AlertGroup, SuppressionRule, CorrelationRule
from .models import AlertSeverity, AlertStatus

class AlertCorrelationEngine:
    """Engine for alert aggregation, correlation, and deduplication"""
    
    def __init__(self) -> None:
        self.alerts: Dict[str, Alert] = {}
        self.groups: Dict[str, AlertGroup] = {}
        self.suppression_rules: Dict[str, SuppressionRule] = {}
        self.correlation_rules: Dict[str, CorrelationRule] = {}
        self._init_default_rules()
    
    def _init_default_rules(self) -> None:
        """Initialize default correlation rules"""
        rules = [
            CorrelationRule(
                rule_id="rule-001",
                name="Same Source IP",
                description="Group alerts from same source IP",
                conditions={"field": "source", "type": "exact"},
                group_template="source_ip_group"
            ),
            CorrelationRule(
                rule_id="rule-002",
                name="Same User",
                description="Group alerts involving same user",
                conditions={"field": "user", "type": "exact"},
                group_template="user_group"
            ),
            CorrelationRule(
                rule_id="rule-003",
                name="Similar Indicators",
                description="Group alerts with shared indicators",
                conditions={"field": "indicators", "type": "overlap"},
                group_template="indicator_group"
            )
        ]
        for rule in rules:
            self.correlation_rules[rule.rule_id] = rule
    
    def ingest_alert(
        self,
        title: str,
        description: str,
        severity: str,
        source: str,
        tags: Optional[List[str]] = None,
        indicators: Optional[List[str]] = None
    ) -> Alert:
        """Ingest a new alert"""
        alert = Alert(
            alert_id=str(uuid4())[:8],
            title=title,
            description=description,
            severity=AlertSeverity[severity],
            source=source,
            tags=tags or [],
            indicators=indicators or []
        )
        self.alerts[alert.alert_id] = alert
        return alert
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID"""
        return self.alerts.get(alert_id)
    
    def get_all_alerts(self) -> List[Alert]:
        """Get all alerts"""
        return list(self.alerts.values())
    
    def deduplicate_alert(self, alert_id: str, duplicate_of: str) -> bool:
        """Mark alert as duplicate"""
        alert = self.alerts.get(alert_id)
        original = self.alerts.get(duplicate_of)
        if alert and original:
            alert.deduplicated = True
            alert.deduplicated_by = duplicate_of
            alert.status = AlertStatus.SUPPRESSED
            return True
        return False
    
    def find_duplicates(self, alert: Alert, threshold: float = 0.8) -> List[Alert]:
        """Find potential duplicate alerts"""
        duplicates = []
        for other in self.alerts.values():
            if other.alert_id == alert.alert_id or other.deduplicated:
                continue
            
            # Check title similarity
            similarity = self._calculate_similarity(alert.title, other.title)
            if similarity >= threshold:
                duplicates.append(other)
            
            # Check indicator overlap
            if set(alert.indicators) & set(other.indicators):
                duplicates.append(other)
        
        return duplicates
    
    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate string similarity"""
        s1_lower = s1.lower()
        s2_lower = s2.lower()
        if s1_lower == s2_lower:
            return 1.0
        if s1_lower in s2_lower or s2_lower in s1_lower:
            return 0.8
        return 0.0
    
    def correlate_alerts(self, alert_ids: List[str]) -> Optional[AlertGroup]:
        """Correlate multiple alerts into a group"""
        alerts = [self.alerts.get(aid) for aid in alert_ids if self.alerts.get(aid)]
        if len(alerts) < 2:
            return None
        
        # Sort by severity to find primary
        alerts.sort(key=lambda a: a.severity.value)
        primary = alerts[0]
        
        # Calculate correlation score
        score = self._calculate_correlation_score(alerts)
        
        group = AlertGroup(
            group_id=str(uuid4())[:8],
            name=f"Alert Group {len(self.groups) + 1}",
            description=f"Correlated {len(alerts)} alerts",
            alert_ids=[a.alert_id for a in alerts],
            primary_alert_id=primary.alert_id,
            correlation_score=score
        )
        self.groups[group.group_id] = group
        return group
    
    def _calculate_correlation_score(self, alerts: List[Alert]) -> float:
        """Calculate correlation score between alerts"""
        if len(alerts) < 2:
            return 0.0
        
        score = 0.5  # Base score
        
        # Check shared sources
        sources = set(a.source for a in alerts)
        if len(sources) == 1:
            score += 0.2
        
        # Check shared indicators
        all_indicators = [i for a in alerts for i in a.indicators]
        if len(all_indicators) != len(set(all_indicators)):
            score += 0.2
        
        # Check temporal proximity
        timestamps = [a.created_at for a in alerts]
        time_range = (max(timestamps) - min(timestamps)).total_seconds()
        if time_range < 3600:  # Within 1 hour
            score += 0.1
        
        return min(score, 1.0)
    
    def prioritize_alerts(self) -> List[Alert]:
        """Get alerts sorted by priority"""
        alerts = [a for a in self.alerts.values() if not a.deduplicated]
        return sorted(alerts, key=lambda a: (a.severity.value, a.created_at))
    
    def create_suppression_rule(
        self,
        name: str,
        description: str,
        conditions: Dict[str, Any]
    ) -> SuppressionRule:
        """Create a suppression rule"""
        rule = SuppressionRule(
            rule_id=str(uuid4())[:8],
            name=name,
            description=description,
            conditions=conditions
        )
        self.suppression_rules[rule.rule_id] = rule
        return rule
    
    def should_suppress(self, alert: Alert) -> bool:
        """Check if alert should be suppressed"""
        for rule in self.suppression_rules.values():
            if not rule.enabled:
                continue
            if self._matches_conditions(alert, rule.conditions):
                return True
        return False
    
    def _matches_conditions(self, alert: Alert, conditions: Dict[str, Any]) -> bool:
        """Check if alert matches conditions"""
        for key, value in conditions.items():
            if key == "source" and alert.source == value:
                return True
            if key == "severity" and alert.severity.name == value:
                return True
            if key == "tag" and value in alert.tags:
                return True
        return False
    
    def link_to_incident(self, alert_id: str, incident_id: str) -> bool:
        """Link alert to an incident"""
        alert = self.alerts.get(alert_id)
        if alert:
            alert.linked_incidents.append(incident_id)
            return True
        return False
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get alert dashboard"""
        status_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        source_counts: Dict[str, int] = {}
        
        for alert in self.alerts.values():
            status_counts[alert.status.value] = status_counts.get(alert.status.value, 0) + 1
            severity_counts[alert.severity.name] = severity_counts.get(alert.severity.name, 0) + 1
            source_counts[alert.source] = source_counts.get(alert.source, 0) + 1
        
        return {
            "total_alerts": len(self.alerts),
            "total_groups": len(self.groups),
            "active_alerts": len([a for a in self.alerts.values() if a.status != AlertStatus.RESOLVED]),
            "deduplicated_count": len([a for a in self.alerts.values() if a.deduplicated]),
            "alerts_by_status": status_counts,
            "alerts_by_severity": severity_counts,
            "alerts_by_source": source_counts
        }