"""Alert Correlation Service"""
from typing import Any, Dict, List, Optional
from .models import Alert, AlertGroup, SuppressionRule
from .correlation_engine import AlertCorrelationEngine

class AlertCorrelationService:
    """Service for enterprise alert correlation"""
    
    def __init__(self) -> None:
        self.engine = AlertCorrelationEngine()
    
    def create_alert(
        self,
        title: str,
        description: str,
        severity: str,
        source: str,
        tags: Optional[List[str]] = None,
        indicators: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create a new alert"""
        alert = self.engine.ingest_alert(title, description, severity, source, tags, indicators)
        return alert.to_dict()
    
    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get an alert"""
        alert = self.engine.get_alert(alert_id)
        return alert.to_dict() if alert else None
    
    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Get all alerts"""
        return [a.to_dict() for a in self.engine.get_all_alerts()]
    
    def get_prioritized_alerts(self) -> List[Dict[str, Any]]:
        """Get alerts sorted by priority"""
        return [a.to_dict() for a in self.engine.prioritize_alerts()]
    
    def correlate_alerts(self, alert_ids: List[str]) -> Optional[Dict[str, Any]]:
        """Correlate alerts into a group"""
        group = self.engine.correlate_alerts(alert_ids)
        return group.to_dict() if group else None
    
    def get_correlation_groups(self) -> List[Dict[str, Any]]:
        """Get all correlation groups"""
        return [g.to_dict() for g in self.engine.groups.values()]
    
    def find_duplicates(self, alert_id: str) -> List[Dict[str, Any]]:
        """Find duplicate alerts"""
        alert = self.engine.get_alert(alert_id)
        if not alert:
            return []
        return [a.to_dict() for a in self.engine.find_duplicates(alert)]
    
    def create_suppression_rule(
        self,
        name: str,
        description: str,
        conditions: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a suppression rule"""
        rule = self.engine.create_suppression_rule(name, description, conditions)
        return rule.to_dict()
    
    def get_suppression_rules(self) -> List[Dict[str, Any]]:
        """Get all suppression rules"""
        return [r.to_dict() for r in self.engine.suppression_rules.values()]
    
    def link_to_incident(self, alert_id: str, incident_id: str) -> bool:
        """Link alert to incident"""
        return self.engine.link_to_incident(alert_id, incident_id)
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard data"""
        return self.engine.get_dashboard()


# Global service instance
_alert_service: Optional[AlertCorrelationService] = None

def get_alert_correlation_service() -> AlertCorrelationService:
    """Get the global service instance"""
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertCorrelationService()
    return _alert_service