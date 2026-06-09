"""
Alert Generator Module.

Low-latency alert generation, prioritization, and routing.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    StreamAlert,
    StreamEvent,
    EventPriority,
)
from .store import StreamStore, get_stream_store

logger = logging.getLogger(__name__)


class AlertGenerator:
    """Alert Generator for real-time alert management.
    
    Provides:
        - Alert generation
        - Alert prioritization
        - Alert deduplication
        - Alert routing
    """
    
    def __init__(self, store: Optional[StreamStore] = None):
        """Initialize the alert generator."""
        self._store = store or get_stream_store()
        self._module_id = "alert_generator"
        self._alert_seen: Dict[str, datetime] = {}
        self._deduplication_window_seconds = 300  # 5 minutes
    
    def generate_alert(
        self,
        alert_type: str,
        title: str,
        description: str,
        severity: EventPriority,
        source_event_ids: List[str] = None,
        stream_name: str = "alerts",
    ) -> StreamAlert:
        """Generate an alert."""
        logger.info(f"Generating alert: {alert_type} - {title}")
        
        alert = StreamAlert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source_event_ids=source_event_ids or [],
            stream_name=stream_name,
        )
        
        self._store.store_alert(alert)
        return alert
    
    def generate_alert_from_event(
        self,
        event: StreamEvent,
        alert_type: str,
        title_template: str,
        description_template: str,
    ) -> StreamAlert:
        """Generate alert from an event."""
        # Format templates with event data
        title = title_template.format(**event.payload)
        description = description_template.format(**event.payload)
        
        return self.generate_alert(
            alert_type=alert_type,
            title=title,
            description=description,
            severity=event.priority,
            source_event_ids=[event.event_id],
            stream_name=event.source,
        )
    
    def check_and_generate(
        self,
        alert_type: str,
        condition: bool,
        title: str,
        description: str,
        severity: EventPriority,
        source_event_ids: List[str] = None,
    ) -> Optional[StreamAlert]:
        """Check condition and generate alert if true."""
        if condition:
            return self.generate_alert(
                alert_type=alert_type,
                title=title,
                description=description,
                severity=severity,
                source_event_ids=source_event_ids,
            )
        return None
    
    def prioritize_alerts(
        self,
        alerts: List[StreamAlert] = None,
        limit: int = 100,
    ) -> List[StreamAlert]:
        """Prioritize alerts by severity."""
        if alerts is None:
            alerts = self._store.get_recent_alerts(limit=limit)
        
        # Priority order
        priority_order = {
            EventPriority.CRITICAL: 0,
            EventPriority.HIGH: 1,
            EventPriority.MEDIUM: 2,
            EventPriority.LOW: 3,
        }
        
        return sorted(
            alerts,
            key=lambda a: (
                priority_order.get(a.severity, 99),
                -a.triggered_at.timestamp(),
            )
        )
    
    def deduplicate_alert(
        self,
        alert_key: str,
        alert: StreamAlert,
    ) -> bool:
        """Check and record alert for deduplication.
        
        Returns True if this is a duplicate alert.
        """
        now = datetime.now(timezone.utc)
        
        # Check if we've seen this alert recently
        if alert_key in self._alert_seen:
            last_seen = self._alert_seen[alert_key]
            if (now - last_seen).total_seconds() < self._deduplication_window_seconds:
                logger.info(f"Duplicate alert detected: {alert_key}")
                return True
        
        # Record this alert
        self._alert_seen[alert_key] = now
        
        # Clean old entries
        self._cleanup_dedup_cache()
        
        return False
    
    def _cleanup_dedup_cache(self) -> None:
        """Clean up old deduplication cache entries."""
        now = datetime.now(timezone.utc)
        expired_keys = [
            key for key, last_seen in self._alert_seen.items()
            if (now - last_seen).total_seconds() > self._deduplication_window_seconds
        ]
        for key in expired_keys:
            del self._alert_seen[key]
    
    def route_alert(
        self,
        alert: StreamAlert,
        routes: Dict[str, List[str]],
    ) -> List[str]:
        """Route alert to appropriate channels."""
        logger.info(f"Routing alert {alert.alert_id}")
        
        destinations = []
        
        # Route by severity
        if alert.severity == EventPriority.CRITICAL:
            destinations.extend(routes.get("critical", []))
        elif alert.severity == EventPriority.HIGH:
            destinations.extend(routes.get("high", []))
        
        # Route by type
        type_routes = routes.get("by_type", {})
        if alert.alert_type in type_routes:
            destinations.extend(type_routes[alert.alert_type])
        
        return list(set(destinations))  # Remove duplicates
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary."""
        alerts = self._store.get_recent_alerts(limit=1000)
        
        critical = sum(1 for a in alerts if a.severity == EventPriority.CRITICAL)
        high = sum(1 for a in alerts if a.severity == EventPriority.HIGH)
        medium = sum(1 for a in alerts if a.severity == EventPriority.MEDIUM)
        low = sum(1 for a in alerts if a.severity == EventPriority.LOW)
        
        unacknowledged = sum(1 for a in alerts if not a.acknowledged)
        
        return {
            "total_alerts": len(alerts),
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "unacknowledged": unacknowledged,
            "acknowledged": len(alerts) - unacknowledged,
        }
    
    def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
    ) -> bool:
        """Acknowledge an alert."""
        alert = self._store.get_alert(alert_id)
        if not alert:
            return False
        
        alert.acknowledged = True
        alert.acknowledged_by = acknowledged_by
        self._store.store_alert(alert)
        
        return True


# Global singleton
_alert_generator: Optional[AlertGenerator] = None


def get_alert_generator(store: Optional[StreamStore] = None) -> AlertGenerator:
    """Get or create the singleton AlertGenerator instance."""
    global _alert_generator
    
    if _alert_generator is None:
        _alert_generator = AlertGenerator(store=store)
    return _alert_generator