"""
Regulatory Change Tracker for Regulatory Fabric.

Tracks regulatory changes and manages update processing.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import threading
import hashlib
import uuid


@dataclass
class ChangeAlert:
    """Alert for a regulatory change."""
    alert_id: str
    update_id: str
    regulation_id: str
    change_type: str
    severity: str
    title: str
    description: str
    effective_date: Optional[datetime]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    action_items: List[str] = field(default_factory=list)


class RegulatoryChangeTracker:
    """Tracks regulatory changes and manages update processing.
    
    Monitors regulatory sources and tracks the lifecycle of changes.
    """

    def __init__(self, store: Any):
        """Initialize the change tracker.
        
        Args:
            store: Compliance store instance
        """
        self.store = store
        self._alerts: List[ChangeAlert] = []
        self._processing_queue: List[str] = []
        self._lock = threading.Lock()
        self._change_handlers: List[callable] = []

    def track_update(self, update: Dict[str, Any]) -> str:
        """Track a new regulatory update.
        
        Args:
            update: Update data
            
        Returns:
            Update ID
        """
        update_id = update.get("update_id", str(uuid.uuid4()))
        update["update_id"] = update_id
        update["processed"] = False
        update["tracked_at"] = datetime.now(timezone.utc)
        
        self.store.add_regulatory_update(update)
        
        # Create alert
        alert = ChangeAlert(
            alert_id=hashlib.md5(f"{update_id}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16],
            update_id=update_id,
            regulation_id=update.get("regulation_id", ""),
            change_type=update.get("update_type", "UPDATE"),
            severity=update.get("compliance_impact", "MEDIUM"),
            title=update.get("title", "Regulatory Update"),
            description=update.get("summary", ""),
            effective_date=update.get("effective_date"),
            action_items=update.get("recommended_actions", []),
        )
        
        with self._lock:
            self._alerts.append(alert)
            self._processing_queue.append(update_id)
        
        # Notify handlers
        for handler in self._change_handlers:
            try:
                handler(alert)
            except Exception:
                pass
        
        return update_id

    def register_change_handler(self, handler: callable) -> None:
        """Register a handler for change alerts.
        
        Args:
            handler: Function to call when changes are detected
        """
        with self._lock:
            self._change_handlers.append(handler)

    def process_update(self, update_id: str) -> Dict[str, Any]:
        """Process a regulatory update.
        
        Args:
            update_id: Update ID to process
            
        Returns:
            Processing result
        """
        update = self.store.get_regulatory_update(update_id)
        if not update:
            return {"error": "Update not found"}
        
        result = {
            "update_id": update_id,
            "processing_started": datetime.now(timezone.utc).isoformat(),
            "actions_taken": [],
        }
        
        # Determine affected controls
        affected_requirements = update.get("affected_requirements", [])
        affected_controls = []
        
        for mapping in self.store.control_mappings.values():
            if mapping.get("requirement_id") in affected_requirements:
                affected_controls.append(mapping.get("control_id"))
        
        result["affected_requirements"] = len(affected_requirements)
        result["affected_controls"] = len(affected_controls)
        result["actions_taken"].append(f"Identified {len(affected_controls)} affected controls")
        
        # Create risk entries for affected controls
        from .risk_engine import get_risk_engine
        risk_engine = get_risk_engine()
        
        for ctrl_id in affected_controls:
            risk = risk_engine.assess_risk("control", ctrl_id)
            risk["regulation_id"] = update.get("regulation_id")
            risk["update_id"] = update_id
            self.store.add_risk(risk)
            result["actions_taken"].append(f"Created risk entry for {ctrl_id}")
        
        # Mark update as processed
        update["processed"] = True
        update["processed_at"] = datetime.now(timezone.utc)
        update["processing_result"] = result
        
        return result

    def get_pending_updates(self, regulation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get updates pending processing.
        
        Args:
            regulation_id: Optional regulation filter
            
        Returns:
            List of pending updates
        """
        return self.store.list_regulatory_updates(
            regulation_id=regulation_id,
            processed=False,
        )

    def get_change_timeline(
        self,
        regulation_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Get timeline of changes for a regulation.
        
        Args:
            regulation_id: Regulation ID
            start_date: Start of timeline
            end_date: End of timeline
            
        Returns:
            Timeline data
        """
        updates = self.store.list_regulatory_updates(regulation_id=regulation_id)
        
        if start_date:
            updates = [u for u in updates if u.get("published_date", "") >= start_date.isoformat()]
        if end_date:
            updates = [u for u in updates if u.get("published_date", "") <= end_date.isoformat()]
        
        # Group by month
        monthly_changes = {}
        for update in updates:
            pub_date = update.get("published_date", "")
            if isinstance(pub_date, str):
                try:
                    pub_date = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
                except ValueError:
                    continue
            
            month_key = pub_date.strftime("%Y-%m")
            if month_key not in monthly_changes:
                monthly_changes[month_key] = {
                    "count": 0,
                    "types": {},
                    "impacts": {},
                }
            
            monthly_changes[month_key]["count"] += 1
            
            update_type = update.get("update_type", "UNKNOWN")
            monthly_changes[month_key]["types"][update_type] = monthly_changes[month_key]["types"].get(update_type, 0) + 1
            
            impact = update.get("compliance_impact", "MEDIUM")
            monthly_changes[month_key]["impacts"][impact] = monthly_changes[month_key]["impacts"].get(impact, 0) + 1
        
        return {
            "regulation_id": regulation_id,
            "total_changes": len(updates),
            "monthly_changes": monthly_changes,
            "changes": sorted(updates, key=lambda x: x.get("published_date", ""), reverse=True)[:20],
        }

    def get_alerts(self, acknowledged: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Get change alerts.
        
        Args:
            acknowledged: Filter by acknowledgment status
            
        Returns:
            List of alerts
        """
        alerts = self._alerts
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        
        return [
            {
                "alert_id": a.alert_id,
                "update_id": a.update_id,
                "regulation_id": a.regulation_id,
                "change_type": a.change_type,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "effective_date": a.effective_date.isoformat() if a.effective_date else None,
                "created_at": a.created_at.isoformat(),
                "acknowledged": a.acknowledged,
                "action_items": a.action_items,
            }
            for a in alerts[-50:]  # Last 50 alerts
        ]

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "SYSTEM") -> bool:
        """Acknowledge a change alert.
        
        Args:
            alert_id: Alert ID
            acknowledged_by: Who acknowledged
            
        Returns:
            True if acknowledged
        """
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                alert.acknowledged_by = acknowledged_by
                alert.acknowledged_at = datetime.now(timezone.utc)
                return True
        return False

    def get_change_impact_summary(self) -> Dict[str, Any]:
        """Get summary of change impacts."""
        pending_updates = self.store.list_regulatory_updates(processed=False)
        
        # Calculate impact by severity
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_type = {}
        
        for update in pending_updates:
            severity = update.get("compliance_impact", "MEDIUM")
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            update_type = update.get("update_type", "UNKNOWN")
            by_type[update_type] = by_type.get(update_type, 0) + 1
        
        # Find urgent updates (effective within 30 days)
        now = datetime.now(timezone.utc)
        urgent_deadlines = []
        
        for update in pending_updates:
            effective = update.get("effective_date")
            if effective:
                if isinstance(effective, str):
                    effective = datetime.fromisoformat(effective)
                days_until = (effective - now).days
                if 0 <= days_until <= 30:
                    urgent_deadlines.append({
                        "update_id": update.get("update_id"),
                        "title": update.get("title"),
                        "effective_date": effective.isoformat(),
                        "days_remaining": days_until,
                        "impact": update.get("compliance_impact"),
                    })
        
        return {
            "total_pending_updates": len(pending_updates),
            "by_severity": by_severity,
            "by_type": by_type,
            "urgent_deadlines": sorted(urgent_deadlines, key=lambda x: x["days_remaining"]),
            "unacknowledged_alerts": len([a for a in self._alerts if not a.acknowledged]),
        }


def get_change_tracker() -> RegulatoryChangeTracker:
    """Get the global change tracker instance."""
    from .store import get_compliance_store
    store = get_compliance_store()
    return RegulatoryChangeTracker(store)