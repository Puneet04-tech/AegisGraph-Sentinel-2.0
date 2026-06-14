"""
Compliance Drift Detector for Regulatory Fabric.

Monitors for changes that could cause compliance drift.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import threading
import hashlib


@dataclass
class DriftEvent:
    """Detected compliance drift event."""
    event_id: str
    drift_type: str
    severity: str
    description: str
    affected_entities: List[str]
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    previous_state: Dict[str, Any] = field(default_factory=dict)
    current_state: Dict[str, Any] = field(default_factory=dict)
    recommended_actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BaselineSnapshot:
    """Snapshot of compliance state for drift comparison."""
    snapshot_id: str
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    controls_state: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    policies_state: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    mappings_state: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComplianceDriftDetector:
    """Detects compliance drift in real-time.
    
    Monitors control states, policy changes, and regulatory mappings
    to detect drift from compliance baseline.
    """

    def __init__(self, store: Any):
        """Initialize the drift detector.
        
        Args:
            store: Compliance store instance
        """
        self.store = store
        self._baselines: Dict[str, BaselineSnapshot] = {}
        self._drift_events: List[DriftEvent] = []
        self._lock = threading.Lock()
        self._drift_handlers: List[callable] = []

    def capture_baseline(self, name: str = "default") -> str:
        """Capture a baseline snapshot of current compliance state.
        
        Args:
            name: Name for the baseline
            
        Returns:
            Baseline snapshot ID
        """
        with self._lock:
            snapshot = BaselineSnapshot(
                snapshot_id=hashlib.md5(f"{name}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16],
                controls_state={k: v.copy() for k, v in self.store.controls.items()},
                policies_state={k: v.copy() for k, v in self.store.policies.items()},
                mappings_state={k: v.copy() for k, v in self.store.control_mappings.items()},
            )
            self._baselines[name] = snapshot
            return snapshot.snapshot_id

    def get_baseline(self, name: str = "default") -> Optional[BaselineSnapshot]:
        """Get a baseline snapshot by name."""
        return self._baselines.get(name)

    def detect_drift(self, baseline_name: str = "default") -> List[DriftEvent]:
        """Detect drift from the specified baseline.
        
        Args:
            baseline_name: Name of the baseline to compare against
            
        Returns:
            List of detected drift events
        """
        baseline = self._baselines.get(baseline_name)
        if not baseline:
            return []
        
        drift_events = []
        current_time = datetime.now(timezone.utc)
        
        # Detect control drift
        control_drift = self._detect_control_drift(baseline, current_time)
        drift_events.extend(control_drift)
        
        # Detect policy drift
        policy_drift = self._detect_policy_drift(baseline, current_time)
        drift_events.extend(policy_drift)
        
        # Detect mapping drift
        mapping_drift = self._detect_mapping_drift(baseline, current_time)
        drift_events.extend(mapping_drift)
        
        # Store and notify
        with self._lock:
            for event in drift_events:
                self._drift_events.append(event)
                for handler in self._drift_handlers:
                    try:
                        handler(event)
                    except Exception:
                        pass
        
        return drift_events

    def _detect_control_drift(self, baseline: BaselineSnapshot, current_time: datetime) -> List[DriftEvent]:
        """Detect drift in control states.
        
        Args:
            baseline: Baseline snapshot
            current_time: Current timestamp
            
        Returns:
            List of drift events
        """
        events = []
        
        for ctrl_id, baseline_ctrl in baseline.controls_state.items():
            current_ctrl = self.store.controls.get(ctrl_id)
            
            if not current_ctrl:
                # Control was removed
                event = DriftEvent(
                    event_id=hashlib.md5(f"{ctrl_id}_removed{current_time}".encode()).hexdigest()[:16],
                    drift_type="CONTROL_REMOVED",
                    severity="CRITICAL",
                    description=f"Control {ctrl_id} has been removed",
                    affected_entities=[ctrl_id],
                    previous_state=baseline_ctrl,
                    current_state={},
                    recommended_actions=["Re-implement control", "Assess compliance impact"],
                )
                events.append(event)
                continue
            
            # Check for status changes
            baseline_status = baseline_ctrl.get("status")
            current_status = current_ctrl.get("status")
            
            if baseline_status != current_status:
                # Determine severity based on new status
                severity_map = {
                    "NON_COMPLIANT": "HIGH",
                    "PARTIALLY_COMPLIANT": "MEDIUM",
                    "COMPLIANT": "LOW",
                }
                severity = severity_map.get(current_status, "MEDIUM")
                
                event = DriftEvent(
                    event_id=hashlib.md5(f"{ctrl_id}_status{current_time}".encode()).hexdigest()[:16],
                    drift_type="CONTROL_STATUS_CHANGED",
                    severity=severity,
                    description=f"Control {ctrl_id} status changed from {baseline_status} to {current_status}",
                    affected_entities=[ctrl_id],
                    previous_state={"status": baseline_status},
                    current_state={"status": current_status},
                    recommended_actions=self._get_recommended_actions_for_status_change(
                        baseline_status, current_status
                    ),
                )
                events.append(event)
            
            # Check for effectiveness changes
            baseline_eff = baseline_ctrl.get("effectiveness")
            current_eff = current_ctrl.get("effectiveness")
            
            if baseline_eff and current_eff and baseline_eff != current_eff:
                event = DriftEvent(
                    event_id=hashlib.md5(f"{ctrl_id}_effectiveness{current_time}".encode()).hexdigest()[:16],
                    drift_type="CONTROL_EFFECTIVENESS_CHANGED",
                    severity="HIGH",
                    description=f"Control {ctrl_id} effectiveness changed from {baseline_eff} to {current_eff}",
                    affected_entities=[ctrl_id],
                    previous_state={"effectiveness": baseline_eff},
                    current_state={"effectiveness": current_eff},
                    recommended_actions=["Review control implementation", "Consider remediation"],
                )
                events.append(event)
        
        # Check for new controls
        for ctrl_id in self.store.controls:
            if ctrl_id not in baseline.controls_state:
                event = DriftEvent(
                    event_id=hashlib.md5(f"{ctrl_id}_new{current_time}".encode()).hexdigest()[:16],
                    drift_type="NEW_CONTROL_ADDED",
                    severity="LOW",
                    description=f"New control {ctrl_id} has been added",
                    affected_entities=[ctrl_id],
                    previous_state={},
                    current_state=self.store.controls[ctrl_id],
                    recommended_actions=["Review new control mapping", "Update baseline"],
                )
                events.append(event)
        
        return events

    def _detect_policy_drift(self, baseline: BaselineSnapshot, current_time: datetime) -> List[DriftEvent]:
        """Detect drift in policy states.
        
        Args:
            baseline: Baseline snapshot
            current_time: Current timestamp
            
        Returns:
            List of drift events
        """
        events = []
        
        for policy_id, baseline_policy in baseline.policies_state.items():
            current_policy = self.store.policies.get(policy_id)
            
            if not current_policy:
                event = DriftEvent(
                    event_id=hashlib.md5(f"{policy_id}_removed{current_time}".encode()).hexdigest()[:16],
                    drift_type="POLICY_REMOVED",
                    severity="HIGH",
                    description=f"Policy {policy_id} has been removed",
                    affected_entities=[policy_id],
                    previous_state=baseline_policy,
                    current_state={},
                    recommended_actions=["Re-implement policy", "Assess regulatory impact"],
                )
                events.append(event)
                continue
            
            # Check for version changes
            if baseline_policy.get("version") != current_policy.get("version"):
                event = DriftEvent(
                    event_id=hashlib.md5(f"{policy_id}_version{current_time}".encode()).hexdigest()[:16],
                    drift_type="POLICY_UPDATED",
                    severity="MEDIUM",
                    description=f"Policy {policy_id} updated from v{baseline_policy.get('version')} to v{current_policy.get('version')}",
                    affected_entities=[policy_id],
                    previous_state={"version": baseline_policy.get("version")},
                    current_state={"version": current_policy.get("version")},
                    recommended_actions=["Review policy changes", "Update related controls"],
                )
                events.append(event)
        
        return events

    def _detect_mapping_drift(self, baseline: BaselineSnapshot, current_time: datetime) -> List[DriftEvent]:
        """Detect drift in control-regulation mappings.
        
        Args:
            baseline: Baseline snapshot
            current_time: Current timestamp
            
        Returns:
            List of drift events
        """
        events = []
        
        # Check for removed mappings
        for mapping_id, baseline_mapping in baseline.mappings_state.items():
            if mapping_id not in self.store.control_mappings:
                event = DriftEvent(
                    event_id=hashlib.md5(f"{mapping_id}_removed{current_time}".encode()).hexdigest()[:16],
                    drift_type="MAPPING_REMOVED",
                    severity="MEDIUM",
                    description=f"Control mapping {mapping_id} has been removed",
                    affected_entities=[
                        baseline_mapping.get("regulation_id", ""),
                        baseline_mapping.get("control_id", ""),
                    ],
                    previous_state=baseline_mapping,
                    current_state={},
                    recommended_actions=["Review mapping removal impact", "Update compliance documentation"],
                )
                events.append(event)
        
        return events

    def _get_recommended_actions_for_status_change(self, old_status: str, new_status: str) -> List[str]:
        """Get recommended actions for status changes."""
        if new_status == "NON_COMPLIANT":
            return [
                "Immediate investigation required",
                "Implement remediation plan",
                "Document root cause",
                "Update risk register",
            ]
        elif new_status == "PARTIALLY_COMPLIANT":
            return [
                "Complete remaining implementation",
                "Schedule follow-up assessment",
                "Document gaps",
            ]
        elif new_status == "COMPLIANT":
            return [
                "Update compliance dashboard",
                "Schedule maintenance review",
            ]
        return ["Review and assess"]

    def register_drift_handler(self, handler: callable) -> None:
        """Register a handler to be called when drift is detected.
        
        Args:
            handler: Function to call with DriftEvent
        """
        with self._lock:
            self._drift_handlers.append(handler)

    def get_drift_events(
        self,
        drift_type: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get drift events with optional filtering.
        
        Args:
            drift_type: Filter by drift type
            severity: Filter by severity
            since: Only events after this time
            limit: Maximum events to return
            
        Returns:
            List of drift event dictionaries
        """
        events = self._drift_events
        
        if drift_type:
            events = [e for e in events if e.drift_type == drift_type]
        if severity:
            events = [e for e in events if e.severity == severity]
        if since:
            events = [e for e in events if e.detected_at >= since]
        
        return [
            {
                "event_id": e.event_id,
                "drift_type": e.drift_type,
                "severity": e.severity,
                "description": e.description,
                "affected_entities": e.affected_entities,
                "detected_at": e.detected_at.isoformat(),
                "previous_state": e.previous_state,
                "current_state": e.current_state,
                "recommended_actions": e.recommended_actions,
            }
            for e in events[-limit:]
        ]

    def get_drift_summary(self) -> Dict[str, Any]:
        """Get a summary of current drift state."""
        if not self._drift_events:
            return {
                "total_events": 0,
                "by_severity": {},
                "by_type": {},
                "last_event": None,
            }
        
        recent_events = [e for e in self._drift_events 
                       if e.detected_at >= datetime.now(timezone.utc) - timedelta(days=7)]
        
        by_severity = {}
        by_type = {}
        
        for event in recent_events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
            by_type[event.drift_type] = by_type.get(event.drift_type, 0) + 1
        
        return {
            "total_events": len(recent_events),
            "by_severity": by_severity,
            "by_type": by_type,
            "last_event": self._drift_events[-1].detected_at.isoformat() if self._drift_events else None,
        }


def get_drift_detector() -> ComplianceDriftDetector:
    """Get the global drift detector instance."""
    from .store import get_compliance_store
    store = get_compliance_store()
    return ComplianceDriftDetector(store)