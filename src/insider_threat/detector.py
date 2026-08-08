"""
Insider Threat Detector Module.

Insider risk detection and behavior monitoring.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    InsiderProfile,
    BehavioralBaseline,
    ActivityRecord,
    ThreatIndicator,
    ThreatLevel,
    ActivityType,
)
from .store import InsiderThreatStore, get_insider_store

logger = logging.getLogger(__name__)


class InsiderThreatDetector:
    """Insider Threat Detector.
    
    Provides:
        - Risk detection
        - Behavior monitoring
        - Anomaly detection
        - Campaign analysis
    """
    
    def __init__(self, store: Optional[InsiderThreatStore] = None):
        self._store = store or get_insider_store()
        self._module_id = "insider_detector"
    
    def create_profile(
        self,
        employee_id: str,
        department: str,
        role: str,
    ) -> InsiderProfile:
        """Create an insider threat profile."""
        profile = InsiderProfile(
            employee_id=employee_id,
            department=department,
            role=role,
        )
        return self._store.store_profile(profile)
    
    def establish_baseline(
        self,
        employee_id: str,
        activity_type: ActivityType,
        historical_data: List[Dict[str, Any]],
    ) -> BehavioralBaseline:
        """Establish behavioral baseline."""
        # Computed from the supplied history rather than
        # random.uniform(1, 10) / random.uniform(30, 300), which regenerated a
        # different "typical" behaviour every time it was consulted.
        records = list(historical_data or [])
        durations = [
            float(r.get("duration", r.get("duration_seconds", 0.0)) or 0.0)
            for r in records
        ]
        hours = sorted({
            int(h) for h in (r.get("hour") for r in records) if h is not None
        })
        locations = sorted({
            str(r["location"]) for r in records if r.get("location")
        })
        devices = sorted({
            str(r["device_id"]) for r in records if r.get("device_id")
        })

        baseline = BehavioralBaseline(
            employee_id=employee_id,
            activity_type=activity_type,
            avg_frequency=float(len(records)),
            avg_duration=(sum(durations) / len(durations)) if durations else 0.0,
            # Fall back to the previous defaults only when the history says
            # nothing, so an empty baseline is not silently authoritative.
            typical_hours=hours or list(range(8, 18)),
            typical_locations=locations or ["HQ"],
            typical_devices=devices or ["LAPTOP-001"],
        )

        # Update profile
        profile = self._store.get_employee_profile(employee_id)
        if profile:
            profile.baseline_established = True
            self._store.store_profile(profile)
        
        return self._store.store_baseline(baseline)
    
    def record_activity(
        self,
        employee_id: str,
        activity_type: ActivityType,
        resource: str,
        location: str,
        device_id: str,
        duration: float = 0.0,
        data_volume: int = 0,
    ) -> ActivityRecord:
        """Record employee activity."""
        # Detect anomalies
        anomalies, risk_score = self._detect_anomalies(
            employee_id,
            activity_type,
            hour=datetime.now(timezone.utc).hour,
            location=location,
            device_id=device_id,
            duration=duration,
            data_volume=data_volume,
        )
        
        activity = ActivityRecord(
            employee_id=employee_id,
            activity_type=activity_type,
            resource_accessed=resource,
            location=location,
            device_id=device_id,
            duration_seconds=duration,
            data_volume=data_volume,
            anomalies=anomalies,
            risk_score_contribution=risk_score,
        )
        
        self._store.store_activity(activity)
        
        # Update profile risk score
        self._update_risk_score(employee_id)
        
        # Generate indicators if needed
        if risk_score > 0.3:
            self._create_indicator(employee_id, activity, anomalies)
        
        return activity
    
    #: Duration this many times the baseline mean counts as anomalous.
    DURATION_DEVIATION_FACTOR = 3.0

    #: Data volume above this multiple of the baseline mean counts as bulk access.
    VOLUME_DEVIATION_FACTOR = 5.0

    def _detect_anomalies(
        self,
        employee_id: str,
        activity_type: ActivityType,
        hour: Optional[int] = None,
        location: Optional[str] = None,
        device_id: Optional[str] = None,
        duration: float = 0.0,
        data_volume: int = 0,
    ) -> tuple:
        """Detect anomalies by comparing an activity against its baseline.

        Each check previously fired on a `random.random()` comparison, so an
        employee doing nothing unusual had a 10% per-call chance of being
        reported for UNUSUAL_TIME. That is not a false-positive rate, it is
        noise, and the baseline it was measured against was itself random.
        """
        anomalies = []
        risk_score = 0.0

        baseline = self._get_baseline(employee_id, activity_type)
        if baseline is None:
            # Nothing to compare against. Report that rather than emitting
            # either an anomaly or a false all-clear.
            return ["INSUFFICIENT_BASELINE"], 0.0

        if hour is not None and baseline.typical_hours and hour not in baseline.typical_hours:
            anomalies.append("UNUSUAL_TIME")
            risk_score += 0.2

        if location and baseline.typical_locations and location not in baseline.typical_locations:
            anomalies.append("UNUSUAL_LOCATION")
            risk_score += 0.3

        if (
            baseline.avg_duration > 0
            and duration > baseline.avg_duration * self.DURATION_DEVIATION_FACTOR
        ):
            anomalies.append("HIGH_VOLUME_DATA_ACCESS")
            risk_score += 0.4

        if device_id and baseline.typical_devices and device_id not in baseline.typical_devices:
            anomalies.append("UNRECOGNISED_DEVICE")
            risk_score += 0.3

        return anomalies, min(1.0, risk_score)

    def _get_baseline(self, employee_id: str, activity_type: ActivityType):
        """Return the stored baseline for an employee and activity type."""
        try:
            baselines = self._store.get_employee_baselines(employee_id) or []
        except AttributeError:
            return None
        except Exception as exc:
            logger.warning("Baseline lookup failed for %s: %s", employee_id, exc)
            return None

        for baseline in baselines:
            if baseline.activity_type == activity_type:
                return baseline
        return None

    def _update_risk_score(self, employee_id: str) -> None:
        """Update employee risk score."""
        profile = self._store.get_employee_profile(employee_id)
        if not profile:
            return
        
        # Calculate new risk score from recent activities
        activities = self._store.get_employee_activities(employee_id, limit=50)
        if activities:
            avg_risk = sum(a.risk_score_contribution for a in activities) / len(activities)
            profile.risk_score = (profile.risk_score * 0.7) + (avg_risk * 0.3)
            profile.last_evaluated = datetime.now(timezone.utc)
            
            # Update threat level
            if profile.risk_score > 0.8:
                profile.threat_level = ThreatLevel.CRITICAL
            elif profile.risk_score > 0.6:
                profile.threat_level = ThreatLevel.HIGH
            elif profile.risk_score > 0.3:
                profile.threat_level = ThreatLevel.MEDIUM
            else:
                profile.threat_level = ThreatLevel.LOW
            
            self._store.store_profile(profile)
    
    def _create_indicator(
        self,
        employee_id: str,
        activity: ActivityRecord,
        anomalies: List[str],
    ) -> ThreatIndicator:
        """Create threat indicator."""
        severity = ThreatLevel.MEDIUM
        if "PRIVILEGE_ESCALATION" in anomalies:
            severity = ThreatLevel.CRITICAL
        elif "HIGH_VOLUME_DATA_ACCESS" in anomalies:
            severity = ThreatLevel.HIGH
        
        indicator = ThreatIndicator(
            employee_id=employee_id,
            indicator_type=", ".join(anomalies),
            severity=severity,
            description=f"Detected anomalies: {', '.join(anomalies)}",
            confidence=0.8,
            related_activities=[activity.activity_id],
        )
        
        return self._store.store_indicator(indicator)
    
    def get_high_risk_employees(self, threshold: float = 0.5) -> List[InsiderProfile]:
        """Get high-risk employees."""
        return [p for p in self._store._profiles.values() if p.risk_score >= threshold]
    
    def get_active_indicators(self) -> List[ThreatIndicator]:
        """Get active threat indicators."""
        return self._store.get_active_indicators()
    
    def resolve_indicator(self, indicator_id: str) -> ThreatIndicator:
        """Resolve a threat indicator."""
        indicator = self._store._indicators.get(indicator_id)
        if indicator:
            indicator.resolved = True
            self._store.store_indicator(indicator)
        return indicator


_detector: Optional[InsiderThreatDetector] = None


def get_insider_detector(store: Optional[InsiderThreatStore] = None) -> InsiderThreatDetector:
    global _detector
    if _detector is None:
        _detector = InsiderThreatDetector(store=store)
    return _detector