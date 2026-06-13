"""
Insider Threat Detector Module.

Insider risk detection and behavior monitoring.
"""

import random
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
        baseline = BehavioralBaseline(
            employee_id=employee_id,
            activity_type=activity_type,
            avg_frequency=random.uniform(1, 10),
            avg_duration=random.uniform(30, 300),
            typical_hours=list(range(8, 18)),
            typical_locations=["HQ"],
            typical_devices=["LAPTOP-001"],
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
        anomalies, risk_score = self._detect_anomalies(employee_id, activity_type)
        
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
    
    def _detect_anomalies(self, employee_id: str, activity_type: ActivityType) -> tuple:
        """Detect anomalies in activity."""
        anomalies = []
        risk_score = 0.0
        
        # Simulate anomaly detection
        if random.random() < 0.1:  # 10% chance of anomaly
            anomalies.append("UNUSUAL_TIME")
            risk_score += 0.2
        
        if random.random() < 0.05:  # 5% chance
            anomalies.append("UNUSUAL_LOCATION")
            risk_score += 0.3
        
        if random.random() < 0.03:  # 3% chance
            anomalies.append("HIGH_VOLUME_DATA_ACCESS")
            risk_score += 0.4
        
        if random.random() < 0.02:  # 2% chance
            anomalies.append("PRIVILEGE_ESCALATION")
            risk_score += 0.5
        
        return anomalies, min(1.0, risk_score)
    
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