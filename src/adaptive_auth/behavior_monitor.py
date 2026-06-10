"""
Behavior Monitoring Engine for Adaptive Authentication & Continuous Authorization.

Monitors user behavior patterns, detects anomalies, and maintains
behavioral profiles for risk assessment.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from .models import (
    AuthenticationSession,
    BehaviorProfile,
    RiskLevel,
)
from .store import AdaptiveAuthStore, get_adaptive_auth_store


@dataclass
class BehaviorAnomaly:
    """Detected behavioral anomaly."""
    anomaly_id: str
    user_id: str
    session_id: str
    anomaly_type: str
    severity: str
    description: str
    detected_at: datetime
    factors: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


@dataclass
class AnomalyDetectionResult:
    """Result of anomaly detection analysis."""
    is_anomalous: bool
    anomaly_score: float
    anomalies: List[BehaviorAnomaly]
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)


class BehaviorAnalyzer:
    """Analyzes behavior patterns and detects anomalies."""
    
    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
    
    def analyze_session_behavior(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> AnomalyDetectionResult:
        """Analyze session behavior against user profile."""
        anomalies = []
        anomaly_types_detected = defaultdict(int)
        
        # Check login time patterns
        time_anomaly = self._check_login_time(session, profile)
        if time_anomaly:
            anomalies.append(time_anomaly)
            anomaly_types_detected["login_time"] += 1
        
        # Check location patterns
        location_anomaly = self._check_location_pattern(session, profile)
        if location_anomaly:
            anomalies.append(location_anomaly)
            anomaly_types_detected["location"] += 1
        
        # Check device patterns
        device_anomaly = self._check_device_pattern(session, profile)
        if device_anomaly:
            anomalies.append(device_anomaly)
            anomaly_types_detected["device"] += 1
        
        # Check IP patterns
        ip_anomaly = self._check_ip_pattern(session, profile)
        if ip_anomaly:
            anomalies.append(ip_anomaly)
            anomaly_types_detected["ip"] += 1
        
        # Check action velocity
        velocity_anomaly = self._check_action_velocity(session, profile)
        if velocity_anomaly:
            anomalies.append(velocity_anomaly)
            anomaly_types_detected["velocity"] += 1
        
        # Calculate overall anomaly score
        is_anomalous = len(anomalies) > 0
        anomaly_score = self._calculate_anomaly_score(anomalies)
        confidence = self._calculate_confidence(profile)
        
        return AnomalyDetectionResult(
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score,
            anomalies=anomalies,
            confidence=confidence,
            details={
                "anomaly_types": dict(anomaly_types_detected),
                "profile_maturity": "mature" if profile.is_mature else "immature",
            },
        )
    
    def _check_login_time(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> Optional[BehaviorAnomaly]:
        """Check if login time is unusual."""
        if not profile.typical_login_times:
            return None
        
        login_hour = session.created_at.hour
        typical_hours = []
        
        for time_str in profile.typical_login_times:
            try:
                # Parse time string (e.g., "09:00", "14:30")
                hour, minute = map(int, time_str.split(":"))
                typical_hours.append(hour + minute / 60)
            except (ValueError, AttributeError):
                continue
        
        if not typical_hours:
            return None
        
        # Check if current hour is within typical range
        current_time = login_hour + session.created_at.minute / 60
        
        # Calculate distance from nearest typical time
        min_distance = min(abs(current_time - t) for t in typical_hours)
        # Handle wrap-around at midnight
        min_distance = min(min_distance, 24 - min_distance)
        
        if min_distance > 6:  # More than 6 hours from any typical time
            return BehaviorAnomaly(
                anomaly_id=str(uuid.uuid4()),
                user_id=session.user_id,
                session_id=session.session_id,
                anomaly_type="login_time",
                severity="medium",
                description=f"Unusual login time: {login_hour}:00 (typical: {', '.join(profile.typical_login_times)})",
                detected_at=datetime.now(timezone.utc),
                factors={
                    "login_hour": login_hour,
                    "typical_hours": profile.typical_login_times,
                    "deviation_hours": min_distance,
                },
            )
        
        return None
    
    def _check_location_pattern(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> Optional[BehaviorAnomaly]:
        """Check if login location is unusual."""
        if not session.location or not profile.typical_locations:
            return None
        
        current_location = f"{session.location.get('country', '')}:{session.location.get('city', '')}"
        
        if current_location not in profile.typical_locations:
            # Check if at least country is known
            current_country = session.location.get('country', '')
            known_countries = set(loc.split(":")[0] for loc in profile.typical_locations)
            
            if current_country and current_country not in known_countries:
                return BehaviorAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    user_id=session.user_id,
                    session_id=session.session_id,
                    anomaly_type="location",
                    severity="high",
                    description=f"Login from unknown country: {current_country}",
                    detected_at=datetime.now(timezone.utc),
                    factors={
                        "current_location": current_location,
                        "typical_locations": profile.typical_locations,
                    },
                )
            elif current_country:
                # Different city but same country
                return BehaviorAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    user_id=session.user_id,
                    session_id=session.session_id,
                    anomaly_type="location",
                    severity="low",
                    description=f"Login from different city: {session.location.get('city', 'unknown')}",
                    detected_at=datetime.now(timezone.utc),
                    factors={
                        "current_location": current_location,
                        "typical_locations": profile.typical_locations,
                    },
                )
        
        return None
    
    def _check_device_pattern(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> Optional[BehaviorAnomaly]:
        """Check if device is unusual."""
        if not session.device_fingerprint or not profile.typical_devices:
            return None
        
        if session.device_fingerprint not in profile.typical_devices:
            return BehaviorAnomaly(
                anomaly_id=str(uuid.uuid4()),
                user_id=session.user_id,
                session_id=session.session_id,
                anomaly_type="device",
                severity="medium",
                description="Login from unknown device",
                detected_at=datetime.now(timezone.utc),
                factors={
                    "device_fingerprint": session.device_fingerprint[:16] + "...",
                    "known_devices": len(profile.typical_devices),
                },
            )
        
        return None
    
    def _check_ip_pattern(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> Optional[BehaviorAnomaly]:
        """Check if IP address is unusual."""
        if not session.ip_address or not profile.typical_ip_ranges:
            return None
        
        ip = session.ip_address
        is_in_range = False
        
        for ip_range in profile.typical_ip_ranges:
            if self._ip_in_range(ip, ip_range):
                is_in_range = True
                break
        
        if not is_in_range:
            return BehaviorAnomaly(
                anomaly_id=str(uuid.uuid4()),
                user_id=session.user_id,
                session_id=session.session_id,
                anomaly_type="ip_address",
                severity="medium",
                description=f"Login from unexpected IP range: {ip}",
                detected_at=datetime.now(timezone.utc),
                factors={
                    "ip_address": ip,
                    "typical_ranges": profile.typical_ip_ranges,
                },
            )
        
        return None
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in CIDR range."""
        try:
            if "/" not in ip_range:
                return ip == ip_range
            
            # Simple CIDR check
            ip_parts = [int(p) for p in ip.split(".")]
            range_parts, bits = ip_range.split("/")
            range_ip_parts = [int(p) for p in range_parts.split(".")]
            prefix_len = int(bits)
            
            # Calculate network address
            ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
            range_int = (range_ip_parts[0] << 24) + (range_ip_parts[1] << 16) + (range_ip_parts[2] << 8) + range_ip_parts[3]
            
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            
            return (ip_int & mask) == (range_int & mask)
        except (ValueError, IndexError):
            return False
    
    def _check_action_velocity(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> Optional[BehaviorAnomaly]:
        """Check if action velocity is unusual."""
        if not session.recent_actions:
            return None
        
        # Calculate actions per minute
        now = datetime.now(timezone.utc)
        actions_last_minute = 0
        actions_last_5_minutes = 0
        
        for action in session.recent_actions:
            try:
                action_time = datetime.fromisoformat(action.get("timestamp", now.isoformat()))
                age_seconds = (now - action_time).total_seconds()
                
                if age_seconds < 60:
                    actions_last_minute += 1
                if age_seconds < 300:
                    actions_last_5_minutes += 1
            except (ValueError, TypeError):
                continue
        
        # Get velocity limits
        limit_per_minute = profile.velocity_limits.get("actions_per_minute", 10)
        limit_per_5_min = profile.velocity_limits.get("actions_per_5_minutes", 30)
        
        if actions_last_minute > limit_per_minute:
            return BehaviorAnomaly(
                anomaly_id=str(uuid.uuid4()),
                user_id=session.user_id,
                session_id=session.session_id,
                anomaly_type="velocity",
                severity="high",
                description=f"Excessive action velocity: {actions_last_minute} actions/min (limit: {limit_per_minute})",
                detected_at=datetime.now(timezone.utc),
                factors={
                    "actions_per_minute": actions_last_minute,
                    "limit": limit_per_minute,
                    "actions_per_5_minutes": actions_last_5_minutes,
                },
            )
        
        return None
    
    def _calculate_anomaly_score(self, anomalies: List[BehaviorAnomaly]) -> float:
        """Calculate overall anomaly score from individual anomalies."""
        if not anomalies:
            return 0.0
        
        severity_weights = {
            "low": 0.2,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1.0,
        }
        
        total_score = sum(severity_weights.get(a.severity, 0.3) for a in anomalies)
        # Normalize to 0-1 range
        return min(1.0, total_score / len(anomalies) * 1.5)
    
    def _calculate_confidence(self, profile: BehaviorProfile) -> float:
        """Calculate confidence in anomaly detection based on profile maturity."""
        if profile.is_mature:
            return 0.9
        elif len(profile.risk_history) >= 5:
            return 0.7
        elif len(profile.risk_history) >= 2:
            return 0.5
        return 0.3


class BehaviorMonitor:
    """
    Main behavior monitoring engine.
    
    Monitors user behavior, maintains profiles, and detects anomalies
    for continuous risk assessment.
    """
    
    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
        self.analyzer = BehaviorAnalyzer(store)
        self._anomaly_cache: Dict[str, BehaviorAnomaly] = {}
    
    def record_action(
        self,
        session: AuthenticationSession,
        action: str,
        resource: str,
        outcome: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a user action for behavior analysis."""
        session.add_action({
            "action": action,
            "resource": resource,
            "outcome": outcome,
            "metadata": metadata or {},
        })
        self.store.update_session(session)
    
    def analyze_behavior(
        self,
        session: AuthenticationSession,
    ) -> AnomalyDetectionResult:
        """Analyze session behavior and detect anomalies."""
        profile = self.store.get_or_create_profile(session.user_id)
        result = self.analyzer.analyze_session_behavior(session, profile)
        
        # Cache anomalies
        for anomaly in result.anomalies:
            self._anomaly_cache[anomaly.anomaly_id] = anomaly
        
        return result
    
    def update_profile_from_session(self, session: AuthenticationSession) -> BehaviorProfile:
        """Update behavior profile based on session data."""
        profile = self.store.get_or_create_profile(session.user_id)
        
        # Update typical login time
        login_time = session.created_at.strftime("%H:%M")
        if login_time not in profile.typical_login_times:
            if len(profile.typical_login_times) < 10:  # Keep last 10
                profile.typical_login_times.append(login_time)
        
        # Update typical location
        if session.location:
            location = f"{session.location.get('country', '')}:{session.location.get('city', '')}"
            if location not in profile.typical_locations:
                if len(profile.typical_locations) < 10:
                    profile.typical_locations.append(location)
        
        # Update typical device
        if session.device_fingerprint and session.device_fingerprint not in profile.typical_devices:
            if len(profile.typical_devices) < 10:
                profile.typical_devices.append(session.device_fingerprint)
        
        # Update typical IP range
        if session.ip_address:
            # Extract /24 subnet
            ip_parts = session.ip_address.split(".")
            if len(ip_parts) == 4:
                subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                if subnet not in profile.typical_ip_ranges:
                    if len(profile.typical_ip_ranges) < 10:
                        profile.typical_ip_ranges.append(subnet)
        
        # Update velocity limits based on observed behavior
        if session.recent_actions:
            actions_per_minute = len([
                a for a in session.recent_actions
                if (datetime.now(timezone.utc) - datetime.fromisoformat(a.get("timestamp", datetime.now(timezone.utc).isoformat()))).total_seconds() < 60
            ])
            profile.velocity_limits["actions_per_minute"] = max(
                profile.velocity_limits.get("actions_per_minute", 10),
                int(actions_per_minute * 1.5)  # Allow 50% above observed
            )
        
        # Record risk history
        if session.current_risk_score:
            profile.risk_history.append({
                "timestamp": session.current_risk_score.timestamp.isoformat(),
                "score": session.current_risk_score.total_score,
                "level": session.current_risk_score.risk_level.value,
            })
            # Keep last 100 entries
            if len(profile.risk_history) > 100:
                profile.risk_history = profile.risk_history[-100:]
        
        # Update anomaly count
        profile.anomaly_count = len([
            a for a in self._anomaly_cache.values()
            if a.user_id == session.user_id and not a.resolved
        ])
        
        profile.last_updated = datetime.now(timezone.utc)
        self.store.update_profile(profile)
        
        return profile
    
    def get_user_anomalies(
        self,
        user_id: str,
        unresolved_only: bool = True,
    ) -> List[BehaviorAnomaly]:
        """Get anomalies for a user."""
        anomalies = [
            a for a in self._anomaly_cache.values()
            if a.user_id == user_id
        ]
        
        if unresolved_only:
            anomalies = [a for a in anomalies if not a.resolved]
        
        return sorted(anomalies, key=lambda a: a.detected_at, reverse=True)
    
    def resolve_anomaly(self, anomaly_id: str) -> bool:
        """Mark an anomaly as resolved."""
        if anomaly_id in self._anomaly_cache:
            anomaly = self._anomaly_cache[anomaly_id]
            anomaly.resolved = True
            anomaly.resolved_at = datetime.now(timezone.utc)
            return True
        return False
    
    def get_behavioral_drift(
        self,
        user_id: str,
        window_days: int = 30,
    ) -> Dict[str, Any]:
        """Calculate behavioral drift for a user."""
        profile = self.store.get_profile(user_id)
        if not profile:
            return {"drift_detected": False, "drift_score": 0.0}
        
        # Calculate drift from historical patterns
        drift_factors = []
        
        # Check login time drift
        if profile.typical_login_times and profile.risk_history:
            # Compare recent activity with historical patterns
            recent_count = len([
                h for h in profile.risk_history
                if datetime.fromisoformat(h["timestamp"]) > datetime.now(timezone.utc) - timedelta(days=7)
            ])
            historical_count = len(profile.risk_history) - recent_count
            
            if historical_count > 0:
                recent_ratio = recent_count / len(profile.risk_history)
                if recent_ratio > 0.5:  # More than 50% activity in last week
                    drift_factors.append(("login_frequency", 0.3))
        
        # Check risk score drift
        if len(profile.risk_history) >= 10:
            recent_scores = [
                h["score"] for h in profile.risk_history[-5:]
            ]
            older_scores = [
                h["score"] for h in profile.risk_history[:-5]
            ]
            
            if older_scores:
                recent_avg = statistics.mean(recent_scores)
                older_avg = statistics.mean(older_scores)
                score_drift = abs(recent_avg - older_avg)
                
                if score_drift > 0.2:
                    drift_factors.append(("risk_score", score_drift))
        
        drift_score = sum(d[1] for d in drift_factors) / len(drift_factors) if drift_factors else 0.0
        
        return {
            "drift_detected": drift_score > 0.15,
            "drift_score": drift_score,
            "drift_factors": dict(drift_factors),
            "profile_maturity": "mature" if profile.is_mature else "immature",
        }


# Global monitor instance
_monitor: Optional[BehaviorMonitor] = None


def get_behavior_monitor() -> BehaviorMonitor:
    """Get the global behavior monitor instance."""
    global _monitor
    if _monitor is None:
        store = get_adaptive_auth_store()
        _monitor = BehaviorMonitor(store)
    return _monitor


def reset_monitor() -> None:
    """Reset the monitor (for testing)."""
    global _monitor
    _monitor = None