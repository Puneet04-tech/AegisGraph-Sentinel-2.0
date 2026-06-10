"""
Risk Engine for Adaptive Authentication & Continuous Authorization.

Evaluates multiple risk signals to compute a comprehensive risk score
for authentication and authorization decisions.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional
import math

from .models import (
    AuthenticationSession,
    BehaviorProfile,
    RiskLevel,
    RiskSignal,
    RiskScore,
)
from .store import AdaptiveAuthStore, get_adaptive_auth_store


# Signal weights for risk calculation
DEFAULT_WEIGHTS = {
    "device_reputation": 0.15,
    "location_risk": 0.18,
    "ip_reputation": 0.12,
    "velocity": 0.20,
    "behavioral_biometrics": 0.15,
    "impossible_travel": 0.10,
    "threat_intelligence": 0.10,
}


@dataclass
class SignalConfig:
    """Configuration for a risk signal."""
    name: str
    weight: float
    enabled: bool = True
    thresholds: Dict[str, float] = None
    
    def __post_init__(self):
        if self.thresholds is None:
            self.thresholds = {}


class RiskSignalEvaluator:
    """Evaluates individual risk signals."""
    
    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
        self._ip_reputation_cache: Dict[str, float] = {}
        self._known_malicious_ips: set = set()
        self._known_vpn_ips: set = set()
        self._known_tor_exits: set = set()
    
    def evaluate_device_reputation(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> RiskSignal:
        """Evaluate device reputation risk."""
        device_fp = session.device_fingerprint
        
        # Check if device is known
        is_known_device = device_fp in profile.typical_devices if profile.typical_devices else False
        
        # Calculate score based on device history
        if not device_fp:
            score = 0.5  # Unknown device
        elif is_known_device:
            score = 0.0  # Known trusted device
        else:
            # New but not necessarily malicious
            score = 0.3
        
        return RiskSignal(
            signal_type="device_reputation",
            value=score,
            weight=DEFAULT_WEIGHTS["device_reputation"],
            source="device_fingerprint",
            timestamp=datetime.now(timezone.utc),
            metadata={
                "device_fingerprint": device_fp[:16] + "..." if device_fp else "none",
                "is_known": is_known_device,
            },
        )
    
    def evaluate_location_risk(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> RiskSignal:
        """Evaluate location-based risk."""
        location = session.location
        user_locations = set(profile.typical_locations) if profile.typical_locations else set()
        
        if not location:
            score = 0.3  # Unknown location
        else:
            current_location = location.get("country", "") + ":" + location.get("city", "")
            
            if current_location in user_locations:
                score = 0.0  # Known location
            elif user_locations:
                # Check if same country
                current_country = location.get("country", "")
                known_countries = set(loc.split(":")[0] for loc in user_locations)
                if current_country in known_countries:
                    score = 0.15  # Same country, different city
                else:
                    score = 0.5  # Different country
            else:
                score = 0.2  # First login, no profile yet
        
        return RiskSignal(
            signal_type="location_risk",
            value=score,
            weight=DEFAULT_WEIGHTS["location_risk"],
            source="geoip",
            timestamp=datetime.now(timezone.utc),
            metadata={
                "location": location,
                "typical_locations": list(user_locations)[:5],
            },
        )
    
    def evaluate_ip_reputation(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> RiskSignal:
        """Evaluate IP reputation risk."""
        ip = session.ip_address
        
        # Check cache first
        if ip in self._ip_reputation_cache:
            score = self._ip_reputation_cache[ip]
        else:
            # Calculate IP reputation score
            score = self._calculate_ip_score(ip)
            self._ip_reputation_cache[ip] = score
        
        return RiskSignal(
            signal_type="ip_reputation",
            value=score,
            weight=DEFAULT_WEIGHTS["ip_reputation"],
            source="ip_reputation_db",
            timestamp=datetime.now(timezone.utc),
            metadata={
                "ip_address": ip,
                "is_vpn": ip in self._known_vpn_ips,
                "is_tor": ip in self._known_tor_exits,
                "is_malicious": ip in self._known_malicious_ips,
            },
        )
    
    def _calculate_ip_score(self, ip: str) -> float:
        """Calculate IP reputation score."""
        if not ip:
            return 0.3
        
        # Check against known lists
        if ip in self._known_malicious_ips:
            return 1.0
        if ip in self._known_tor_exits:
            return 0.7
        if ip in self._known_vpn_ips:
            return 0.4
        
        # Heuristic checks for demonstration
        # In production, this would query external threat intelligence
        score = 0.0
        
        # Check for private/local IPs (usually lower risk)
        if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.", "127.")):
            score = 0.0
        
        return score
    
    def evaluate_velocity(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> RiskSignal:
        """Evaluate velocity-based risk (rapid actions, unusual frequency)."""
        recent_actions = session.recent_actions
        
        if not recent_actions:
            score = 0.0
        else:
            # Count actions in last minute
            now = datetime.now(timezone.utc)
            recent_count = sum(
                1 for a in recent_actions
                if (now - datetime.fromisoformat(a.get("timestamp", now.isoformat()))).total_seconds() < 60
            )
            
            # Compare against velocity limits
            limit = profile.velocity_limits.get("actions_per_minute", 10)
            
            if recent_count > limit:
                score = min(1.0, (recent_count - limit) / limit + 0.5)
            else:
                score = 0.0
        
        return RiskSignal(
            signal_type="velocity",
            value=score,
            weight=DEFAULT_WEIGHTS["velocity"],
            source="action_tracking",
            timestamp=datetime.now(timezone.utc),
            metadata={
                "recent_action_count": len(recent_actions),
                "velocity_limit": profile.velocity_limits.get("actions_per_minute", 10),
            },
        )
    
    def evaluate_behavioral_biometrics(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
        context: Dict[str, Any],
    ) -> RiskSignal:
        """Evaluate behavioral biometrics risk."""
        # In production, this would analyze typing patterns, mouse movements, etc.
        # For now, we use session metadata as a proxy
        
        session_patterns = session.metadata.get("behavioral_patterns", {})
        typical_patterns = profile.typical_transaction_patterns
        
        if not session_patterns or not typical_patterns:
            score = 0.2  # Not enough data
        else:
            # Calculate deviation from typical patterns
            deviation = self._calculate_pattern_deviation(session_patterns, typical_patterns)
            score = min(1.0, deviation)
        
        return RiskSignal(
            signal_type="behavioral_biometrics",
            value=score,
            weight=DEFAULT_WEIGHTS["behavioral_biometrics"],
            source="behavior_analysis",
            timestamp=datetime.now(timezone.utc),
            metadata={"deviation_detected": score > 0.5},
        )
    
    def _calculate_pattern_deviation(
        self,
        session_patterns: Dict[str, Any],
        typical_patterns: Dict[str, Any],
    ) -> float:
        """Calculate deviation from typical patterns."""
        # Simplified deviation calculation
        deviations = []
        
        for key in ["transaction_amount", "transaction_frequency", "time_of_activity"]:
            session_val = session_patterns.get(key, 0)
            typical_val = typical_patterns.get(key, 0)
            
            if typical_val > 0:
                deviation = abs(session_val - typical_val) / typical_val
                deviations.append(deviation)
        
        return sum(deviations) / len(deviations) if deviations else 0.0
    
    def evaluate_impossible_travel(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> RiskSignal:
        """Evaluate impossible travel risk."""
        recent_actions = session.recent_actions
        score = 0.0
        locations_compared = 0
        time_since_last = None
        
        if len(recent_actions) >= 2:
            # Find two most recent actions with locations
            actions_with_location = [
                a for a in recent_actions
                if a.get("location")
            ]
            
            if len(actions_with_location) >= 2:
                # Get the two most recent
                latest = actions_with_location[-1]
                previous = actions_with_location[-2]
                
                # Calculate time difference
                latest_time = datetime.fromisoformat(latest.get("timestamp", datetime.now(timezone.utc).isoformat()))
                prev_time = datetime.fromisoformat(previous.get("timestamp", datetime.now(timezone.utc).isoformat()))
                time_diff_hours = (latest_time - prev_time).total_seconds() / 3600
                time_since_last = time_diff_hours
                locations_compared = len(actions_with_location)
                
                if time_diff_hours > 0:
                    # Estimate distance (simplified - in production use actual geo calculation)
                    # For demo, use location hash difference
                    latest_loc = latest.get("location", {})
                    prev_loc = previous.get("location", {})
                    
                    # Simple distance proxy using country/city
                    latest_key = f"{latest_loc.get('country')}:{latest_loc.get('city')}"
                    prev_key = f"{prev_loc.get('country')}:{prev_loc.get('city')}"
                    
                    if latest_key != prev_key:
                        # Different location - check if travel is possible
                        # Assume max realistic travel speed of 1000 km/h (plane)
                        # If locations are in different continents, assume 12+ hours
                        if latest_loc.get("country") != prev_loc.get("country"):
                            # Different countries
                            score = 0.8  # Likely impossible
                        else:
                            score = 0.3  # Same country, might be possible
        
        return RiskSignal(
            signal_type="impossible_travel",
            value=score,
            weight=DEFAULT_WEIGHTS["impossible_travel"],
            source="location_tracking",
            timestamp=datetime.now(timezone.utc),
            metadata={
                "locations_compared": locations_compared,
                "time_since_last": time_since_last,
            },
        )
    
    def evaluate_threat_intelligence(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
    ) -> RiskSignal:
        """Evaluate threat intelligence signals."""
        # In production, this would query external threat intelligence feeds
        ip = session.ip_address
        
        score = 0.0
        threats_detected = []
        
        # Check known malicious sources
        if ip in self._known_malicious_ips:
            score = 1.0
            threats_detected.append("known_malicious_ip")
        
        if ip in self._known_tor_exits:
            score = max(score, 0.7)
            threats_detected.append("tor_exit_node")
        
        # Check for patterns associated with attacks
        user_agents = session.user_agent.lower() if session.user_agent else ""
        if any(pattern in user_agents for pattern in ["curl", "wget", "python-requests", "scanner"]):
            score = max(score, 0.5)
            threats_detected.append("suspicious_user_agent")
        
        return RiskSignal(
            signal_type="threat_intelligence",
            value=score,
            weight=DEFAULT_WEIGHTS["threat_intelligence"],
            source="threat_intel_feed",
            timestamp=datetime.now(timezone.utc),
            metadata={
                "threats_detected": threats_detected,
                "threat_count": len(threats_detected),
            },
        )


class RiskEngine:
    """
    Main risk evaluation engine.
    
    Combines multiple risk signals to compute comprehensive risk scores
    for authentication and authorization decisions.
    """
    
    def __init__(
        self,
        store: AdaptiveAuthStore,
        signal_weights: Optional[Dict[str, float]] = None,
    ):
        self.store = store
        self.signal_weights = signal_weights or DEFAULT_WEIGHTS.copy()
        self.evaluator = RiskSignalEvaluator(store)
        self._cache: Dict[str, float] = {}
        self._cache_ttl = 60  # seconds
    
    def evaluate_risk(
        self,
        session: AuthenticationSession,
        profile: BehaviorProfile,
        context: Optional[Dict[str, Any]] = None,
    ) -> RiskScore:
        """Evaluate risk for a session."""
        signals = []
        
        # Evaluate all signals
        signals.append(self.evaluator.evaluate_device_reputation(session, profile))
        signals.append(self.evaluator.evaluate_location_risk(session, profile))
        signals.append(self.evaluator.evaluate_ip_reputation(session, profile))
        signals.append(self.evaluator.evaluate_velocity(session, profile))
        signals.append(self.evaluator.evaluate_behavioral_biometrics(session, profile, context or {}))
        signals.append(self.evaluator.evaluate_impossible_travel(session, profile))
        signals.append(self.evaluator.evaluate_threat_intelligence(session, profile))
        
        # Calculate overall risk score
        risk_score = RiskScore.calculate(
            session_id=session.session_id,
            user_id=session.user_id,
            signals=signals,
        )
        
        # Store the score
        self.store.store_risk_score(risk_score)
        
        # Update session with latest risk score
        session.current_risk_score = risk_score
        self.store.update_session(session)
        
        return risk_score
    
    def evaluate_login_risk(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str,
        location: Optional[Dict[str, Any]] = None,
    ) -> RiskScore:
        """Evaluate risk for a login attempt."""
        # Create or get session
        profile = self.store.get_or_create_profile(user_id)
        
        session = self.store.create_session(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            location=location,
            ttl_minutes=30,
        )
        
        return self.evaluate_risk(session, profile)
    
    def evaluate_action_risk(
        self,
        session: AuthenticationSession,
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> RiskScore:
        """Evaluate risk for a specific action within a session."""
        profile = self.store.get_or_create_profile(session.user_id)
        
        # Record the action
        session.add_action({
            "action": action,
            "resource": resource,
            "context": context or {},
        })
        
        return self.evaluate_risk(session, profile, context)
    
    def get_risk_level_from_score(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    def should_require_step_up(self, risk_score: RiskScore) -> bool:
        """Determine if step-up authentication is required."""
        return risk_score.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    
    def update_ip_reputation(
        self,
        ip: str,
        is_malicious: bool = False,
        is_vpn: bool = False,
        is_tor: bool = False,
    ) -> None:
        """Update IP reputation data."""
        if is_malicious:
            self.evaluator._known_malicious_ips.add(ip)
        if is_vpn:
            self.evaluator._known_vpn_ips.add(ip)
        if is_tor:
            self.evaluator._known_tor_exits.add(ip)
        
        # Recalculate reputation score
        self.evaluator._ip_reputation_cache[ip] = self._calculate_ip_reputation_score(ip)
    
    def _calculate_ip_reputation_score(self, ip: str) -> float:
        """Calculate IP reputation score for caching."""
        if ip in self.evaluator._known_malicious_ips:
            return 1.0
        if ip in self.evaluator._known_tor_exits:
            return 0.7
        if ip in self.evaluator._known_vpn_ips:
            return 0.4
        return 0.0


# Global engine instance
_engine: Optional[RiskEngine] = None


def get_risk_engine() -> RiskEngine:
    """Get the global risk engine instance."""
    global _engine
    if _engine is None:
        store = get_adaptive_auth_store()
        _engine = RiskEngine(store)
    return _engine


def reset_engine() -> None:
    """Reset the engine (for testing)."""
    global _engine
    _engine = None