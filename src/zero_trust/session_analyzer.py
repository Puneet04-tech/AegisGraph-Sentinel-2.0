"""
Session Risk Analyzer for Zero Trust Security
"""

from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
from collections import defaultdict

from .models import SessionRisk, SessionRiskLevel, EvaluationContext
from .store import ZeroTrustStore, get_store


VELOCITY_THRESHOLD = 10
UNUSUAL_HOUR_THRESHOLD = (22, 6)


@dataclass
class BehavioralProfile:
    user_id: str
    typical_login_hours: List[int] = None
    typical_locations: List[str] = None
    typical_devices: List[str] = None
    average_session_duration: int = 1800
    behavioral_data_points: int = 0

    def __post_init__(self):
        if self.typical_login_hours is None:
            self.typical_login_hours = []
        if self.typical_locations is None:
            self.typical_locations = []
        if self.typical_devices is None:
            self.typical_devices = []


class SessionRiskAnalyzer:
    def __init__(self, store: Optional[ZeroTrustStore] = None):
        self.store = store or get_store()
        self.behavioral_profiles: Dict[str, BehavioralProfile] = {}
        self.login_attempts: Dict[str, List[float]] = defaultdict(list)
        self.anomaly_count = 0
        self.sessions_analyzed = 0

    def analyze_session(self, context: EvaluationContext, historical_data: Optional[Dict[str, Any]] = None) -> SessionRisk:
        self.sessions_analyzed += 1
        session = SessionRisk(session_id=context.session_id or self._generate_session_id(), user_id=context.user_id,
                              session_start=context.timestamp)
        profile = self._get_or_create_profile(context.user_id, historical_data)
        anomalies = []

        velocity_result = self._check_login_velocity(context.user_id)
        if velocity_result["anomaly"]:
            anomalies.append(f"High login velocity: {velocity_result['count']} attempts")
            session.velocity_anomaly = True

        location_risk = self._evaluate_location_risk(context)
        session.location_risk = location_risk
        if location_risk > 0.5:
            anomalies.append(f"High location risk: {location_risk:.2f}")

        behavior_deviation = self._detect_behavioral_anomaly(context, profile)
        session.behavior_deviation = behavior_deviation
        if behavior_deviation > 0.6:
            anomalies.append(f"Behavioral deviation: {behavior_deviation:.2f}")

        unusual_ops = self._detect_unusual_operations(context)
        session.unusual_operations = unusual_ops
        if unusual_ops:
            anomalies.append(f"Unusual operations detected: {len(unusual_ops)}")

        risk_score = self._calculate_session_risk_score(session, profile)
        risk_level = self._determine_risk_level(risk_score, anomalies)
        recommended_actions = self._generate_recommended_actions(risk_level, anomalies, session)

        session.risk_score = risk_score
        session.risk_level = risk_level
        session.anomalies_detected = anomalies
        session.context_risks = self._build_context_risks(context)
        session.recommended_actions = recommended_actions

        self.store.create_session_risk(session)
        self._update_behavioral_profile(context, profile)
        return session

    def _generate_session_id(self) -> str:
        return str(uuid.uuid4())

    def _get_or_create_profile(self, user_id: str, historical_data: Optional[Dict[str, Any]]) -> BehavioralProfile:
        if user_id in self.behavioral_profiles:
            return self.behavioral_profiles[user_id]
        profile = BehavioralProfile(user_id=user_id)
        if historical_data:
            profile.typical_login_hours = historical_data.get("login_hours", [])
            profile.typical_locations = historical_data.get("locations", [])
            profile.typical_devices = historical_data.get("devices", [])
            profile.average_session_duration = historical_data.get("avg_session_duration", 1800)
            profile.behavioral_data_points = historical_data.get("data_points", 0)
        self.behavioral_profiles[user_id] = profile
        return profile

    def _check_login_velocity(self, user_id: str) -> Dict[str, Any]:
        now = time.time()
        current_minute = now // 60
        recent_attempts = []
        for minute in range(int(current_minute) - 5, int(current_minute) + 1):
            key = f"{user_id}:{minute}"
            recent_attempts.extend(self.login_attempts.get(key, []))
        cutoff = now - 300
        for key in list(self.login_attempts.keys()):
            self.login_attempts[key] = [t for t in self.login_attempts[key] if t > cutoff]
            if not self.login_attempts[key]:
                del self.login_attempts[key]
        count = len([t for t in recent_attempts if t > cutoff])
        key = f"{user_id}:{current_minute}"
        self.login_attempts[key].append(now)
        return {"anomaly": count > VELOCITY_THRESHOLD, "count": count, "threshold": VELOCITY_THRESHOLD}

    def _evaluate_location_risk(self, context: EvaluationContext) -> float:
        risk = 0.0
        if context.ip_address:
            if self._is_vpn_ip(context.ip_address):
                risk += 0.2
            if self._is_tor_exit_node(context.ip_address):
                risk += 0.4
        if context.location:
            if context.location.get("city_change"):
                risk += 0.2
            if context.location.get("impossible_travel"):
                risk += 0.5
        current_hour = datetime.now(timezone.utc).hour
        if UNUSUAL_HOUR_THRESHOLD[0] <= current_hour or current_hour < UNUSUAL_HOUR_THRESHOLD[1]:
            risk += 0.1
        return min(1.0, risk)

    def _is_vpn_ip(self, ip_address: str) -> bool:
        return False

    def _is_tor_exit_node(self, ip_address: str) -> bool:
        return False

    def _detect_behavioral_anomaly(self, context: EvaluationContext, profile: BehavioralProfile) -> float:
        if profile.behavioral_data_points < 10:
            return 0.0
        anomaly_score = 0.0
        current_hour = datetime.now(timezone.utc).hour
        if profile.typical_login_hours:
            hour_variance = self._calculate_variance(current_hour, profile.typical_login_hours)
            anomaly_score += min(hour_variance * 0.3, 0.3)
        if context.location and profile.typical_locations:
            current_location = context.location.get("city", "")
            if current_location and current_location not in profile.typical_locations:
                anomaly_score += 0.2
        if context.device_id and profile.typical_devices:
            if context.device_id not in profile.typical_devices:
                anomaly_score += 0.15
        if context.authentication_strength < 0.5:
            anomaly_score += 0.2
        return min(1.0, anomaly_score)

    def _calculate_variance(self, value: int, typical_values: List[int]) -> float:
        if not typical_values:
            return 0.0
        avg = sum(typical_values) / len(typical_values)
        diff = abs(value - avg)
        return min(diff / 12.0, 1.0)

    def _detect_unusual_operations(self, context: EvaluationContext) -> List[str]:
        unusual_ops = []
        session_attrs = context.session_attributes
        if session_attrs.get("transaction_amount", 0) > 50000:
            unusual_ops.append("HIGH_VALUE_TRANSACTION")
        if session_attrs.get("api_pattern") == "unusual":
            unusual_ops.append("UNUSUAL_API_PATTERN")
        if session_attrs.get("bulk_access"):
            unusual_ops.append("BULK_DATA_ACCESS")
        if session_attrs.get("privilege_escalation_attempt"):
            unusual_ops.append("PRIVILEGE_ESCALATION")
        return unusual_ops

    def _calculate_session_risk_score(self, session: SessionRisk, profile: BehavioralProfile) -> float:
        risk = 0.0
        risk += session.location_risk * 0.30
        risk += session.behavior_deviation * 0.25
        if session.velocity_anomaly:
            risk += 0.25
        risk += min(len(session.unusual_operations) * 0.1, 0.20)
        return min(1.0, risk)

    def _determine_risk_level(self, risk_score: float, anomalies: List[str]) -> SessionRiskLevel:
        if risk_score >= 0.8 or len(anomalies) >= 4:
            return SessionRiskLevel.CRITICAL
        elif risk_score >= 0.6 or len(anomalies) >= 2:
            return SessionRiskLevel.HIGH
        elif risk_score >= 0.3:
            return SessionRiskLevel.MEDIUM
        return SessionRiskLevel.LOW

    def _generate_recommended_actions(self, risk_level: SessionRiskLevel, anomalies: List[str], session: SessionRisk) -> List[str]:
        actions = []
        if risk_level == SessionRiskLevel.CRITICAL:
            actions.extend(["TERMINATE_SESSION", "REQUIRE_REAUTHENTICATION", "ALERT_SECURITY_TEAM", "LOG_ALL_ACTIVITY"])
        elif risk_level == SessionRiskLevel.HIGH:
            actions.extend(["REQUIRE_MFA", "LIMIT_SESSION_PRIVILEGES", "ENHANCED_MONITORING", "NOTIFY_USER"])
        elif risk_level == SessionRiskLevel.MEDIUM:
            actions.extend(["VERIFY_IDENTITY", "REDUCED_TRANSACTION_LIMIT", "ADDITIONAL_LOGGING"])
        if session.velocity_anomaly:
            actions.append("VERIFY_LOGIN_LOCATION")
        if session.location_risk > 0.5:
            actions.append("VERIFY_LOCATION")
        if session.behavior_deviation > 0.5:
            actions.append("VERIFY_BEHAVIOR")
        return list(set(actions))

    def _build_context_risks(self, context: EvaluationContext) -> Dict[str, Any]:
        return {"ip_address": context.ip_address, "location": context.location, "device_id": context.device_id,
                "authentication_method": context.authentication_method, "authentication_strength": context.authentication_strength,
                "requested_resource": context.requested_resource, "session_attributes": context.session_attributes}

    def _update_behavioral_profile(self, context: EvaluationContext, profile: BehavioralProfile):
        profile.behavioral_data_points += 1
        current_hour = datetime.now(timezone.utc).hour
        if current_hour not in profile.typical_login_hours and len(profile.typical_login_hours) < 24:
            profile.typical_login_hours.append(current_hour)
        if context.location:
            city = context.location.get("city", "")
            if city and city not in profile.typical_locations and len(profile.typical_locations) < 10:
                profile.typical_locations.append(city)
        if context.device_id and context.device_id not in profile.typical_devices and len(profile.typical_devices) < 5:
            profile.typical_devices.append(context.device_id)

    def get_session_risk(self, session_id: str) -> Optional[SessionRisk]:
        return self.store.get_session_risk(session_id)

    def get_user_sessions(self, user_id: str) -> List[SessionRisk]:
        return self.store.get_user_sessions(user_id)

    def get_user_anomaly_summary(self, user_id: str) -> Dict[str, Any]:
        sessions = self.get_user_sessions(user_id)
        total_anomalies = sum(len(s.anomalies_detected) for s in sessions)
        critical_sessions = sum(1 for s in sessions if s.risk_level == SessionRiskLevel.CRITICAL)
        high_risk_sessions = sum(1 for s in sessions if s.risk_level == SessionRiskLevel.HIGH)
        anomaly_types = defaultdict(int)
        for session in sessions:
            for anomaly in session.anomalies_detected:
                anomaly_types[anomaly.split(":")[0]] += 1
        return {"total_sessions": len(sessions), "total_anomalies": total_anomalies,
                "critical_sessions": critical_sessions, "high_risk_sessions": high_risk_sessions,
                "anomaly_breakdown": dict(anomaly_types)}

    def get_analyzer_stats(self) -> Dict[str, Any]:
        return {"sessions_analyzed": self.sessions_analyzed, "anomaly_count": self.anomaly_count,
                "profiles_tracked": len(self.behavioral_profiles), "store_stats": self.store.get_stats()}