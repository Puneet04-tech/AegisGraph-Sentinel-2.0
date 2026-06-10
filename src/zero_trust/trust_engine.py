"""
Trust Evaluation Engine for Zero Trust Security
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from .models import TrustLevel, TrustScore, RiskFactors, EvaluationContext, DeviceStatus
from .store import ZeroTrustStore, get_store


TRUST_THRESHOLDS = {
    TrustLevel.BLOCKED: 0.0, TrustLevel.UNTRUSTED: 0.2,
    TrustLevel.SUSPICIOUS: 0.4, TrustLevel.TRUSTED: 0.7, TrustLevel.HIGHLY_TRUSTED: 0.9,
}

FACTOR_WEIGHTS = {
    "device_trust": 0.25, "behavioral": 0.20, "location": 0.15,
    "session": 0.15, "historical": 0.15, "threat_intelligence": 0.10,
}


class TrustEngine:
    def __init__(self, store: Optional[ZeroTrustStore] = None):
        self.store = store or get_store()
        self.evaluation_count = 0
        self.total_evaluation_time = 0.0

    def evaluate_trust(self, context: EvaluationContext, cached: bool = True) -> TrustScore:
        start_time = time.time()
        if cached:
            cached_score = self.store.get_trust_score(context.user_id, context.device_id)
            if cached_score:
                self.evaluation_count += 1
                self.total_evaluation_time += (time.time() - start_time) * 1000
                return cached_score

        factors = self._collect_risk_factors(context)
        score, breakdown = self._calculate_trust_score(factors, context)
        level = self._get_trust_level(score)
        recommendations = self._generate_recommendations(score, level, factors)

        trust_score = TrustScore(
            score=score, level=level, factors=factors,
            confidence=self._calculate_confidence(factors),
            factors_breakdown=breakdown, recommendations=recommendations,
        )

        self.store.set_trust_score(context.user_id, context.device_id, trust_score)
        self.store.record_evaluation(context, trust_score.to_dict())
        self.evaluation_count += 1
        self.total_evaluation_time += (time.time() - start_time) * 1000
        return trust_score

    def _collect_risk_factors(self, context: EvaluationContext) -> RiskFactors:
        factors = RiskFactors()
        if context.device_id:
            device = self.store.get_device(context.device_id)
            if device:
                factors.device_trust_score = device.trust_score
                factors.device_registered = device.status == DeviceStatus.REGISTERED
                try:
                    first_seen = datetime.fromisoformat(device.first_seen.replace('Z', '+00:00'))
                    age = (datetime.now(timezone.utc) - first_seen).days
                    factors.device_age_days = age
                    factors.new_device = age < 1
                except (ValueError, AttributeError):
                    factors.new_device = True
        if context.device_fingerprint:
            factors.device_trust_score = max(factors.device_trust_score, 0.5)
        if context.session_id:
            session = self.store.get_session_risk(context.session_id)
            if session:
                factors.behavioral_anomaly_score = session.behavior_deviation
                factors.location_risk = session.location_risk
                factors.velocity_anomaly = session.velocity_anomaly
                try:
                    session_start = datetime.fromisoformat(session.session_start.replace('Z', '+00:00'))
                    factors.session_duration = int((datetime.now(timezone.utc) - session_start).total_seconds())
                except (ValueError, AttributeError):
                    pass
        if context.historical_context:
            factors.historical_trust = context.historical_context.get("trust_score", 0.5)
            factors.failed_attempts = context.historical_context.get("failed_attempts", 0)
            factors.login_velocity = context.historical_context.get("login_velocity", 0)
        if context.ip_address:
            factors.ip_reputation = self._evaluate_ip_reputation(context.ip_address)
        if context.location:
            factors.location_risk = self._evaluate_location_risk(context.location)
        current_hour = datetime.now(timezone.utc).hour
        factors.unusual_time = current_hour < 6 or current_hour > 22
        factors.threat_intelligence_score = self._check_threat_intelligence(context)
        return factors

    def _calculate_trust_score(self, factors: RiskFactors, context: EvaluationContext) -> tuple[float, Dict[str, float]]:
        breakdown = {}
        device_score = factors.device_trust_score
        if not factors.device_registered:
            device_score *= 0.7
        if factors.new_device:
            device_score *= 0.8
        breakdown["device_trust"] = device_score

        behavioral_score = 1.0 - factors.behavioral_anomaly_score
        if factors.failed_attempts > 0:
            behavioral_score *= (1.0 - min(factors.failed_attempts * 0.1, 0.5))
        breakdown["behavioral"] = behavioral_score

        location_score = 1.0 - factors.location_risk
        if factors.vpn_detected:
            location_score *= 0.9
        if factors.tor_detected:
            location_score *= 0.7
        breakdown["location"] = location_score

        session_score = 0.5
        if factors.session_duration > 0:
            session_score = min(0.5 + (factors.session_duration / 3600) * 0.1, 0.9)
        if factors.velocity_anomaly:
            session_score *= 0.5
        breakdown["session"] = session_score

        historical_score = factors.historical_trust
        breakdown["historical"] = historical_score

        threat_score = 1.0 - factors.threat_intelligence_score
        breakdown["threat_intelligence"] = threat_score

        total_score = sum(breakdown[k] * FACTOR_WEIGHTS[k] for k in FACTOR_WEIGHTS)
        total_score = max(0.0, min(1.0, total_score))
        return total_score, breakdown

    def _get_trust_level(self, score: float) -> TrustLevel:
        for level in [TrustLevel.HIGHLY_TRUSTED, TrustLevel.TRUSTED, TrustLevel.SUSPICIOUS,
                      TrustLevel.UNTRUSTED, TrustLevel.BLOCKED]:
            if score >= TRUST_THRESHOLDS[level]:
                return level
        return TrustLevel.BLOCKED

    def _calculate_confidence(self, factors: RiskFactors) -> float:
        confidence = 0.5
        factor_count = sum([1 if factors.device_trust_score != 0.5 else 0,
                           1 if factors.historical_trust != 0.5 else 0,
                           1 if factors.ip_reputation != 0.5 else 0,
                           1 if factors.location_risk > 0 else 0])
        confidence += factor_count * 0.1
        if factors.new_device:
            confidence -= 0.1
        return max(0.0, min(1.0, confidence))

    def _generate_recommendations(self, score: float, level: TrustLevel, factors: RiskFactors) -> List[str]:
        recommendations = []
        if level == TrustLevel.BLOCKED:
            recommendations.extend(["BLOCK: Immediate block due to critical trust score", "MFA: Require multi-factor authentication", "ALERT: Alert security team"])
        elif level == TrustLevel.UNTRUSTED:
            recommendations.extend(["VERIFY: Require additional verification", "LOG: Enable enhanced logging"])
            if factors.new_device:
                recommendations.append("DEVICE: Verify device ownership")
        elif level == TrustLevel.SUSPICIOUS:
            recommendations.extend(["MONITOR: Implement enhanced monitoring"])
            if factors.velocity_anomaly:
                recommendations.append("VELOCITY: Review login velocity")
            if factors.location_risk > 0.5:
                recommendations.append("LOCATION: Verify location")
        elif level == TrustLevel.TRUSTED:
            recommendations.append("ALLOW: Standard access with monitoring")
        elif level == TrustLevel.HIGHLY_TRUSTED:
            recommendations.extend(["ALLOW: Fast track access", "REVIEW: Periodically re-verify"])
        if factors.failed_attempts > 3:
            recommendations.append("ACCOUNT: Review account for compromise")
        if factors.tor_detected:
            recommendations.append("TOR: Flag for TOR exit node access")
        return recommendations

    def _evaluate_ip_reputation(self, ip_address: str) -> float:
        score = 0.5
        if ip_address.startswith(('10.', '172.16.', '192.168.')):
            score = 0.8
        if ip_address in ('127.0.0.1', '::1'):
            score = 1.0
        return score

    def _evaluate_location_risk(self, location: Dict[str, Any]) -> float:
        risk = 0.0
        if location.get("city_change"):
            risk += 0.2
        return min(1.0, risk)

    def _check_threat_intelligence(self, context: EvaluationContext) -> float:
        return 0.0

    def get_stats(self) -> Dict[str, Any]:
        return {"total_evaluations": self.evaluation_count,
                "average_evaluation_time_ms": self.get_average_evaluation_time_ms(),
                "store_stats": self.store.get_stats()}

    def get_average_evaluation_time_ms(self) -> float:
        return self.total_evaluation_time / self.evaluation_count if self.evaluation_count > 0 else 0.0

    def reset_stats(self):
        self.evaluation_count = 0
        self.total_evaluation_time = 0.0
        self.store.reset_stats()