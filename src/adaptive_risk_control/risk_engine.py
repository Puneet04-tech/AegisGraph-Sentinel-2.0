"""
Adaptive Risk Engine for continuous risk evaluation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    RiskProfile,
    RiskLevel,
    TransactionAssessment,
    DecisionType,
    FraudAttempt,
)


class AdaptiveRiskEngine:
    """
    Provides continuous risk evaluation with dynamic thresholds.

    Handles:
    - Real-time risk scoring
    - Multi-factor risk analysis
    - Behavioral risk assessment
    - Risk trend monitoring
    """

    def __init__(self):
        self._risk_factors = self._initialize_risk_factors()
        self._thresholds = self._initialize_thresholds()

    def _initialize_risk_factors(self) -> Dict[str, float]:
        """Initialize risk factor weights."""
        return {
            "velocity": 0.25,
            "amount": 0.20,
            "device": 0.15,
            "location": 0.15,
            "behavior": 0.15,
            "history": 0.10,
        }

    def _initialize_thresholds(self) -> Dict[str, float]:
        """Initialize risk thresholds."""
        return {
            "approve": 0.3,
            "monitor": 0.5,
            "challenge": 0.7,
            "review": 0.8,
            "block": 0.9,
            "deny": 1.0,
        }

    async def evaluate_risk(
        self,
        entity_id: str,
        transaction_data: Dict[str, Any],
        profile: Optional[RiskProfile] = None,
    ) -> TransactionAssessment:
        """Evaluate transaction risk in real-time."""
        start_time = datetime.now(timezone.utc)

        # Calculate component scores
        velocity_score = self._calculate_velocity_score(transaction_data)
        amount_score = self._calculate_amount_score(transaction_data)
        device_score = self._calculate_device_score(transaction_data)
        location_score = self._calculate_location_score(transaction_data)
        behavior_score = self._calculate_behavior_score(transaction_data, profile)

        # Calculate overall risk score
        risk_score = self._calculate_overall_risk(
            velocity=velocity_score,
            amount=amount_score,
            device=device_score,
            location=location_score,
            behavior=behavior_score,
        )

        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)

        # Determine decision
        decision = self._determine_decision(risk_score)

        # Identify risk factors
        risk_factors = self._identify_risk_factors(
            velocity_score, amount_score, device_score,
            location_score, behavior_score
        )

        # Identify indicators
        indicators = self._identify_indicators(transaction_data, risk_score)

        # Calculate processing time
        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        assessment = TransactionAssessment(
            assessment_id=str(uuid.uuid4()),
            transaction_id=transaction_data.get("transaction_id", str(uuid.uuid4())),
            entity_id=entity_id,
            risk_score=risk_score,
            risk_level=risk_level,
            decision=decision,
            confidence=self._calculate_confidence(risk_score, transaction_data),
            risk_factors=risk_factors,
            indicators=indicators,
            velocity_score=velocity_score,
            behavioral_score=behavior_score,
            device_score=device_score,
            location_score=location_score,
            amount_score=amount_score,
            assessed_at=datetime.now(timezone.utc),
            processing_time_ms=processing_time,
        )

        return assessment

    def _calculate_velocity_score(self, data: Dict[str, Any]) -> float:
        """Calculate velocity risk score."""
        velocity = data.get("velocity", 1)
        max_velocity = data.get("max_velocity", 10)

        if velocity > max_velocity:
            return 1.0
        return velocity / max_velocity

    def _calculate_amount_score(self, data: Dict[str, Any]) -> float:
        """Calculate amount risk score."""
        amount = data.get("amount", 0)
        avg_amount = data.get("avg_amount", 1000)
        max_amount = data.get("max_amount", 10000)

        if amount > max_amount:
            return 1.0

        # Compare to average
        ratio = amount / avg_amount if avg_amount > 0 else 0
        return min(1.0, ratio / 5)  # 5x average = full score

    def _calculate_device_score(self, data: Dict[str, Any]) -> float:
        """Calculate device risk score."""
        if not data.get("device_trusted", True):
            return 0.8
        if data.get("is_new_device", False):
            return 0.6
        if data.get("device_risk_score"):
            return data["device_risk_score"]
        return 0.1

    def _calculate_location_score(self, data: Dict[str, Any]) -> float:
        """Calculate location risk score."""
        if data.get("impossible_travel", False):
            return 1.0
        if data.get("high_risk_country", False):
            return 0.7
        if data.get("location_changed", False):
            return 0.4
        return 0.1

    def _calculate_behavior_score(
        self,
        data: Dict[str, Any],
        profile: Optional[RiskProfile],
    ) -> float:
        """Calculate behavioral risk score."""
        if not profile:
            return 0.5

        # Compare to behavioral baseline
        baseline = profile.behavioral_baseline
        current = data.get("behavior_pattern", "normal")

        if baseline.get("pattern") == current:
            return 0.1  # Normal behavior

        # Check deviation from baseline
        deviation = abs(profile.risk_score - data.get("expected_risk", 0.5))
        return min(1.0, deviation * 2)

    def _calculate_overall_risk(
        self,
        velocity: float,
        amount: float,
        device: float,
        location: float,
        behavior: float,
    ) -> float:
        """Calculate overall risk score."""
        return (
            velocity * self._risk_factors["velocity"] +
            amount * self._risk_factors["amount"] +
            device * self._risk_factors["device"] +
            location * self._risk_factors["location"] +
            behavior * self._risk_factors["behavior"]
        )

    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score."""
        if risk_score >= 0.9:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.5:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.3:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def _determine_decision(self, risk_score: float) -> DecisionType:
        """Determine decision from risk score."""
        if risk_score >= self._thresholds["deny"]:
            return DecisionType.DENY
        elif risk_score >= self._thresholds["block"]:
            return DecisionType.BLOCK
        elif risk_score >= self._thresholds["review"]:
            return DecisionType.REVIEW
        elif risk_score >= self._thresholds["challenge"]:
            return DecisionType.CHALLENGE
        elif risk_score >= self._thresholds["monitor"]:
            return DecisionType.MONITOR
        else:
            return DecisionType.APPROVE

    def _identify_risk_factors(
        self,
        velocity: float,
        amount: float,
        device: float,
        location: float,
        behavior: float,
    ) -> List[str]:
        """Identify contributing risk factors."""
        factors = []

        if velocity > 0.7:
            factors.append("High transaction velocity")
        if amount > 0.7:
            factors.append("High transaction amount")
        if device > 0.5:
            factors.append("Untrusted device")
        if location > 0.5:
            factors.append("Suspicious location")
        if behavior > 0.5:
            factors.append("Behavioral anomaly")

        return factors

    def _identify_indicators(
        self,
        data: Dict[str, Any],
        risk_score: float,
    ) -> List[str]:
        """Identify fraud indicators."""
        indicators = []

        if data.get("is_vpn") or data.get("is_proxy"):
            indicators.append("Anonymous network detected")
        if data.get("is_tor"):
            indicators.append("TOR network detected")
        if data.get("bot_signature"):
            indicators.append("Automated bot detected")
        if data.get("stolen_card"):
            indicators.append("Stolen card indicators")
        if data.get("velocity_spike"):
            indicators.append("Velocity spike detected")

        return indicators

    def _calculate_confidence(
        self,
        risk_score: float,
        data: Dict[str, Any],
    ) -> float:
        """Calculate assessment confidence."""
        confidence = 0.7

        # More data = higher confidence
        data_points = len([v for v in data.values() if v is not None])
        confidence += min(0.2, data_points * 0.02)

        # Extreme scores = higher confidence
        if risk_score > 0.8 or risk_score < 0.2:
            confidence += 0.1

        return min(1.0, confidence)

    async def detect_fraud_attempt(
        self,
        entity_id: str,
        assessment: TransactionAssessment,
    ) -> Optional[FraudAttempt]:
        """Detect potential fraud attempt."""
        if assessment.risk_score < 0.7:
            return None

        # Create fraud attempt record
        attempt = FraudAttempt(
            attempt_id=str(uuid.uuid4()),
            entity_id=entity_id,
            attempt_type="high_risk_transaction",
            risk_score=assessment.risk_score,
            confidence=assessment.confidence,
            indicators=assessment.indicators,
            affected_transactions=[assessment.transaction_id],
            detected_at=datetime.now(timezone.utc),
        )

        return attempt

    async def update_risk_profile(
        self,
        profile: RiskProfile,
        assessment: TransactionAssessment,
    ) -> RiskProfile:
        """Update risk profile based on assessment."""
        # Adjust risk score based on assessment
        alpha = 0.1  # Learning rate
        profile.risk_score = (
            alpha * assessment.risk_score +
            (1 - alpha) * profile.risk_score
        )

        # Update risk level
        profile.risk_level = self._determine_risk_level(profile.risk_score)

        # Update trend
        if assessment.risk_score > profile.risk_score:
            profile.risk_trend = "increasing"
        elif assessment.risk_score < profile.risk_score:
            profile.risk_trend = "decreasing"
        else:
            profile.risk_trend = "stable"

        # Update counters
        profile.total_transactions += 1
        if assessment.decision in [DecisionType.BLOCK, DecisionType.DENY]:
            profile.fraudulent_transactions += 1

        # Update last evaluation
        profile.last_evaluation = datetime.now(timezone.utc)

        return profile


# Global engine instance
_engine: Optional[AdaptiveRiskEngine] = None


def get_risk_engine() -> AdaptiveRiskEngine:
    """Get the adaptive risk engine instance."""
    global _engine
    if _engine is None:
        _engine = AdaptiveRiskEngine()
    return _engine