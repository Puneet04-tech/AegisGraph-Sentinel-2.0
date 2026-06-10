"""
Session Trust Evaluator for Adaptive Authentication & Continuous Authorization.

Evaluates and manages session trust levels throughout the authentication lifecycle,
providing continuous trust assessment based on user behavior and actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    AuthenticationSession,
    RiskLevel,
    SessionStatus,
    SessionTrust,
    TrustLevel,
)
from .store import AdaptiveAuthStore, get_adaptive_auth_store


@dataclass
class TrustEvaluationResult:
    """Result of trust evaluation."""
    session_id: str
    trust_level: TrustLevel
    trust_score: float
    action_required: Optional[str] = None
    factors: Dict[str, float] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class TrustAdjustment:
    """Trust adjustment based on action outcome."""
    session_id: str
    action_type: str
    adjustment: float  # Positive or negative
    reason: str
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


class TrustEvaluator:
    """
    Evaluates session trust based on various factors.
    
    Trust is dynamic and changes based on:
    - User behavior patterns
    - Authentication strength
    - Session activity
    - Risk signals
    """
    
    # Trust thresholds
    TRUST_THRESHOLDS = {
        TrustLevel.FULL: 0.9,
        TrustLevel.HIGH: 0.7,
        TrustLevel.MEDIUM: 0.4,
        TrustLevel.LOW: 0.2,
    }
    
    # Trust decay rates (per hour of inactivity)
    TRUST_DECAY_RATES = {
        TrustLevel.FULL: 0.02,
        TrustLevel.HIGH: 0.03,
        TrustLevel.MEDIUM: 0.05,
        TrustLevel.LOW: 0.08,
    }
    
    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
        self._adjustment_history: Dict[str, List[TrustAdjustment]] = {}
    
    def evaluate_trust(
        self,
        session: AuthenticationSession,
        risk_level: Optional[RiskLevel] = None,
    ) -> TrustEvaluationResult:
        """Evaluate trust level for a session."""
        trust = session.trust
        
        # Apply time-based decay
        self._apply_trust_decay(trust, session)
        
        # Factor-based adjustments
        factors: Dict[str, float] = {}
        recommendations: List[str] = []
        
        # Strong authentication bonus
        auth_strength = self._evaluate_auth_strength(session)
        factors["authentication_strength"] = auth_strength * 0.2
        
        # Behavior consistency
        behavior_score = self._evaluate_behavior_consistency(session)
        factors["behavior_consistency"] = behavior_score * 0.3
        
        # Risk adjustment
        if risk_level:
            risk_factor = self._calculate_risk_factor(risk_level)
            factors["risk_adjustment"] = -risk_factor * 0.3
        else:
            factors["risk_adjustment"] = 0.0
        
        # Session activity
        activity_factor = self._evaluate_session_activity(session)
        factors["session_activity"] = activity_factor * 0.2
        
        # Calculate final trust score
        base_trust = trust.trust_score
        adjustments = sum(factors.values())
        new_score = max(0.0, min(1.0, base_trust + adjustments))
        
        # Determine new trust level
        new_level = self._get_trust_level(new_score)
        
        # Generate recommendations
        if new_level == TrustLevel.LOW:
            recommendations.append("Session trust is low. Consider re-authentication.")
        if factors["behavior_consistency"] < 0.5:
            recommendations.append("Behavioral anomalies detected. Monitor closely.")
        if factors["authentication_strength"] < 0.5:
            recommendations.append("Consider step-up authentication for sensitive actions.")
        
        return TrustEvaluationResult(
            session_id=session.session_id,
            trust_level=new_level,
            trust_score=new_score,
            factors=factors,
            recommendations=recommendations,
        )
    
    def _evaluate_auth_strength(self, session: AuthenticationSession) -> float:
        """Evaluate the strength of authentication used."""
        auth_methods = session.metadata.get("auth_methods", [])
        
        if not auth_methods:
            return 0.2  # Unknown auth
        
        strength_scores = {
            "password": 0.3,
            "mfa": 0.6,
            "totp": 0.7,
            "hardware_token": 0.9,
            "biometric": 0.8,
            "certificate": 0.95,
        }
        
        max_strength = max(strength_scores.get(m.lower(), 0.3) for m in auth_methods)
        return max_strength
    
    def _evaluate_behavior_consistency(
        self,
        session: AuthenticationSession,
    ) -> float:
        """Evaluate how consistent the session behavior is with user patterns."""
        profile = self.store.get_profile(session.user_id)
        if not profile:
            return 0.5  # No profile to compare
        
        consistency_score = 0.5
        
        # Check device consistency
        if session.device_fingerprint in profile.typical_devices:
            consistency_score += 0.15
        
        # Check location consistency
        if session.location:
            current_loc = f"{session.location.get('country')}:{session.location.get('city')}"
            if current_loc in profile.typical_locations:
                consistency_score += 0.15
        
        # Check IP consistency
        if session.ip_address:
            ip_parts = session.ip_address.split(".")
            if len(ip_parts) == 4:
                subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                if subnet in profile.typical_ip_ranges:
                    consistency_score += 0.1
        
        # Check for anomalies
        if profile.anomaly_count > 5:
            consistency_score -= 0.2
        elif profile.anomaly_count > 2:
            consistency_score -= 0.1
        
        return max(0.0, min(1.0, consistency_score))
    
    def _evaluate_session_activity(self, session: AuthenticationSession) -> float:
        """Evaluate session activity level."""
        now = datetime.now(timezone.utc)
        inactive_minutes = (now - session.last_activity).total_seconds() / 60
        
        if inactive_minutes < 5:
            return 1.0
        elif inactive_minutes < 15:
            return 0.8
        elif inactive_minutes < 60:
            return 0.6
        elif inactive_minutes < 240:
            return 0.3
        else:
            return 0.1
    
    def _calculate_risk_factor(self, risk_level: RiskLevel) -> float:
        """Calculate trust adjustment based on risk level."""
        risk_factors = {
            RiskLevel.LOW: 0.0,
            RiskLevel.MEDIUM: 0.3,
            RiskLevel.HIGH: 0.6,
            RiskLevel.CRITICAL: 1.0,
        }
        return risk_factors.get(risk_level, 0.0)
    
    def _apply_trust_decay(self, trust: SessionTrust, session: AuthenticationSession) -> None:
        """Apply time-based trust decay."""
        now = datetime.now(timezone.utc)
        inactive_hours = (now - trust.last_evaluated).total_seconds() / 3600
        
        if inactive_hours > 0:
            level = trust.trust_level
            decay_rate = self.TRUST_DECAY_RATES.get(level, 0.05)
            decay = decay_rate * inactive_hours
            trust.trust_score = max(0.0, trust.trust_score - decay)
            trust.trust_level = self._get_trust_level(trust.trust_score)
    
    def _get_trust_level(self, score: float) -> TrustLevel:
        """Convert numeric score to trust level."""
        if score >= 0.9:
            return TrustLevel.FULL
        elif score >= 0.7:
            return TrustLevel.HIGH
        elif score >= 0.4:
            return TrustLevel.MEDIUM
        elif score >= 0.2:
            return TrustLevel.LOW
        return TrustLevel.NONE
    
    def adjust_trust(
        self,
        session: AuthenticationSession,
        adjustment: float,
        reason: str,
        action_type: str = "general",
    ) -> TrustEvaluationResult:
        """Adjust trust based on action outcome."""
        trust = session.trust
        
        # Record adjustment
        trust_adj = TrustAdjustment(
            session_id=session.session_id,
            action_type=action_type,
            adjustment=adjustment,
            reason=reason,
        )
        
        if session.session_id not in self._adjustment_history:
            self._adjustment_history[session.session_id] = []
        self._adjustment_history[session.session_id].append(trust_adj)
        
        # Apply adjustment
        trust.trust_score = max(0.0, min(1.0, trust.trust_score + adjustment))
        trust.trust_level = self._get_trust_level(trust.trust_score)
        trust.last_evaluated = datetime.now(timezone.utc)
        trust.evaluation_count += 1
        
        # Update session
        self.store.update_session(session)
        
        return TrustEvaluationResult(
            session_id=session.session_id,
            trust_level=trust.trust_level,
            trust_score=trust.trust_score,
            action_required=self._determine_action_required(trust),
            recommendations=[reason],
        )
    
    def _determine_action_required(self, trust: SessionTrust) -> Optional[str]:
        """Determine if any action is required based on trust level."""
        if trust.trust_level == TrustLevel.NONE:
            return "session_termination"
        elif trust.trust_level == TrustLevel.LOW:
            return "re_authentication"
        elif trust.consecutive_bad_actions >= 3:
            return "step_up_required"
        return None
    
    def get_trust_adjustments(
        self,
        session_id: str,
        limit: int = 10,
    ) -> List[TrustAdjustment]:
        """Get trust adjustment history for a session."""
        adjustments = self._adjustment_history.get(session_id, [])
        return adjustments[-limit:]


class SessionEvaluator:
    """
    Main session evaluation service.
    
    Orchestrates trust evaluation, risk assessment, and session management
    for continuous authorization.
    """
    
    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
        self.trust_evaluator = TrustEvaluator(store)
    
    def evaluate_session(
        self,
        session_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[TrustEvaluationResult]:
        """Evaluate a session and return trust assessment."""
        session = self.store.get_session(session_id)
        if not session:
            return None
        
        # Get risk level if available
        risk_level = None
        if session.current_risk_score:
            risk_level = session.current_risk_score.risk_level
        
        return self.trust_evaluator.evaluate_trust(session, risk_level)
    
    def record_action(
        self,
        session_id: str,
        action_type: str,
        outcome: str,
        risk_delta: float = 0.0,
    ) -> Optional[TrustEvaluationResult]:
        """Record an action and update trust accordingly."""
        session = self.store.get_session(session_id)
        if not session:
            return None
        
        # Determine adjustment based on outcome
        if outcome == "success":
            adjustment = 0.05 + risk_delta * 0.1
            reason = f"Successful {action_type}"
        elif outcome == "failed":
            adjustment = -0.15
            reason = f"Failed {action_type}"
            session.trust.consecutive_bad_actions += 1
            session.trust.consecutive_good_actions = 0
        else:
            adjustment = 0.0
            reason = f"Neutral {action_type}"
        
        # Apply trust adjustment
        result = self.trust_evaluator.adjust_trust(
            session=session,
            adjustment=adjustment,
            reason=reason,
            action_type=action_type,
        )
        
        # Check if session should be terminated
        if result.action_required == "session_termination":
            self.terminate_session(session_id, "Trust level dropped to none")
        
        return result
    
    def reassess_session(
        self,
        session_id: str,
        reason: str = "scheduled_reassessment",
    ) -> Optional[TrustEvaluationResult]:
        """Perform a full session reassessment."""
        session = self.store.get_session(session_id)
        if not session:
            return None
        
        # Mark session as reassessing
        session.status = SessionStatus.REASSESSING
        self.store.update_session(session)
        
        # Perform evaluation
        result = self.evaluate_session(session_id)
        
        # Restore active status
        if session.status == SessionStatus.REASSESSING:
            if result and result.trust_level != TrustLevel.NONE:
                session.status = SessionStatus.ACTIVE
            self.store.update_session(session)
        
        return result
    
    def terminate_session(
        self,
        session_id: str,
        reason: str = "",
    ) -> bool:
        """Terminate a session."""
        return self.store.terminate_session(session_id, reason)
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive session information."""
        session = self.store.get_session(session_id)
        if not session:
            return None
        
        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "status": session.status.value,
            "trust_level": session.trust.trust_level.value,
            "trust_score": session.trust.trust_score,
            "created_at": session.created_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "ip_address": session.ip_address,
            "anomaly_count": len([
                a for a in session.recent_actions
                if a.get("anomaly_detected")
            ]),
            "recent_actions": len(session.recent_actions),
            "evaluation_count": session.trust.evaluation_count,
        }


# Global evaluator instance
_evaluator: Optional[SessionEvaluator] = None


def get_session_evaluator() -> SessionEvaluator:
    """Get the global session evaluator instance."""
    global _evaluator
    if _evaluator is None:
        store = get_adaptive_auth_store()
        _evaluator = SessionEvaluator(store)
    return _evaluator


def reset_evaluator() -> None:
    """Reset the evaluator (for testing)."""
    global _evaluator
    _evaluator = None