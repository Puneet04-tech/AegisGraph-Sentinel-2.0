"""
Data models for Adaptive Authentication & Continuous Authorization Engine.

This module defines the core data structures used for risk-based authentication,
behavior monitoring, session trust evaluation, and continuous authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class RiskLevel(str, Enum):
    """Risk level classification for authentication and authorization decisions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthenticationStatus(str, Enum):
    """Status of an authentication attempt."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    STEP_UP_REQUIRED = "step_up_required"
    DENIED = "denied"


class ChallengeType(str, Enum):
    """Types of step-up authentication challenges."""
    SMS_OTP = "sms_otp"
    EMAIL_OTP = "email_otp"
    TOTP = "totp"
    PUSH_NOTIFICATION = "push_notification"
    BIOMETRIC = "biometric"
    HARDWARE_TOKEN = "hardware_token"
    SECURITY_QUESTIONS = "security_questions"
    CALLBACK = "callback"


class TrustLevel(str, Enum):
    """Session trust level classification."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    FULL = "full"


class PolicyAction(str, Enum):
    """Actions that can be taken by the policy engine."""
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"
    CHALLENGE = "challenge"
    REVIEW = "review"
    TERMINATE = "terminate"


class SessionStatus(str, Enum):
    """Status of a user session."""
    ACTIVE = "active"
    REASSESSING = "reassessing"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"
    EXPIRED = "expired"


@dataclass
class RiskSignal:
    """Individual risk signal contributing to overall risk score."""
    signal_type: str
    value: float
    weight: float
    source: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def weighted_score(self) -> float:
        """Calculate the weighted contribution of this signal."""
        return self.value * self.weight


@dataclass
class RiskScore:
    """Complete risk score with breakdown by signal type."""
    session_id: str
    user_id: str
    total_score: float
    risk_level: RiskLevel
    signals: List[RiskSignal]
    timestamp: datetime
    factors: Dict[str, float] = field(default_factory=dict)
    recommendation: str = ""
    
    @classmethod
    def calculate(cls, session_id: str, user_id: str, signals: List[RiskSignal]) -> RiskScore:
        """Calculate risk score from signals."""
        total_score = sum(s.weighted_score for s in signals)
        total_score = min(total_score, 1.0)
        
        # Determine risk level based on score
        if total_score >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif total_score >= 0.6:
            risk_level = RiskLevel.HIGH
        elif total_score >= 0.3:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Group factors by type
        factors: Dict[str, float] = {}
        for signal in signals:
            if signal.signal_type not in factors:
                factors[signal.signal_type] = 0.0
            factors[signal.signal_type] += signal.weighted_score
        
        return cls(
            session_id=session_id,
            user_id=user_id,
            total_score=total_score,
            risk_level=risk_level,
            signals=signals,
            timestamp=datetime.now(timezone.utc),
            factors=factors,
            recommendation=_get_recommendation(risk_level),
        )


def _get_recommendation(risk_level: RiskLevel) -> str:
    """Get recommendation based on risk level."""
    recommendations = {
        RiskLevel.LOW: "Allow access with standard authentication.",
        RiskLevel.MEDIUM: "Allow with enhanced monitoring.",
        RiskLevel.HIGH: "Require step-up authentication.",
        RiskLevel.CRITICAL: "Block access and require administrative review.",
    }
    return recommendations.get(risk_level, "Unknown risk level.")


@dataclass
class AuthenticationRequest:
    """Request for authentication evaluation."""
    user_id: str
    session_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""
    device_fingerprint: str = ""
    location: Optional[Dict[str, Any]] = None
    requested_resource: str = ""
    auth_method: str = "password"
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuthenticationDecision:
    """Decision from the authentication decision engine."""
    request_id: str
    session_id: str
    user_id: str
    status: AuthenticationStatus
    risk_score: RiskScore
    required_challenges: List[ChallengeType] = field(default_factory=list)
    session_trust_level: TrustLevel = TrustLevel.NONE
    allowed_auth_methods: List[str] = field(default_factory=list)
    denied_auth_methods: List[str] = field(default_factory=list)
    policy_violations: List[str] = field(default_factory=list)
    factors: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


@dataclass
class BehaviorProfile:
    """User behavior profile for anomaly detection."""
    user_id: str
    profile_id: str
    typical_login_times: List[str] = field(default_factory=list)
    typical_locations: List[str] = field(default_factory=list)
    typical_devices: List[str] = field(default_factory=list)
    typical_ip_ranges: List[str] = field(default_factory=list)
    typical_transaction_patterns: Dict[str, Any] = field(default_factory=dict)
    velocity_limits: Dict[str, int] = field(default_factory=dict)
    anomaly_count: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_history: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def is_mature(self) -> bool:
        """Check if profile has enough data for reliable anomaly detection."""
        return len(self.risk_history) >= 10


@dataclass
class SessionTrust:
    """Trust score for an active session."""
    session_id: str
    user_id: str
    trust_level: TrustLevel
    trust_score: float
    last_evaluated: datetime
    next_evaluation: Optional[datetime] = None
    evaluation_count: int = 0
    factors: Dict[str, float] = field(default_factory=dict)
    anomalies_detected: List[str] = field(default_factory=list)
    consecutive_good_actions: int = 0
    consecutive_bad_actions: int = 0
    
    def update(self, action_trusted: bool) -> None:
        """Update trust based on action outcome."""
        if action_trusted:
            self.consecutive_good_actions += 1
            self.consecutive_bad_actions = 0
            # Gradual trust increase
            self.trust_score = min(1.0, self.trust_score + 0.05)
        else:
            self.consecutive_bad_actions += 1
            self.consecutive_good_actions = 0
            # Faster trust decrease
            self.trust_score = max(0.0, self.trust_score - 0.15)
        
        self.trust_level = _trust_level_from_score(self.trust_score)
        self.evaluation_count += 1
        self.last_evaluated = datetime.now(timezone.utc)


def _trust_level_from_score(score: float) -> TrustLevel:
    """Convert trust score to trust level."""
    if score >= 0.9:
        return TrustLevel.FULL
    elif score >= 0.7:
        return TrustLevel.HIGH
    elif score >= 0.4:
        return TrustLevel.MEDIUM
    elif score >= 0.2:
        return TrustLevel.LOW
    return TrustLevel.NONE


@dataclass
class StepUpChallenge:
    """Step-up authentication challenge."""
    challenge_id: str
    session_id: str
    user_id: str
    challenge_type: ChallengeType
    status: str = "pending"  # pending, active, completed, expired, failed
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=5))
    attempts: int = 0
    max_attempts: int = 3
    verification_code: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    completed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if challenge has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_max_attempts_reached(self) -> bool:
        """Check if max attempts reached."""
        return self.attempts >= self.max_attempts


@dataclass
class AuthorizationPolicy:
    """Authorization policy for continuous access control."""
    policy_id: str
    name: str
    description: str
    resource_pattern: str
    required_trust_level: TrustLevel
    required_risk_level: RiskLevel
    allowed_auth_methods: List[str] = field(default_factory=list)
    denied_auth_methods: List[str] = field(default_factory=list)
    step_up_required: bool = False
    step_up_challenge_types: List[ChallengeType] = field(default_factory=list)
    action_on_violation: PolicyAction = PolicyAction.DENY
    conditions: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def create_default_policies(cls) -> List[AuthorizationPolicy]:
        """Create default authorization policies."""
        return [
            cls(
                policy_id=str(uuid.uuid4()),
                name="High Security Resource Access",
                description="Require high trust level for sensitive resources",
                resource_pattern=r"/api/v1/admin/.*",
                required_trust_level=TrustLevel.HIGH,
                required_risk_level=RiskLevel.MEDIUM,
                allowed_auth_methods=["mfa", "hardware_token"],
                step_up_required=True,
                step_up_challenge_types=[ChallengeType.TOTP, ChallengeType.PUSH_NOTIFICATION],
                action_on_violation=PolicyAction.DENY,
                priority=100,
            ),
            cls(
                policy_id=str(uuid.uuid4()),
                name="Standard Resource Access",
                description="Standard access for regular resources",
                resource_pattern=r"/api/v1/.*",
                required_trust_level=TrustLevel.LOW,
                required_risk_level=RiskLevel.HIGH,
                allowed_auth_methods=["password", "mfa", "biometric"],
                step_up_required=False,
                action_on_violation=PolicyAction.STEP_UP,
                priority=50,
            ),
            cls(
                policy_id=str(uuid.uuid4()),
                name="Critical Action Protection",
                description="Require step-up for critical actions like transfers",
                resource_pattern=r"/api/v1/.*/(transfer|payment|withdraw).*",
                required_trust_level=TrustLevel.MEDIUM,
                required_risk_level=RiskLevel.HIGH,
                step_up_required=True,
                step_up_challenge_types=[ChallengeType.SMS_OTP, ChallengeType.TOTP],
                action_on_violation=PolicyAction.CHALLENGE,
                priority=90,
            ),
        ]


@dataclass
class AuditEvent:
    """Audit event for authentication and authorization."""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    user_id: str
    session_id: Optional[str]
    resource: str
    action: str
    outcome: str
    risk_score: Optional[float] = None
    trust_level: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    correlation_id: str = ""
    
    @classmethod
    def create(
        cls,
        event_type: str,
        severity: str,
        user_id: str,
        resource: str,
        action: str,
        outcome: str,
        session_id: Optional[str] = None,
        **kwargs
    ) -> AuditEvent:
        """Create an audit event."""
        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            session_id=session_id,
            resource=resource,
            action=action,
            outcome=outcome,
            **kwargs
        )


@dataclass
class AuthenticationSession:
    """Complete authentication session state."""
    session_id: str
    user_id: str
    status: SessionStatus
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    device_fingerprint: str
    trust: SessionTrust
    location: Optional[Dict[str, Any]] = None
    current_risk_score: Optional[RiskScore] = None
    active_challenges: List[StepUpChallenge] = field(default_factory=list)
    recent_actions: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_active(self) -> bool:
        """Check if session is active."""
        return self.status == SessionStatus.ACTIVE and not self.is_expired()
    
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)
    
    def add_action(self, action: Dict[str, Any]) -> None:
        """Add an action to recent actions history."""
        action["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.recent_actions.append(action)
        # Keep only last 100 actions
        if len(self.recent_actions) > 100:
            self.recent_actions = self.recent_actions[-100:]
        self.update_activity()


@dataclass
class RiskEvaluationRequest:
    """Request for risk evaluation."""
    user_id: str
    session_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""
    device_fingerprint: str = ""
    location: Optional[Dict[str, Any]] = None
    action: str = ""
    resource: str = ""
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskEvaluationResponse:
    """Response from risk evaluation."""
    session_id: str
    user_id: str
    risk_score: float
    risk_level: RiskLevel
    signals: List[Dict[str, Any]]
    recommendation: str
    requires_step_up: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))