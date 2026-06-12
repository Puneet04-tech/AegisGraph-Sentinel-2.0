"""
Adaptive Authentication & Continuous Authorization Engine.

A risk-based adaptive authentication platform capable of dynamically adjusting
authentication requirements and continuously evaluating user trust throughout
a session.

Main Components:
- Risk Engine: Evaluates multiple risk signals to compute comprehensive risk scores
- Behavior Monitor: Monitors user behavior patterns and detects anomalies
- Session Evaluator: Evaluates and manages session trust levels
- Step-Up Auth Service: Manages step-up authentication challenges
- Policy Engine: Evaluates access decisions based on trust and risk
- Audit Service: Comprehensive audit logging for security events

Usage:
    from src.adaptive_auth import get_adaptive_auth_service
    
    service = get_adaptive_auth_service()
    
    # Evaluate authentication
    decision = await service.evaluate_authentication(request)
    
    # Get session info
    session = await service.get_session(session_id)
    
    # Create step-up challenge
    challenge = await service.initiate_challenge(session_id, user_id, "totp")
"""

# Core models
from .models import (
    # Enums
    RiskLevel,
    AuthenticationStatus,
    ChallengeType,
    TrustLevel,
    PolicyAction,
    SessionStatus,
    # Data classes
    RiskSignal,
    RiskScore,
    AuthenticationRequest,
    AuthenticationDecision,
    BehaviorProfile,
    SessionTrust,
    StepUpChallenge,
    AuthorizationPolicy,
    AuditEvent,
    AuthenticationSession,
    RiskEvaluationRequest,
    RiskEvaluationResponse,
)

# Storage
from .store import AdaptiveAuthStore, get_adaptive_auth_store, reset_store

# Risk Engine
from .risk_engine import RiskEngine, get_risk_engine, reset_engine

# Behavior Monitor
from .behavior_monitor import (
    BehaviorMonitor,
    BehaviorAnalyzer,
    BehaviorAnomaly,
    AnomalyDetectionResult,
    get_behavior_monitor,
    reset_monitor,
)

# Session Evaluator
from .session_evaluator import (
    SessionEvaluator,
    TrustEvaluator,
    TrustEvaluationResult,
    TrustAdjustment,
    get_session_evaluator,
    reset_evaluator,
)

# Step-Up Auth
from .stepup_auth import (
    StepUpAuthService,
    ChallengeConfig,
    ChallengeResponse,
    get_stepup_auth_service,
    reset_service,
)

# Policy Engine
from .policy_engine import (
    PolicyEngine,
    PolicyEvaluator,
    PolicyEvaluationContext,
    PolicyDecision,
    AccessDecision,
    get_policy_engine,
    reset_engine as reset_policy_engine,
)

# Audit Service
from .audit import (
    AuditService,
    AuditQuery,
    AuditSummary,
    get_audit_service,
    reset_audit_service,
)

# Main Service
from .service import (
    AdaptiveAuthService,
    AdaptiveAuthConfig,
    get_adaptive_auth_service,
    reset_service as reset_auth_service,
    # Sync convenience functions
    evaluate_risk_sync,
    create_session_sync,
)

__all__ = [
    # Enums
    "RiskLevel",
    "AuthenticationStatus",
    "ChallengeType",
    "TrustLevel",
    "PolicyAction",
    "SessionStatus",
    # Models
    "RiskSignal",
    "RiskScore",
    "AuthenticationRequest",
    "AuthenticationDecision",
    "BehaviorProfile",
    "SessionTrust",
    "StepUpChallenge",
    "AuthorizationPolicy",
    "AuditEvent",
    "AuthenticationSession",
    "RiskEvaluationRequest",
    "RiskEvaluationResponse",
    # Storage
    "AdaptiveAuthStore",
    "get_adaptive_auth_store",
    "reset_store",
    # Risk Engine
    "RiskEngine",
    "get_risk_engine",
    "reset_engine",
    # Behavior Monitor
    "BehaviorMonitor",
    "BehaviorAnalyzer",
    "BehaviorAnomaly",
    "AnomalyDetectionResult",
    "get_behavior_monitor",
    "reset_monitor",
    # Session Evaluator
    "SessionEvaluator",
    "TrustEvaluator",
    "TrustEvaluationResult",
    "TrustAdjustment",
    "get_session_evaluator",
    "reset_evaluator",
    # Step-Up Auth
    "StepUpAuthService",
    "ChallengeConfig",
    "ChallengeResponse",
    "get_stepup_auth_service",
    "reset_service",
    # Policy Engine
    "PolicyEngine",
    "PolicyEvaluator",
    "PolicyEvaluationContext",
    "PolicyDecision",
    "AccessDecision",
    "get_policy_engine",
    "reset_policy_engine",
    # Audit Service
    "AuditService",
    "AuditQuery",
    "AuditSummary",
    "get_audit_service",
    "reset_audit_service",
    # Main Service
    "AdaptiveAuthService",
    "AdaptiveAuthConfig",
    "get_adaptive_auth_service",
    "reset_auth_service",
    "evaluate_risk_sync",
    "create_session_sync",
]