"""
Main Service for Adaptive Authentication & Continuous Authorization.

Orchestrates all adaptive authentication components and provides
the main API interface for risk-based authentication and continuous authorization.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .audit import AuditService, get_audit_service
from .behavior_monitor import BehaviorMonitor, get_behavior_monitor
from .models import (
    AuthenticationDecision,
    AuthenticationRequest,
    AuthenticationSession,
    AuthenticationStatus,
    AuthorizationPolicy,
    ChallengeType,
    PolicyAction,
    RiskEvaluationRequest,
    RiskEvaluationResponse,
    RiskLevel,
    RiskScore,
    SessionTrust,
    TrustLevel,
)
from .policy_engine import PolicyEngine, get_policy_engine
from .risk_engine import RiskEngine, get_risk_engine
from .session_evaluator import SessionEvaluator, get_session_evaluator
from .stepup_auth import StepUpAuthService, get_stepup_auth_service
from .store import AdaptiveAuthStore, get_adaptive_auth_store


@dataclass
class AdaptiveAuthConfig:
    """Configuration for adaptive authentication service."""
    enable_continuous_reassessment: bool = True
    reassessment_interval_seconds: int = 300
    trust_decay_enabled: bool = True
    max_session_duration_hours: int = 24
    step_up_required_for_high_risk: bool = True
    automatic_session_termination: bool = True
    behavior_learning_enabled: bool = True


class AdaptiveAuthService:
    """
    Main adaptive authentication service.
    
    Orchestrates all components to provide:
    - Risk-based authentication
    - Continuous authorization
    - Session trust evaluation
    - Step-up authentication
    - Behavior monitoring
    """
    
    def __init__(
        self,
        store: Optional[AdaptiveAuthStore] = None,
        config: Optional[AdaptiveAuthConfig] = None,
    ):
        self.store = store or get_adaptive_auth_store()
        self.config = config or AdaptiveAuthConfig()
        
        # Initialize components
        self.risk_engine = RiskEngine(self.store)
        self.behavior_monitor = BehaviorMonitor(self.store)
        self.session_evaluator = SessionEvaluator(self.store)
        self.stepup_service = StepUpAuthService(self.store)
        self.policy_engine = PolicyEngine(self.store)
        self.audit_service = AuditService(self.store)
        
        # Background tasks
        self._background_tasks: List[asyncio.Task] = []
        self._running = False
    
    async def start(self) -> None:
        """Start background tasks."""
        self._running = True
        if self.config.enable_continuous_reassessment:
            task = asyncio.create_task(self._reassessment_loop())
            self._background_tasks.append(task)
    
    async def stop(self) -> None:
        """Stop background tasks."""
        self._running = False
        for task in self._background_tasks:
            task.cancel()
        self._background_tasks.clear()
    
    async def _reassessment_loop(self) -> None:
        """Background loop for continuous session reassessment."""
        while self._running:
            try:
                await asyncio.sleep(self.config.reassessment_interval_seconds)
                await self._reassess_active_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue
                print(f"Reassessment error: {e}")
    
    async def _reassess_active_sessions(self) -> None:
        """Reassess all active sessions."""
        for session in self.store._sessions.values():
            if session.status.value == "active" and not session.is_expired():
                try:
                    await self.assess_session(session.session_id)
                except Exception:
                    pass
    
    # ========== Authentication Evaluation ==========
    
    async def evaluate_authentication(
        self,
        request: AuthenticationRequest,
    ) -> AuthenticationDecision:
        """Evaluate an authentication request and make a decision."""
        request_id = str(uuid.uuid4())
        
        # Create or get session
        if request.session_id:
            session = self.store.get_session(request.session_id)
        else:
            session = self.store.create_session(
                user_id=request.user_id,
                ip_address=request.ip_address,
                user_agent=request.user_agent,
                device_fingerprint=request.device_fingerprint,
                location=request.location,
                ttl_minutes=self.config.max_session_duration_hours * 60,
            )
        
        if not session:
            raise ValueError("Session not found or could not be created")
        
        # Evaluate risk
        profile = self.store.get_or_create_profile(request.user_id)
        risk_score = self.risk_engine.evaluate_risk(session, profile, request.context)
        
        # Analyze behavior
        behavior_result = self.behavior_monitor.analyze_behavior(session)
        
        # Log risk evaluation
        self.audit_service.log_risk_evaluation(
            session=session,
            risk_score=risk_score.total_score,
            risk_level=risk_score.risk_level,
            signals=[{"type": s.signal_type, "value": s.value} for s in risk_score.signals],
        )
        
        # Determine if step-up is required
        requires_step_up = (
            self.config.step_up_required_for_high_risk and
            risk_score.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ) or behavior_result.is_anomalous
        
        # Determine authentication status
        if requires_step_up:
            status = AuthenticationStatus.STEP_UP_REQUIRED
            challenges = [ChallengeType.SMS_OTP, ChallengeType.TOTP]
        else:
            status = AuthenticationStatus.SUCCESS
            challenges = []
        
        # Evaluate trust
        trust_result = self.session_evaluator.evaluate_session(session.session_id)
        trust_level = trust_result.trust_level if trust_result else TrustLevel.LOW
        
        # Create decision
        decision = AuthenticationDecision(
            request_id=request_id,
            session_id=session.session_id,
            user_id=request.user_id,
            status=status,
            risk_score=risk_score,
            required_challenges=challenges,
            session_trust_level=trust_level,
            allowed_auth_methods=self._get_allowed_auth_methods(risk_score.risk_level),
            expires_at=session.expires_at,
        )
        
        # Store decision
        self.store.store_decision(decision)
        
        # Log authentication attempt
        self.audit_service.log_authentication_attempt(
            session=session,
            risk_score=risk_score.total_score,
            outcome=status.value,
            challenges_issued=[c.value for c in challenges],
        )
        
        # Update behavior profile
        if self.config.behavior_learning_enabled:
            self.behavior_monitor.update_profile_from_session(session)
        
        return decision
    
    def _get_allowed_auth_methods(self, risk_level: RiskLevel) -> List[str]:
        """Get allowed authentication methods based on risk level."""
        base_methods = ["password"]
        
        if risk_level == RiskLevel.LOW:
            return base_methods + ["mfa", "biometric"]
        elif risk_level == RiskLevel.MEDIUM:
            return base_methods + ["mfa", "totp", "biometric"]
        elif risk_level == RiskLevel.HIGH:
            return ["mfa", "totp", "push_notification"]
        else:  # CRITICAL
            return ["hardware_token", "callback"]
    
    # ========== Risk Evaluation ==========
    
    async def evaluate_risk(
        self,
        request: RiskEvaluationRequest,
    ) -> RiskEvaluationResponse:
        """Evaluate risk for an action or session."""
        # Get or create session
        if request.session_id:
            session = self.store.get_session(request.session_id)
            if not session:
                raise ValueError("Session not found")
        else:
            session = self.store.create_session(
                user_id=request.user_id,
                ip_address=request.ip_address,
                user_agent=request.user_agent,
                device_fingerprint=request.device_fingerprint,
                location=request.location,
            )
        
        # Evaluate risk
        profile = self.store.get_or_create_profile(request.user_id)
        risk_score = self.risk_engine.evaluate_action_risk(
            session=session,
            action=request.action,
            resource=request.resource,
            context=request.context,
        )
        
        return RiskEvaluationResponse(
            session_id=session.session_id,
            user_id=request.user_id,
            risk_score=risk_score.total_score,
            risk_level=risk_score.risk_level,
            signals=[{"type": s.signal_type, "value": s.value, "weight": s.weight} for s in risk_score.signals],
            recommendation=risk_score.recommendation,
            requires_step_up=risk_score.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL),
        )
    
    # ========== Step-Up Authentication ==========
    
    async def initiate_challenge(
        self,
        session_id: str,
        user_id: str,
        challenge_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Initiate a step-up authentication challenge."""
        session = self.store.get_session(session_id)
        if not session:
            raise ValueError("Session not found")
        
        try:
            ctype = ChallengeType(challenge_type)
        except ValueError:
            raise ValueError(f"Invalid challenge type: {challenge_type}")
        
        challenge = self.stepup_service.create_challenge(
            session_id=session_id,
            user_id=user_id,
            challenge_type=ctype,
            metadata=metadata,
        )
        
        if not challenge:
            raise ValueError(f"Challenge type not enabled: {challenge_type}")
        
        # Log challenge initiation
        self.audit_service.log_stepup_challenge(
            session=session,
            challenge_id=challenge.challenge_id,
            challenge_type=challenge_type,
            outcome="initiated",
        )
        
        # Prepare response (hide actual code in production)
        response = {
            "challenge_id": challenge.challenge_id,
            "challenge_type": challenge_type,
            "status": challenge.status,
            "expires_at": challenge.expires_at.isoformat(),
            "max_attempts": challenge.max_attempts,
            "message": self._get_challenge_message(challenge_type),
        }
        
        # Include OTP for demo purposes (would be sent via SMS/email in production)
        if challenge.metadata.get("otp_to_send"):
            response["otp_code"] = challenge.metadata["otp_to_send"]
        
        return response
    
    def _get_challenge_message(self, challenge_type: str) -> str:
        """Get user-friendly message for challenge type."""
        messages = {
            "sms_otp": "A verification code has been sent to your registered phone.",
            "email_otp": "A verification code has been sent to your email.",
            "totp": "Enter the code from your authenticator app.",
            "push_notification": "A push notification has been sent to your device.",
            "biometric": "Please verify your identity using biometrics.",
            "hardware_token": "Enter the code from your hardware token.",
            "security_questions": "Please answer your security questions.",
            "callback": "You will receive a phone call to verify your identity.",
        }
        return messages.get(challenge_type, "Please complete the verification.")
    
    async def verify_challenge(
        self,
        challenge_id: str,
        response: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Verify a step-up challenge response."""
        result = self.stepup_service.verify_challenge(challenge_id, response, context)
        
        # Get challenge info for logging
        challenge_info = self.stepup_service.get_challenge_info(challenge_id)
        
        if challenge_info:
            session = self.store.get_session_unsafe(challenge_info["session_id"])
            if session:
                self.audit_service.log_stepup_challenge(
                    session=session,
                    challenge_id=challenge_id,
                    challenge_type=challenge_info["challenge_type"],
                    outcome="completed" if result.success else "failed",
                    attempts=challenge_info["attempts"],
                )
        
        return {
            "challenge_id": challenge_id,
            "success": result.success,
            "message": result.message,
            "remaining_attempts": result.remaining_attempts,
            "new_trust_level": result.new_trust_level,
        }
    
    # ========== Session Management ==========
    
    async def assess_session(
        self,
        session_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Assess a session and update its state."""
        session = self.store.get_session(session_id)
        if not session:
            raise ValueError("Session not found")
        
        # Re-evaluate risk
        profile = self.store.get_or_create_profile(session.user_id)
        risk_score = self.risk_engine.evaluate_risk(session, profile, context)
        
        # Evaluate trust
        trust_result = self.session_evaluator.evaluate_session(session_id)
        
        # Analyze behavior
        behavior_result = self.behavior_monitor.analyze_behavior(session)
        
        # Check if termination is required
        should_terminate = False
        termination_reason = None
        
        if self.config.automatic_session_termination:
            if trust_result and trust_result.trust_level == TrustLevel.NONE:
                should_terminate = True
                termination_reason = "Trust level dropped to none"
            elif risk_score.risk_level == RiskLevel.CRITICAL:
                should_terminate = True
                termination_reason = "Critical risk level detected"
        
        if should_terminate:
            self.session_evaluator.terminate_session(session_id, termination_reason)
            self.audit_service.log_session_termination(session, termination_reason)
            return {
                "session_id": session_id,
                "status": "terminated",
                "reason": termination_reason,
                "risk_level": risk_score.risk_level.value,
            }
        
        return {
            "session_id": session_id,
            "status": "active",
            "trust_level": trust_result.trust_level.value if trust_result else "unknown",
            "trust_score": trust_result.trust_score if trust_result else 0.0,
            "risk_level": risk_score.risk_level.value,
            "risk_score": risk_score.total_score,
            "anomalies_detected": len(behavior_result.anomalies),
            "recommendations": trust_result.recommendations if trust_result else [],
        }
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information."""
        session = self.store.get_session(session_id)
        if not session:
            return None
        
        trust_result = self.session_evaluator.evaluate_session(session_id)
        
        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "status": session.status.value,
            "trust_level": trust_result.trust_level.value if trust_result else session.trust.trust_level.value,
            "trust_score": trust_result.trust_score if trust_result else session.trust.trust_score,
            "risk_level": session.current_risk_score.risk_level.value if session.current_risk_score else "unknown",
            "created_at": session.created_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "ip_address": session.ip_address,
            "active_challenges": len(session.active_challenges),
            "recent_actions_count": len(session.recent_actions),
        }
    
    async def reassess_session(
        self,
        session_id: str,
        reason: str = "user_requested",
    ) -> Dict[str, Any]:
        """Manually trigger session reassessment."""
        trust_result = self.session_evaluator.reassess_session(session_id, reason)
        
        if not trust_result:
            raise ValueError("Session not found")
        
        session = self.store.get_session(session_id)
        
        return {
            "session_id": session_id,
            "status": session.status.value if session else "unknown",
            "trust_level": trust_result.trust_level.value,
            "trust_score": trust_result.trust_score,
            "action_required": trust_result.action_required,
            "recommendations": trust_result.recommendations,
            "reassessment_reason": reason,
        }
    
    # ========== Policy Management ==========
    
    async def get_policies(self) -> List[Dict[str, Any]]:
        """Get all authorization policies."""
        policies = self.policy_engine.get_policies()
        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "description": p.description,
                "resource_pattern": p.resource_pattern,
                "required_trust_level": p.required_trust_level.value,
                "required_risk_level": p.required_risk_level.value,
                "step_up_required": p.step_up_required,
                "action_on_violation": p.action_on_violation.value,
                "priority": p.priority,
                "enabled": p.enabled,
            }
            for p in policies
        ]
    
    async def create_policy(
        self,
        name: str,
        description: str,
        resource_pattern: str,
        required_trust_level: str = "low",
        required_risk_level: str = "high",
        step_up_required: bool = False,
        step_up_challenge_types: Optional[List[str]] = None,
        action_on_violation: str = "deny",
        conditions: Optional[Dict[str, Any]] = None,
        priority: int = 50,
    ) -> Dict[str, Any]:
        """Create a new authorization policy."""
        policy = self.policy_engine.create_policy(
            name=name,
            description=description,
            resource_pattern=resource_pattern,
            required_trust_level=TrustLevel(required_trust_level),
            required_risk_level=RiskLevel(required_risk_level),
            step_up_required=step_up_required,
            step_up_challenge_types=step_up_challenge_types,
            action_on_violation=PolicyAction(action_on_violation),
            conditions=conditions,
            priority=priority,
        )
        
        return {
            "policy_id": policy.policy_id,
            "name": policy.name,
            "created_at": policy.created_at.isoformat(),
        }
    
    # ========== Audit ==========
    
    async def get_audit_events(
        self,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query audit events."""
        from .audit import AuditQuery
        
        query = AuditQuery(
            user_id=user_id,
            session_id=session_id,
            event_type=event_type,
            start_time=datetime.fromisoformat(start_time) if start_time else None,
            end_time=datetime.fromisoformat(end_time) if end_time else None,
            limit=limit,
        )
        
        events = self.audit_service.query_events(query)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "severity": e.severity,
                "user_id": e.user_id,
                "session_id": e.session_id,
                "resource": e.resource,
                "action": e.action,
                "outcome": e.outcome,
            }
            for e in events
        ]
    
    # ========== Statistics ==========
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            "store": self.store.get_stats(),
            "policies": self.policy_engine.get_policy_stats(),
            "audit": self.audit_service.get_stats(),
        }


# Global service instance
_service: Optional[AdaptiveAuthService] = None


def get_adaptive_auth_service() -> AdaptiveAuthService:
    """Get the global adaptive auth service instance."""
    global _service
    if _service is None:
        _service = AdaptiveAuthService()
    return _service


def reset_service() -> None:
    """Reset the service (for testing)."""
    global _service
    if _service:
        asyncio.run(_service.stop())
    _service = None


# Synchronous convenience functions
def evaluate_risk_sync(
    user_id: str,
    ip_address: str = "",
    user_agent: str = "",
    device_fingerprint: str = "",
    location: Optional[Dict[str, Any]] = None,
) -> RiskScore:
    """Synchronous wrapper for risk evaluation."""
    return get_risk_engine().evaluate_login_risk(
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        device_fingerprint=device_fingerprint,
        location=location,
    )


def create_session_sync(
    user_id: str,
    ip_address: str = "",
    user_agent: str = "",
    device_fingerprint: str = "",
    location: Optional[Dict[str, Any]] = None,
) -> AuthenticationSession:
    """Synchronous wrapper for session creation."""
    return get_adaptive_auth_store().create_session(
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        device_fingerprint=device_fingerprint,
        location=location,
    )