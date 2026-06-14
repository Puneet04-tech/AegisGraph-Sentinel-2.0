"""
Storage layer for Adaptive Authentication & Continuous Authorization Engine.

Provides in-memory storage with thread-safe operations for sessions,
risk scores, behavior profiles, and authentication state.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    AuthenticationSession,
    AuthenticationDecision,
    AuthorizationPolicy,
    BehaviorProfile,
    RiskScore,
    SessionStatus,
    SessionTrust,
    StepUpChallenge,
    TrustLevel,
)


class LRUCache(OrderedDict):
    """Thread-safe LRU cache with configurable max size."""
    
    def __init__(self, maxsize: int = 10000, *args, **kwds):
        self.maxsize = maxsize
        super().__init__(*args, **kwds)
        self._lock = threading.RLock()
    
    def __getitem__(self, key: str):
        with self._lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value
    
    def __setitem__(self, key: str, value: Any):
        with self._lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]
    
    def __delitem__(self, key: str):
        with self._lock:
            super().__delitem__(key)
    
    def __contains__(self, key: str) -> bool:
        with self._lock:
            return super().__contains__(key)
    
    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            try:
                return self[key]
            except KeyError:
                return default
    
    def pop(self, key: str, *args) -> Any:
        with self._lock:
            return super().pop(key, *args)
    
    def clear(self) -> None:
        with self._lock:
            super().clear()


class AdaptiveAuthStore:
    """
    Central storage for adaptive authentication data.
    
    Provides O(1) session lookup and thread-safe operations.
    """
    
    def __init__(self, max_sessions: int = 100000, max_profiles: int = 100000):
        self._sessions: LRUCache = LRUCache(maxsize=max_sessions)
        self._profiles: LRUCache = LRUCache(maxsize=max_profiles)
        self._policies: Dict[str, AuthorizationPolicy] = {}
        self._decisions: LRUCache = LRUCache(maxsize=max_sessions)
        self._challenges: Dict[str, StepUpChallenge] = {}
        self._lock = threading.RLock()
        
        # Initialize default policies
        self._initialize_default_policies()
    
    def _initialize_default_policies(self) -> None:
        """Initialize with default authorization policies."""
        for policy in AuthorizationPolicy.create_default_policies():
            self._policies[policy.policy_id] = policy
    
    # Session Management
    def create_session(
        self,
        user_id: str,
        ip_address: str = "",
        user_agent: str = "",
        device_fingerprint: str = "",
        location: Optional[Dict[str, Any]] = None,
        ttl_minutes: int = 60,
    ) -> AuthenticationSession:
        """Create a new authentication session."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        trust = SessionTrust(
            session_id=session_id,
            user_id=user_id,
            trust_level=TrustLevel.LOW,
            trust_score=0.3,
            last_evaluated=now,
        )
        
        session = AuthenticationSession(
            session_id=session_id,
            user_id=user_id,
            status=SessionStatus.ACTIVE,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(minutes=ttl_minutes),
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            location=location,
            trust=trust,
        )
        
        self._sessions[session_id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[AuthenticationSession]:
        """Get session by ID with O(1) lookup."""
        session = self._sessions.get(session_id)
        if session and not session.is_expired():
            return session
        elif session:
            # Clean up expired session
            session.status = SessionStatus.EXPIRED
        return None
    
    def get_session_unsafe(self, session_id: str) -> Optional[AuthenticationSession]:
        """Get session without expiration check."""
        return self._sessions.get(session_id)
    
    def update_session(self, session: AuthenticationSession) -> None:
        """Update an existing session."""
        session.last_activity = datetime.now(timezone.utc)
        self._sessions[session.session_id] = session
    
    def terminate_session(self, session_id: str, reason: str = "") -> bool:
        """Terminate a session."""
        session = self._sessions.get(session_id)
        if session:
            session.status = SessionStatus.TERMINATED
            session.metadata["termination_reason"] = reason
            session.metadata["terminated_at"] = datetime.now(timezone.utc).isoformat()
            return True
        return False
    
    def get_user_sessions(self, user_id: str) -> List[AuthenticationSession]:
        """Get all active sessions for a user."""
        sessions = []
        now = datetime.now(timezone.utc)
        for session in self._sessions.values():
            if session.user_id == user_id and session.status == SessionStatus.ACTIVE:
                if session.expires_at > now:
                    sessions.append(session)
        return sessions
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions. Returns count of removed sessions."""
        count = 0
        now = datetime.now(timezone.utc)
        expired = []
        for session_id, session in self._sessions.items():
            if session.expires_at <= now:
                expired.append(session_id)
        for session_id in expired:
            del self._sessions[session_id]
            count += 1
        return count
    
    # Behavior Profile Management
    def get_or_create_profile(self, user_id: str) -> BehaviorProfile:
        """Get existing profile or create new one."""
        profile = self._profiles.get(user_id)
        if not profile:
            profile = BehaviorProfile(
                user_id=user_id,
                profile_id=str(uuid.uuid4()),
            )
            self._profiles[user_id] = profile
        return profile
    
    def get_profile(self, user_id: str) -> Optional[BehaviorProfile]:
        """Get behavior profile for user."""
        return self._profiles.get(user_id)
    
    def update_profile(self, profile: BehaviorProfile) -> None:
        """Update a behavior profile."""
        profile.last_updated = datetime.now(timezone.utc)
        self._profiles[profile.user_id] = profile
    
    # Risk Score Management
    def store_risk_score(self, risk_score: RiskScore) -> None:
        """Store a risk score for a session."""
        key = f"{risk_score.session_id}:{risk_score.timestamp.isoformat()}"
        self._decisions[key] = risk_score
    
    def get_latest_risk_score(self, session_id: str) -> Optional[RiskScore]:
        """Get the most recent risk score for a session."""
        latest = None
        latest_time = None
        for key, score in self._decisions.items():
            if key.startswith(session_id + ":"):
                if latest_time is None or score.timestamp > latest_time:
                    latest = score
                    latest_time = score.timestamp
        return latest
    
    def get_risk_scores(self, session_id: str, limit: int = 10) -> List[RiskScore]:
        """Get recent risk scores for a session."""
        scores = []
        for key, score in self._decisions.items():
            if key.startswith(session_id + ":"):
                scores.append((score.timestamp, score))
        scores.sort(key=lambda x: x[0], reverse=True)
        return [s[1] for s in scores[:limit]]
    
    # Authorization Policy Management
    def get_policies(self) -> List[AuthorizationPolicy]:
        """Get all authorization policies."""
        return list(self._policies.values())
    
    def get_enabled_policies(self) -> List[AuthorizationPolicy]:
        """Get enabled authorization policies sorted by priority."""
        policies = [p for p in self._policies.values() if p.enabled]
        policies.sort(key=lambda p: p.priority, reverse=True)
        return policies
    
    def get_policy(self, policy_id: str) -> Optional[AuthorizationPolicy]:
        """Get a specific policy."""
        return self._policies.get(policy_id)
    
    def add_policy(self, policy: AuthorizationPolicy) -> None:
        """Add a new authorization policy."""
        self._policies[policy.policy_id] = policy
    
    def update_policy(self, policy: AuthorizationPolicy) -> None:
        """Update an existing policy."""
        policy.updated_at = datetime.now(timezone.utc)
        self._policies[policy.policy_id] = policy
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete an authorization policy."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False
    
    # Step-Up Challenge Management
    def create_challenge(
        self,
        session_id: str,
        user_id: str,
        challenge_type: str,
    ) -> StepUpChallenge:
        """Create a new step-up challenge."""
        from .models import ChallengeType
        
        challenge = StepUpChallenge(
            challenge_id=str(uuid.uuid4()),
            session_id=session_id,
            user_id=user_id,
            challenge_type=ChallengeType(challenge_type),
        )
        self._challenges[challenge.challenge_id] = challenge
        return challenge
    
    def get_challenge(self, challenge_id: str) -> Optional[StepUpChallenge]:
        """Get a challenge by ID."""
        challenge = self._challenges.get(challenge_id)
        if challenge and not challenge.is_expired():
            return challenge
        return None
    
    def update_challenge(self, challenge: StepUpChallenge) -> None:
        """Update a challenge."""
        self._challenges[challenge.challenge_id] = challenge
    
    def get_session_challenges(self, session_id: str) -> List[StepUpChallenge]:
        """Get all active challenges for a session."""
        challenges = []
        for challenge in self._challenges.values():
            if challenge.session_id == session_id and challenge.status == "pending":
                if not challenge.is_expired():
                    challenges.append(challenge)
        return challenges
    
    # Decision Storage
    def store_decision(self, decision: AuthenticationDecision) -> None:
        """Store an authentication decision."""
        self._decisions[decision.request_id] = decision
    
    def get_decision(self, request_id: str) -> Optional[AuthenticationDecision]:
        """Get an authentication decision."""
        return self._decisions.get(request_id)
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        active_sessions = sum(
            1 for s in self._sessions.values()
            if s.status == SessionStatus.ACTIVE and not s.is_expired()
        )
        return {
            "total_sessions": len(self._sessions),
            "active_sessions": active_sessions,
            "total_profiles": len(self._profiles),
            "total_policies": len(self._policies),
            "enabled_policies": sum(1 for p in self._policies.values() if p.enabled),
            "active_challenges": sum(
                1 for c in self._challenges.values()
                if c.status == "pending" and not c.is_expired()
            ),
            "total_decisions": len(self._decisions),
        }


# Global store instance
_store: Optional[AdaptiveAuthStore] = None


def get_adaptive_auth_store() -> AdaptiveAuthStore:
    """Get the global adaptive auth store instance."""
    global _store
    if _store is None:
        _store = AdaptiveAuthStore()
    return _store


def reset_store() -> None:
    """Reset the store (for testing)."""
    global _store
    _store = None