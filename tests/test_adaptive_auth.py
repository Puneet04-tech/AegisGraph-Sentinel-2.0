"""
Unit tests for Adaptive Authentication & Continuous Authorization Engine.

Tests cover:
- Risk scoring and signal evaluation
- Step-up authentication
- Session trust evaluation
- Policy enforcement
- Behavior monitoring
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# Import the adaptive auth modules
import sys
sys.path.insert(0, '/workspace/project/AegisGraph-Sentinel-2.0')

from src.adaptive_auth.models import (
    RiskLevel,
    AuthenticationStatus,
    ChallengeType,
    TrustLevel,
    PolicyAction,
    SessionStatus,
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
)

from src.adaptive_auth.store import AdaptiveAuthStore, LRUCache, get_adaptive_auth_store, reset_store
from src.adaptive_auth.risk_engine import RiskEngine, RiskSignalEvaluator, get_risk_engine, reset_engine
from src.adaptive_auth.behavior_monitor import BehaviorMonitor, BehaviorAnalyzer, get_behavior_monitor, reset_monitor
from src.adaptive_auth.session_evaluator import SessionEvaluator, TrustEvaluator, get_session_evaluator, reset_evaluator
from src.adaptive_auth.stepup_auth import StepUpAuthService, get_stepup_auth_service, reset_service as reset_stepup_service
from src.adaptive_auth.policy_engine import PolicyEngine, PolicyEvaluator, get_policy_engine
from src.adaptive_auth.audit import AuditService, get_audit_service, reset_audit_service
from src.adaptive_auth.service import AdaptiveAuthService, get_adaptive_auth_service, reset_service


class TestLRUCache:
    """Test LRU cache implementation."""
    
    def test_lru_cache_basic_operations(self):
        """Test basic get/set operations."""
        cache = LRUCache(maxsize=3)
        
        cache["a"] = 1
        cache["b"] = 2
        cache["c"] = 3
        
        assert cache["a"] == 1
        assert cache["b"] == 2
        assert cache["c"] == 3
    
    def test_lru_cache_eviction(self):
        """Test LRU eviction when max size reached."""
        cache = LRUCache(maxsize=3)
        
        cache["a"] = 1
        cache["b"] = 2
        cache["c"] = 3
        cache["d"] = 4  # Should evict "a"
        
        assert "a" not in cache
        assert cache["d"] == 4
    
    def test_lru_cache_access_order(self):
        """Test that accessing moves item to end."""
        cache = LRUCache(maxsize=3)
        
        cache["a"] = 1
        cache["b"] = 2
        cache["c"] = 3
        
        _ = cache["a"]  # Access "a"
        cache["d"] = 4  # Should evict "b" (least recently used)
        
        assert "b" not in cache
        assert "a" in cache


class TestModels:
    """Test data models."""
    
    def test_risk_score_calculation(self):
        """Test risk score calculation from signals."""
        signals = [
            RiskSignal("device", 0.5, 0.3, "test", datetime.now(timezone.utc)),
            RiskSignal("location", 0.3, 0.4, "test", datetime.now(timezone.utc)),
            RiskSignal("ip", 0.2, 0.3, "test", datetime.now(timezone.utc)),
        ]
        
        score = RiskScore.calculate("session1", "user1", signals)
        
        # Weighted sum: 0.5*0.3 + 0.3*0.4 + 0.2*0.3 = 0.15 + 0.12 + 0.06 = 0.33
        assert 0.3 <= score.total_score <= 0.4
        assert score.risk_level in RiskLevel
        assert len(score.signals) == 3
    
    def test_risk_level_assignment(self):
        """Test risk level assignment based on score."""
        signals = [RiskSignal("test", 0.0, 1.0, "test", datetime.now(timezone.utc))]
        
        # Test LOW (score < 0.3)
        score = RiskScore.calculate("s1", "u1", [RiskSignal("t", 0.1, 1.0, "t", datetime.now(timezone.utc))])
        assert score.risk_level == RiskLevel.LOW
        
        # Test MEDIUM (0.3 <= score < 0.6)
        score = RiskScore.calculate("s2", "u1", [RiskSignal("t", 0.4, 1.0, "t", datetime.now(timezone.utc))])
        assert score.risk_level == RiskLevel.MEDIUM
        
        # Test HIGH (0.6 <= score < 0.8)
        score = RiskScore.calculate("s3", "u1", [RiskSignal("t", 0.7, 1.0, "t", datetime.now(timezone.utc))])
        assert score.risk_level == RiskLevel.HIGH
        
        # Test CRITICAL (score >= 0.8)
        score = RiskScore.calculate("s4", "u1", [RiskSignal("t", 0.9, 1.0, "t", datetime.now(timezone.utc))])
        assert score.risk_level == RiskLevel.CRITICAL
    
    def test_session_trust_update(self):
        """Test trust score updates."""
        trust = SessionTrust(
            session_id="s1",
            user_id="u1",
            trust_level=TrustLevel.MEDIUM,
            trust_score=0.5,
            last_evaluated=datetime.now(timezone.utc),
        )
        
        # Test positive action
        trust.update(action_trusted=True)
        assert trust.trust_score > 0.5
        assert trust.consecutive_good_actions == 1
        assert trust.consecutive_bad_actions == 0
        
        # Test negative action
        trust.update(action_trusted=False)
        assert trust.trust_score < 0.5 + 0.05  # Should have decreased
        assert trust.consecutive_good_actions == 0
        assert trust.consecutive_bad_actions == 1
    
    def test_challenge_expiration(self):
        """Test challenge expiration logic."""
        challenge = StepUpChallenge(
            challenge_id="c1",
            session_id="s1",
            user_id="u1",
            challenge_type=ChallengeType.TOTP,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),  # Already expired
        )
        
        assert challenge.is_expired() is True
        
        challenge2 = StepUpChallenge(
            challenge_id="c2",
            session_id="s1",
            user_id="u1",
            challenge_type=ChallengeType.TOTP,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        
        assert challenge2.is_expired() is False
    
    def test_authorization_policy_defaults(self):
        """Test default policy creation."""
        policies = AuthorizationPolicy.create_default_policies()
        
        assert len(policies) > 0
        assert all(p.policy_id for p in policies)
        assert all(p.enabled for p in policies)


class TestAdaptiveAuthStore:
    """Test adaptive authentication store."""
    
    def setup_method(self):
        """Reset store before each test."""
        reset_store()
    
    def test_session_creation(self):
        """Test session creation."""
        store = get_adaptive_auth_store()
        
        session = store.create_session(
            user_id="user1",
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
        )
        
        assert session.user_id == "user1"
        assert session.status == SessionStatus.ACTIVE
        assert session.trust.trust_level == TrustLevel.LOW
    
    def test_session_retrieval(self):
        """Test session retrieval with O(1) lookup."""
        store = get_adaptive_auth_store()
        
        session = store.create_session(user_id="user1")
        session_id = session.session_id
        
        retrieved = store.get_session(session_id)
        
        assert retrieved is not None
        assert retrieved.session_id == session_id
    
    def test_session_expiration(self):
        """Test expired session handling."""
        store = get_adaptive_auth_store()
        
        session = store.create_session(
            user_id="user1",
            ttl_minutes=0,  # Immediate expiration
        )
        
        import time
        time.sleep(0.1)
        
        retrieved = store.get_session(session.session_id)
        assert retrieved is None
    
    def test_profile_management(self):
        """Test behavior profile creation and retrieval."""
        store = get_adaptive_auth_store()
        
        profile = store.get_or_create_profile("user1")
        
        assert profile.user_id == "user1"
        assert profile.profile_id is not None
        
        # Get same profile
        profile2 = store.get_or_create_profile("user1")
        assert profile.profile_id == profile2.profile_id
    
    def test_policy_management(self):
        """Test authorization policy CRUD."""
        store = get_adaptive_auth_store()
        
        policies = store.get_policies()
        initial_count = len(policies)
        
        new_policy = AuthorizationPolicy(
            policy_id="test-policy-1",
            name="Test Policy",
            description="A test policy",
            resource_pattern="/api/v1/test.*",
            required_trust_level=TrustLevel.LOW,
            required_risk_level=RiskLevel.HIGH,
        )
        
        store.add_policy(new_policy)
        
        policies = store.get_policies()
        assert len(policies) == initial_count + 1
        
        retrieved = store.get_policy("test-policy-1")
        assert retrieved is not None
        assert retrieved.name == "Test Policy"
        
        store.delete_policy("test-policy-1")
        policies = store.get_policies()
        assert len(policies) == initial_count


class TestRiskEngine:
    """Test risk evaluation engine."""
    
    def setup_method(self):
        """Reset components before each test."""
        reset_store()
        reset_engine()
    
    def test_risk_evaluation(self):
        """Test basic risk evaluation."""
        store = get_adaptive_auth_store()
        engine = get_risk_engine()
        
        session = store.create_session(
            user_id="user1",
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
            device_fingerprint="device123",
        )
        
        profile = store.get_or_create_profile("user1")
        risk_score = engine.evaluate_risk(session, profile)
        
        assert risk_score is not None
        assert 0.0 <= risk_score.total_score <= 1.0
        assert risk_score.risk_level in RiskLevel
    
    def test_login_risk_evaluation(self):
        """Test login risk evaluation convenience function."""
        risk_score = get_risk_engine().evaluate_login_risk(
            user_id="user1",
            ip_address="10.0.0.1",  # Private IP - lower risk
            user_agent="Chrome/120.0",
            device_fingerprint="trusted_device",
        )
        
        assert risk_score is not None
        # Private IPs should have lower risk
        assert risk_score.total_score < 0.3
    
    def test_ip_reputation_update(self):
        """Test IP reputation database updates."""
        engine = get_risk_engine()
        
        # Add malicious IP
        engine.update_ip_reputation("1.2.3.4", is_malicious=True)
        
        # Verify it's tracked
        store = get_adaptive_auth_store()
        session = store.create_session(
            user_id="user1",
            ip_address="1.2.3.4",
        )
        
        profile = store.get_or_create_profile("user1")
        risk_score = engine.evaluate_risk(session, profile)
        
        # Should have elevated risk due to malicious IP (IP reputation adds 0.12)
        assert risk_score.total_score > 0.3
        # The malicious IP signal should be present
        ip_signal = next((s for s in risk_score.signals if s.signal_type == "ip_reputation"), None)
        assert ip_signal is not None
        assert ip_signal.value == 1.0


class TestBehaviorMonitor:
    """Test behavior monitoring engine."""
    
    def setup_method(self):
        """Reset components before each test."""
        reset_store()
        reset_monitor()
    
    def test_anomaly_detection(self):
        """Test anomaly detection."""
        store = get_adaptive_auth_store()
        monitor = get_behavior_monitor()
        
        # Create session with unusual location
        session = store.create_session(
            user_id="user1",
            location={"country": "RU", "city": "Moscow"},
        )
        
        # Create profile with typical locations (different country)
        profile = store.get_or_create_profile("user1")
        profile.typical_locations = ["US:New York", "US:Los Angeles"]
        
        result = monitor.analyze_behavior(session)
        
        assert result is not None
        # Should detect location anomaly
        assert result.is_anomalous or len(result.anomalies) > 0
    
    def test_profile_update(self):
        """Test profile learning from session."""
        store = get_adaptive_auth_store()
        monitor = get_behavior_monitor()
        
        session = store.create_session(
            user_id="user1",
            ip_address="192.168.1.1",
            device_fingerprint="device123",
            location={"country": "US", "city": "New York"},
        )
        
        profile = monitor.update_profile_from_session(session)
        
        assert "192.168.1.1" in profile.typical_ip_ranges or len(profile.typical_ip_ranges) > 0
        assert "device123" in profile.typical_devices
        assert "US:New York" in profile.typical_locations
    
    def test_behavioral_drift(self):
        """Test behavioral drift detection."""
        store = get_adaptive_auth_store()
        monitor = get_behavior_monitor()
        
        profile = store.get_or_create_profile("user1")
        
        # Add historical risk scores
        for i in range(10):
            profile.risk_history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "score": 0.2 + (i * 0.05),  # Gradually increasing
                "level": "low",
            })
        
        store.update_profile(profile)
        
        drift = monitor.get_behavioral_drift("user1")
        
        assert "drift_score" in drift
        assert "drift_detected" in drift


class TestSessionEvaluator:
    """Test session trust evaluation."""
    
    def setup_method(self):
        """Reset components before each test."""
        reset_store()
        reset_evaluator()
    
    def test_trust_evaluation(self):
        """Test trust evaluation."""
        store = get_adaptive_auth_store()
        evaluator = get_session_evaluator()
        
        session = store.create_session(
            user_id="user1",
            ip_address="192.168.1.1",
        )
        
        result = evaluator.evaluate_session(session.session_id)
        
        assert result is not None
        assert result.trust_level in TrustLevel
        assert 0.0 <= result.trust_score <= 1.0
    
    def test_trust_adjustment(self):
        """Test trust adjustments based on actions."""
        store = get_adaptive_auth_store()
        evaluator = get_session_evaluator()
        
        session = store.create_session(user_id="user1")
        initial_trust = session.trust.trust_score
        
        # Record successful action
        evaluator.record_action(
            session_id=session.session_id,
            action_type="login",
            outcome="success",
        )
        
        session = store.get_session(session.session_id)
        assert session.trust.trust_score > initial_trust or session.trust.consecutive_good_actions > 0
    
    def test_session_reassessment(self):
        """Test session reassessment."""
        store = get_adaptive_auth_store()
        evaluator = get_session_evaluator()
        
        session = store.create_session(user_id="user1")
        
        result = evaluator.reassess_session(session.session_id, "test_reassessment")
        
        assert result is not None
        assert result.trust_level is not None


class TestStepUpAuth:
    """Test step-up authentication."""
    
    def setup_method(self):
        """Reset components before each test."""
        reset_store()
        reset_stepup_service()
    
    def test_challenge_creation(self):
        """Test challenge creation."""
        store = get_adaptive_auth_store()
        service = get_stepup_auth_service()
        
        session = store.create_session(user_id="user1")
        
        challenge = service.create_challenge(
            session_id=session.session_id,
            user_id="user1",
            challenge_type=ChallengeType.TOTP,
        )
        
        assert challenge is not None
        assert challenge.challenge_id is not None
        assert challenge.status == "pending"
        assert not challenge.is_expired()
    
    def test_challenge_verification(self):
        """Test challenge verification (mock)."""
        store = get_adaptive_auth_store()
        service = get_stepup_auth_service()
        
        session = store.create_session(user_id="user1")
        
        challenge = service.create_challenge(
            session_id=session.session_id,
            user_id="user1",
            challenge_type=ChallengeType.EMAIL_OTP,
        )
        
        # Get the OTP that would be sent
        otp = challenge.metadata.get("otp_to_send")
        assert otp is not None
        
        # Verify with correct OTP
        result = service.verify_challenge(challenge.challenge_id, otp)
        
        assert result.success is True
        assert "verified" in result.message.lower()
    
    def test_challenge_max_attempts(self):
        """Test challenge max attempts enforcement."""
        store = get_adaptive_auth_store()
        service = get_stepup_auth_service()
        
        session = store.create_session(user_id="user1")
        
        challenge = service.create_challenge(
            session_id=session.session_id,
            user_id="user1",
            challenge_type=ChallengeType.EMAIL_OTP,
        )
        
        # Try wrong OTP multiple times
        for i in range(challenge.max_attempts):
            result = service.verify_challenge(challenge.challenge_id, "000000")
        
        # Should be blocked now
        assert result.remaining_attempts == 0
        assert result.success is False
    
    def test_totp_setup(self):
        """Test TOTP setup."""
        service = get_stepup_auth_service()
        
        setup = service.setup_totp("user1")
        
        assert "secret" in setup
        assert "provisioning_uri" in setup
        assert setup["algorithm"] == "SHA1"
        assert setup["digits"] == 6


class TestPolicyEngine:
    """Test authorization policy engine."""
    
    def setup_method(self):
        """Reset components before each test."""
        reset_store()
    
    def test_policy_evaluation_allow(self):
        """Test policy evaluation allowing access."""
        store = get_adaptive_auth_store()
        engine = get_policy_engine()
        
        session = store.create_session(
            user_id="user1",
            ip_address="192.168.1.1",
        )
        # Set auth methods in session metadata to satisfy policy requirements
        session.metadata["auth_methods"] = ["password", "mfa"]
        store.update_session(session)
        
        decision = engine.evaluate_access(
            session_id=session.session_id,
            resource="/api/v1/users/profile",
            action="read",
        )
        
        assert decision is not None
        # With proper auth methods, access should be allowed
        assert decision.allowed is True or decision.final_action == PolicyAction.ALLOW
    
    def test_policy_evaluation_deny(self):
        """Test policy evaluation denying access."""
        store = get_adaptive_auth_store()
        engine = get_policy_engine()
        
        session = store.create_session(user_id="user1")
        
        # Manually set low trust level
        session.trust.trust_level = TrustLevel.NONE
        store.update_session(session)
        
        decision = engine.evaluate_access(
            session_id=session.session_id,
            resource="/api/v1/admin/users",
            action="delete",
        )
        
        # Should be denied due to no trust
        assert decision.allowed is False or decision.final_action != PolicyAction.ALLOW
    
    def test_policy_creation(self):
        """Test policy creation."""
        store = get_adaptive_auth_store()
        engine = get_policy_engine()
        
        initial_count = len(engine.get_policies())
        
        policy = engine.create_policy(
            name="Test Policy",
            description="Test description",
            resource_pattern="/api/v1/test.*",
            required_trust_level=TrustLevel.MEDIUM,
            required_risk_level=RiskLevel.HIGH,
            action_on_violation=PolicyAction.DENY,
        )
        
        assert policy.policy_id is not None
        
        policies = engine.get_policies()
        assert len(policies) == initial_count + 1


class TestAuditService:
    """Test audit logging service."""
    
    def setup_method(self):
        """Reset components before each test."""
        reset_store()
        reset_audit_service()
    
    def test_event_logging(self):
        """Test audit event logging."""
        store = get_adaptive_auth_store()
        audit = get_audit_service()
        
        event = audit.log_event(
            event_type="test_event",
            severity="info",
            user_id="user1",
            resource="/api/v1/test",
            action="test",
            outcome="success",
        )
        
        assert event.event_id is not None
        assert event.event_type == "test_event"
    
    def test_event_query(self):
        """Test event querying."""
        store = get_adaptive_auth_store()
        audit = get_audit_service()
        
        # Log multiple events
        for i in range(5):
            audit.log_event(
                event_type="test_event",
                severity="info",
                user_id=f"user{i}",
                resource="/api/v1/test",
                action="test",
                outcome="success",
            )
        
        from src.adaptive_auth.audit import AuditQuery
        query = AuditQuery(limit=10)
        events = audit.query_events(query)
        
        assert len(events) >= 5
    
    def test_audit_summary(self):
        """Test audit summary generation."""
        audit = get_audit_service()
        
        # Log some events
        audit.log_event(
            event_type="authentication_attempt",
            severity="info",
            user_id="user1",
            resource="/auth",
            action="login",
            outcome="success",
        )
        
        audit.log_event(
            event_type="authentication_attempt",
            severity="warning",
            user_id="user2",
            resource="/auth",
            action="login",
            outcome="failed",
        )
        
        summary = audit.get_summary()
        
        assert summary.total_events >= 2
        assert "authentication_attempt" in summary.events_by_type


class TestAdaptiveAuthService:
    """Test main adaptive authentication service."""
    
    def setup_method(self):
        """Reset all services before each test."""
        reset_store()
        reset_engine()
        reset_monitor()
        reset_evaluator()
        reset_stepup_service()
        reset_audit_service()
        reset_service()
    
    def test_risk_evaluation(self):
        """Test service-level risk evaluation."""
        import asyncio
        
        service = get_adaptive_auth_service()
        
        async def run_test():
            from src.adaptive_auth.models import RiskEvaluationRequest
            
            request = RiskEvaluationRequest(
                user_id="user1",
                ip_address="192.168.1.1",
                user_agent="TestAgent/1.0",
                action="login",
                resource="/api/v1/auth/login",
            )
            
            result = await service.evaluate_risk(request)
            
            assert result is not None
            assert result.risk_score is not None
            assert 0.0 <= result.risk_score <= 1.0
        
        asyncio.run(run_test())
    
    def test_session_assessment(self):
        """Test session assessment."""
        import asyncio
        
        service = get_adaptive_auth_service()
        store = get_adaptive_auth_store()
        
        session = store.create_session(user_id="user1")
        
        async def run_test():
            result = await service.assess_session(session.session_id)
            
            assert result is not None
            assert "status" in result
            assert "trust_level" in result
            assert "risk_level" in result
        
        asyncio.run(run_test())


class TestIntegration:
    """Integration tests for complete flows."""
    
    def setup_method(self):
        """Reset all services before each test."""
        reset_store()
        reset_engine()
        reset_monitor()
        reset_evaluator()
        reset_stepup_service()
        reset_audit_service()
        reset_service()
    
    def test_complete_authentication_flow(self):
        """Test complete authentication flow with step-up."""
        import asyncio
        
        service = get_adaptive_auth_service()
        store = get_adaptive_auth_store()
        
        async def run_test():
            from src.adaptive_auth.models import AuthenticationRequest
            
            # Step 1: Initial authentication request
            auth_request = AuthenticationRequest(
                user_id="user1",
                ip_address="192.168.1.1",
                user_agent="Chrome/120.0",
                device_fingerprint="trusted_device",
                requested_resource="/api/v1/account",
            )
            
            decision = await service.evaluate_authentication(auth_request)
            
            assert decision is not None
            assert decision.session_id is not None
            
            # Step 2: If step-up required, create challenge
            if decision.status == AuthenticationStatus.STEP_UP_REQUIRED:
                challenge_type = decision.required_challenges[0].value
                
                challenge = await service.initiate_challenge(
                    session_id=decision.session_id,
                    user_id="user1",
                    challenge_type=challenge_type,
                )
                
                assert challenge is not None
                assert "challenge_id" in challenge
            
            # Step 3: Get session info
            session_info = await service.get_session(decision.session_id)
            
            assert session_info is not None
            assert session_info["user_id"] == "user1"
        
        asyncio.run(run_test())
    
    def test_policy_enforcement_flow(self):
        """Test policy enforcement with different trust levels."""
        store = get_adaptive_auth_store()
        engine = get_policy_engine()
        
        # Create session with high trust
        high_trust_session = store.create_session(user_id="user1")
        high_trust_session.trust.trust_level = TrustLevel.HIGH
        high_trust_session.trust.trust_score = 0.9
        store.update_session(high_trust_session)
        
        # Create session with low trust
        low_trust_session = store.create_session(user_id="user2")
        low_trust_session.trust.trust_level = TrustLevel.LOW
        low_trust_session.trust.trust_score = 0.2
        store.update_session(low_trust_session)
        
        # High trust should have easier access
        high_trust_decision = engine.evaluate_access(
            session_id=high_trust_session.session_id,
            resource="/api/v1/users/profile",
        )
        
        low_trust_decision = engine.evaluate_access(
            session_id=low_trust_session.session_id,
            resource="/api/v1/users/profile",
        )
        
        # High trust should generally have better access outcomes
        assert high_trust_decision.allowed or high_trust_decision.final_action.value <= low_trust_decision.final_action.value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])