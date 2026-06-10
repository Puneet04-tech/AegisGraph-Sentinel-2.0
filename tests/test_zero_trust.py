"""
Unit tests for Zero Trust Security Architecture
"""

import pytest
import time
from datetime import datetime, timezone

from src.zero_trust import (
    TrustLevel, TrustScore, DeviceTrust, DeviceFingerprint, DeviceStatus,
    SessionRisk, SessionRiskLevel, Policy, PolicyResult, EvaluationContext, RiskFactors,
    TrustEngine, DeviceTrustManager, SessionRiskAnalyzer, PolicyEnforcementEngine,
    ZeroTrustStore, ZeroTrustService, get_zero_trust_service,
)


class TestTrustLevel:
    def test_trust_levels_exist(self):
        assert TrustLevel.BLOCKED
        assert TrustLevel.UNTRUSTED
        assert TrustLevel.SUSPICIOUS
        assert TrustLevel.TRUSTED
        assert TrustLevel.HIGHLY_TRUSTED


class TestDeviceStatus:
    def test_device_statuses_exist(self):
        assert DeviceStatus.UNKNOWN
        assert DeviceStatus.REGISTERED
        assert DeviceStatus.BLOCKED


class TestRiskFactors:
    def test_default_values(self):
        factors = RiskFactors()
        assert factors.device_trust_score == 0.5
        assert factors.device_registered is False

    def test_to_dict(self):
        factors = RiskFactors(device_trust_score=0.8)
        data = factors.to_dict()
        assert "device_trust_score" in data


class TestTrustScore:
    def test_default_values(self):
        score = TrustScore()
        assert score.score == 0.5
        assert score.level == TrustLevel.SUSPICIOUS

    def test_to_dict(self):
        score = TrustScore(score=0.9, level=TrustLevel.HIGHLY_TRUSTED)
        data = score.to_dict()
        assert data["score"] == 0.9


class TestDeviceFingerprint:
    def test_fingerprint_generation(self):
        fingerprint = DeviceFingerprint(device_type="desktop", os_version="Windows 11")
        assert fingerprint.hash
        assert len(fingerprint.hash) == 32


class TestDeviceTrust:
    def test_default_values(self):
        device = DeviceTrust(device_id="test-123")
        assert device.device_id == "test-123"
        assert device.status == DeviceStatus.UNKNOWN


class TestSessionRisk:
    def test_default_values(self):
        session = SessionRisk(user_id="user-123")
        assert session.user_id == "user-123"
        assert session.risk_level == SessionRiskLevel.LOW


class TestEvaluationContext:
    def test_required_fields(self):
        context = EvaluationContext(user_id="user-123")
        assert context.user_id == "user-123"


class TestZeroTrustStore:
    def test_store_creation(self):
        store = ZeroTrustStore()
        assert store.cache_size > 0
        assert len(store.policies) > 0

    def test_default_policies(self):
        store = ZeroTrustStore()
        policies = store.get_all_policies()
        assert len(policies) >= 5

    def test_trust_score_caching(self):
        store = ZeroTrustStore()
        score = TrustScore(score=0.8)
        store.set_trust_score("user-123", "device-456", score)
        retrieved = store.get_trust_score("user-123", "device-456")
        assert retrieved is not None
        assert retrieved.score == 0.8

    def test_device_registration(self):
        store = ZeroTrustStore()
        device = DeviceTrust(device_id="test-device", fingerprint=DeviceFingerprint(user_id="user-123"))
        stored = store.register_device(device)
        assert stored.status == DeviceStatus.REGISTERED


class TestTrustEngine:
    def test_engine_creation(self):
        engine = TrustEngine()
        assert engine.evaluation_count == 0

    def test_evaluate_trust_basic(self):
        engine = TrustEngine()
        context = EvaluationContext(user_id="test-user")
        result = engine.evaluate_trust(context)
        assert isinstance(result, TrustScore)
        assert 0.0 <= result.score <= 1.0


class TestDeviceTrustManager:
    def test_manager_creation(self):
        manager = DeviceTrustManager()
        assert manager.registration_count == 0

    def test_register_device(self):
        manager = DeviceTrustManager()
        device_info = {"device_type": "desktop", "os_version": "Windows 11"}
        result = manager.register_device("user-123", device_info)
        assert result is not None
        assert result.fingerprint.user_id == "user-123"

    def test_evaluate_device_trust_unknown(self):
        manager = DeviceTrustManager()
        result = manager.evaluate_device_trust("nonexistent-device")
        assert result["trusted"] is False


class TestSessionRiskAnalyzer:
    def test_analyzer_creation(self):
        analyzer = SessionRiskAnalyzer()
        assert analyzer.sessions_analyzed == 0

    def test_analyze_session_basic(self):
        analyzer = SessionRiskAnalyzer()
        context = EvaluationContext(user_id="session-test-user", ip_address="192.168.1.100")
        result = analyzer.analyze_session(context)
        assert isinstance(result, SessionRisk)


class TestPolicyEnforcementEngine:
    def test_engine_creation(self):
        engine = PolicyEnforcementEngine()
        assert engine.evaluation_count == 0

    def test_evaluate_access_default_policies(self):
        engine = PolicyEnforcementEngine()
        context = EvaluationContext(user_id="policy-test-user")
        result = engine.evaluate_access(context)
        assert result.decision in ["ALLOW", "DENY", "CHALLENGE"]


class TestZeroTrustService:
    def test_service_creation(self):
        service = ZeroTrustService()
        assert service.total_requests == 0

    def test_evaluate_basic(self):
        service = ZeroTrustService()
        result = service.evaluate(user_id="service-test-user", ip_address="192.168.1.1")
        assert "trust_score" in result
        assert "final_decision" in result

    def test_register_device(self):
        service = ZeroTrustService()
        device_info = {"device_type": "mobile", "os_version": "iOS 17"}
        result = service.register_device("register-user", device_info)
        assert result["device_id"] is not None


class TestZeroTrustIntegration:
    def test_full_trust_evaluation_flow(self):
        service = ZeroTrustService()
        device_info = {"device_type": "desktop", "os_version": "Windows 11", "browser": "Chrome"}
        device_result = service.register_device("flow-user", device_info)
        device_id = device_result["device_id"]
        evaluation = service.evaluate(user_id="flow-user", device_id=device_id, ip_address="192.168.1.100")
        assert evaluation["final_decision"] in ["ALLOW", "CHALLENGE", "BLOCK"]


class TestZeroTrustPerformance:
    def test_trust_lookup_performance(self):
        service = ZeroTrustService()
        device_info = {"device_type": "desktop"}
        registered = service.register_device("perf-user", device_info)
        service.evaluate(user_id="perf-user", device_id=registered["device_id"])
        times = []
        for _ in range(10):
            start = time.time()
            service.evaluate(user_id="perf-user", device_id=registered["device_id"])
            times.append((time.time() - start) * 1000)
        avg_time = sum(times) / len(times)
        assert avg_time < 1000


class TestZeroTrustSecurity:
    def test_trust_score_boundaries(self):
        service = ZeroTrustService()
        for i in range(3):
            result = service.evaluate(user_id=f"edge-{i}", ip_address=f"192.168.1.{i}")
            score = result["trust_score"]["score"]
            assert 0.0 <= score <= 1.0

    def test_device_fingerprint_uniqueness(self):
        manager = DeviceTrustManager()
        device1 = manager.register_device("fp-user", {"device_type": "desktop"})
        device2 = manager.register_device("fp-user", {"device_type": "desktop"})
        assert device1.device_id != device2.device_id


# Run with: pytest tests/test_zero_trust.py -v