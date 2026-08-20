"""
Unit tests for automated webhook alerts integration in BehaviorMonitor (#2646).
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.adaptive_auth.behavior_monitor import (
    BehaviorAnomaly,
    BehaviorMonitor,
    AnomalyDetectionResult,
)
from src.adaptive_auth.models import (
    AuthenticationSession,
    RiskScore,
    RiskLevel,
    SessionStatus,
    SessionTrust,
    TrustLevel,
)
from src.adaptive_auth.store import AdaptiveAuthStore


@pytest.fixture
def mock_store():
    return AdaptiveAuthStore()


@pytest.fixture
def monitor(mock_store):
    return BehaviorMonitor(
        store=mock_store,
        webhook_url="https://hooks.example.com/alerts",
        webhook_secret="test_secret_key",
        risk_threshold=85.0,
    )


@pytest.fixture
def sample_session():
    now = datetime.now(timezone.utc)
    return AuthenticationSession(
        session_id="sess-12345",
        user_id="user-999",
        status=SessionStatus.ACTIVE,
        created_at=now,
        last_activity=now,
        expires_at=now + timedelta(hours=1),
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
        device_fingerprint="fp-abcdef",
        trust=SessionTrust(
            session_id="sess-12345",
            user_id="user-999",
            trust_level=TrustLevel.MEDIUM,
            trust_score=0.5,
            last_evaluated=now,
        ),
    )


def test_behavior_monitor_webhook_triggered_on_high_anomaly_score(monitor, sample_session):
    """Verify trigger_webhook_alert is called when anomaly score >= 0.85 (85/100)."""
    high_risk_result = AnomalyDetectionResult(
        is_anomalous=True,
        anomaly_score=0.90,  # 90/100 -> > 85 threshold
        anomalies=[
            BehaviorAnomaly(
                anomaly_id="anom-1",
                user_id=sample_session.user_id,
                session_id=sample_session.session_id,
                anomaly_type="location",
                severity="critical",
                description="Login from unknown country",
                detected_at=datetime.now(timezone.utc),
            )
        ],
        confidence=0.9,
    )

    with patch("src.adaptive_auth.behavior_monitor.trigger_webhook_alert") as mock_trigger:
        with patch.object(monitor.analyzer, "analyze_session_behavior", return_value=high_risk_result):
            res = monitor.analyze_behavior(sample_session)
            assert res.is_anomalous is True
            mock_trigger.assert_called_once()
            call_kwargs = mock_trigger.call_args.kwargs
            assert call_kwargs["url"] == "https://hooks.example.com/alerts"
            assert call_kwargs["secret_key"] == "test_secret_key"
            payload = call_kwargs["payload"]
            assert payload["event"] == "high_risk_anomaly_detected"
            assert payload["user_id"] == "user-999"
            assert payload["risk_score"] == 90.0
            assert payload["anomaly_count"] == 1


def test_behavior_monitor_webhook_triggered_on_high_risk_score(monitor, sample_session):
    """Verify webhook triggers when session.current_risk_score >= 85."""
    sample_session.current_risk_score = RiskScore(
        session_id=sample_session.session_id,
        user_id=sample_session.user_id,
        total_score=88.5,
        risk_level=RiskLevel.HIGH,
        signals=[],
        timestamp=datetime.now(timezone.utc),
    )
    low_anomaly_result = AnomalyDetectionResult(
        is_anomalous=True,
        anomaly_score=0.20,
        anomalies=[],
        confidence=0.5,
    )

    with patch("src.adaptive_auth.behavior_monitor.trigger_webhook_alert") as mock_trigger:
        with patch.object(monitor.analyzer, "analyze_session_behavior", return_value=low_anomaly_result):
            monitor.analyze_behavior(sample_session)
            mock_trigger.assert_called_once()
            assert mock_trigger.call_args.kwargs["payload"]["risk_score"] == 88.5


def test_behavior_monitor_webhook_not_triggered_on_low_risk(monitor, sample_session):
    """Verify webhook is NOT triggered when risk score is below 85."""
    low_risk_result = AnomalyDetectionResult(
        is_anomalous=False,
        anomaly_score=0.10,  # 10/100 -> < 85 threshold
        anomalies=[],
        confidence=0.5,
    )

    with patch("src.adaptive_auth.behavior_monitor.trigger_webhook_alert") as mock_trigger:
        with patch.object(monitor.analyzer, "analyze_session_behavior", return_value=low_risk_result):
            monitor.analyze_behavior(sample_session)
            mock_trigger.assert_not_called()


def test_behavior_monitor_webhook_exception_handling(monitor, sample_session):
    """Verify exception during webhook dispatch doesn't break behavior monitoring."""
    high_risk_result = AnomalyDetectionResult(
        is_anomalous=True,
        anomaly_score=0.95,
        anomalies=[],
        confidence=0.9,
    )

    with patch("src.adaptive_auth.behavior_monitor.trigger_webhook_alert", side_effect=RuntimeError("Webhook failed")):
        with patch.object(monitor.analyzer, "analyze_session_behavior", return_value=high_risk_result):
            # Should complete without throwing exception
            result = monitor.analyze_behavior(sample_session)
            assert result.anomaly_score == 0.95
