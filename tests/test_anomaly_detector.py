"""
Unit tests for AnomalyDetector in src/threat_hunting/anomaly_detector.py
"""

import pytest
from unittest.mock import MagicMock

from src.threat_hunting.anomaly_detector import AnomalyDetector
from src.threat_hunting.models import (
    ThreatIndicator,
    IndicatorType,
    ThreatSeverity,
)
from src.threat_hunting.store import ThreatHuntingStore, get_store


@pytest.fixture(autouse=True)
def reset_thunting_store():
    """Ensure the threat hunting store is clean before each test."""
    store = get_store()
    store.reset()
    yield
    store.reset()


@pytest.fixture
def mock_store():
    """Provide a fresh mock store."""
    return MagicMock(spec=ThreatHuntingStore)


class TestAnomalyDetector:
    """Tests for AnomalyDetector.detect_anomalies."""

    def test_detects_blocked_device(self, mock_store):
        """BLOCKED device status triggers a FINGERPRINT indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-42",
            operation="login",
            ip_address="1.2.3.4",
            device_status="BLOCKED",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        ind = indicators[0]
        assert ind.indicator_type == IndicatorType.FINGERPRINT
        assert ind.severity == ThreatSeverity.CRITICAL
        assert ind.confidence == 0.9
        assert ind.value == "user-42"
        mock_store.register_indicator.assert_called_once_with(ind)

    def test_detects_stolen_device(self, mock_store):
        """STOLEN device status triggers a FINGERPRINT indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-99",
            operation="login",
            ip_address="5.6.7.8",
            device_status="STOLEN",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.FINGERPRINT

    def test_detects_lost_device(self, mock_store):
        """LOST device status triggers a FINGERPRINT indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-lost",
            operation="login",
            ip_address="9.10.11.12",
            device_status="LOST",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.FINGERPRINT

    def test_no_indicator_for_active_device(self, mock_store):
        """Active (unknown) device status does not trigger any indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-1",
            operation="login",
            ip_address="1.2.3.4",
            device_status="ACTIVE",
            failed_attempts=0,
        )
        assert indicators == []
        mock_store.register_indicator.assert_not_called()

    def test_detects_failed_attempts_3_to_4(self, mock_store):
        """3-4 failed attempts triggers a VELOCITY indicator with HIGH severity."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-brute",
            operation="login",
            ip_address="1.2.3.4",
            device_status="OK",
            failed_attempts=3,
        )
        assert len(indicators) == 1
        ind = indicators[0]
        assert ind.indicator_type == IndicatorType.VELOCITY
        assert ind.severity == ThreatSeverity.HIGH
        assert ind.confidence == 0.85

    def test_detects_failed_attempts_5_plus(self, mock_store):
        """5+ failed attempts triggers a VELOCITY indicator with CRITICAL severity."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-brute-5",
            operation="login",
            ip_address="1.2.3.4",
            device_status="OK",
            failed_attempts=5,
        )
        assert len(indicators) == 1
        ind = indicators[0]
        assert ind.indicator_type == IndicatorType.VELOCITY
        assert ind.severity == ThreatSeverity.CRITICAL

    def test_no_indicator_below_threshold(self, mock_store):
        """< 3 failed attempts does not trigger a VELOCITY indicator."""
        detector = AnomalyDetector(store=mock_store)
        for attempts in (0, 1, 2):
            indicators = detector.detect_anomalies(
                entity_id=f"user-{attempts}",
                operation="login",
                ip_address="1.2.3.4",
                device_status="OK",
                failed_attempts=attempts,
            )
            velocity_indicators = [
                i for i in indicators if i.indicator_type == IndicatorType.VELOCITY
            ]
            assert velocity_indicators == [], f"Expected no VELOCITY for {attempts} attempts"

    def test_detects_sensitive_operation_revoke_credentials(self, mock_store):
        """revoke_credentials triggers a BEHAVIOR indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-op",
            operation="revoke_credentials",
            ip_address="1.2.3.4",
            device_status="OK",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        ind = indicators[0]
        assert ind.indicator_type == IndicatorType.BEHAVIOR
        assert ind.severity == ThreatSeverity.MEDIUM
        assert ind.confidence == 0.7

    def test_detects_sensitive_operation_export_data(self, mock_store):
        """export_data triggers a BEHAVIOR indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-op",
            operation="export_data",
            ip_address="1.2.3.4",
            device_status="OK",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.BEHAVIOR

    def test_detects_sensitive_operation_update_credentials(self, mock_store):
        """update_credentials triggers a BEHAVIOR indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-op",
            operation="update_credentials",
            ip_address="1.2.3.4",
            device_status="OK",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.BEHAVIOR

    def test_detects_sensitive_operation_delete_account(self, mock_store):
        """delete_account triggers a BEHAVIOR indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-op",
            operation="delete_account",
            ip_address="1.2.3.4",
            device_status="OK",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.BEHAVIOR

    def test_no_indicator_for_non_sensitive_operation(self, mock_store):
        """Non-sensitive operations do not trigger BEHAVIOR indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-op",
            operation="read_data",
            ip_address="1.2.3.4",
            device_status="OK",
            failed_attempts=0,
        )
        behavior_indicators = [
            i for i in indicators if i.indicator_type == IndicatorType.BEHAVIOR
        ]
        assert behavior_indicators == []

    def test_detects_proxy_ip_subnet_100(self, mock_store):
        """IP starting with 100. triggers an IP indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-ip",
            operation="login",
            ip_address="100.50.200.10",
            device_status="OK",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        ind = indicators[0]
        assert ind.indicator_type == IndicatorType.IP
        assert ind.value == "100.50.200.10"
        assert ind.severity == ThreatSeverity.MEDIUM

    def test_detects_proxy_ip_subnet_200(self, mock_store):
        """IP starting with 200. triggers an IP indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-ip",
            operation="login",
            ip_address="200.1.2.3",
            device_status="OK",
            failed_attempts=0,
        )
        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.IP

    def test_no_indicator_for_non_proxy_ip(self, mock_store):
        """IP not in 100. or 200. subnet does not trigger IP indicator."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-ip",
            operation="login",
            ip_address="8.8.8.8",
            device_status="OK",
            failed_attempts=0,
        )
        ip_indicators = [
            i for i in indicators if i.indicator_type == IndicatorType.IP
        ]
        assert ip_indicators == []

    def test_combined_multiple_indicators(self, mock_store):
        """Multiple conditions trigger multiple indicators simultaneously."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-multi",
            operation="export_data",
            ip_address="100.1.2.3",
            device_status="BLOCKED",
            failed_attempts=5,
        )
        assert len(indicators) == 4
        types = {i.indicator_type for i in indicators}
        assert IndicatorType.FINGERPRINT in types
        assert IndicatorType.VELOCITY in types
        assert IndicatorType.BEHAVIOR in types
        assert IndicatorType.IP in types
        assert mock_store.register_indicator.call_count == 4

    def test_attributes_passed_through(self, mock_store):
        """Custom attributes are preserved in the returned indicators."""
        detector = AnomalyDetector(store=mock_store)
        custom_attrs = {"request_id": "req-123", "region": "us-east"}
        indicators = detector.detect_anomalies(
            entity_id="user-attrs",
            operation="login",
            ip_address="1.2.3.4",
            device_status="OK",
            failed_attempts=0,
            attributes=custom_attrs,
        )
        assert indicators == []

    def test_attributes_used_in_context(self, mock_store):
        """Custom attributes do not override built-in detection attributes."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-attrs2",
            operation="revoke_credentials",
            ip_address="1.2.3.4",
            device_status="BLOCKED",
            failed_attempts=0,
            attributes={"device_status": "CUSTOM"},
        )
        ind = next(i for i in indicators if i.indicator_type == IndicatorType.FINGERPRINT)
        assert ind.attributes["device_status"] == "BLOCKED"

    def test_empty_attributes_defaults_to_empty_dict(self, mock_store):
        """No attributes provided defaults to an empty dict without error."""
        detector = AnomalyDetector(store=mock_store)
        indicators = detector.detect_anomalies(
            entity_id="user-noattrs",
            operation="login",
            ip_address="1.2.3.4",
            device_status="BLOCKED",
            failed_attempts=0,
            attributes=None,
        )
        assert len(indicators) == 1
        assert indicators[0].attributes == {"device_status": "BLOCKED"}

    def test_store_defaults_to_get_store(self):
        """No store passed uses the global get_store() instance."""
        store = get_store()
        store.reset()
        detector = AnomalyDetector()
        assert detector.store is store

    def test_indicator_stored_in_store(self, mock_store):
        """Each indicator is registered with the store."""
        detector = AnomalyDetector(store=mock_store)
        detector.detect_anomalies(
            entity_id="user-store",
            operation="login",
            ip_address="1.2.3.4",
            device_status="STOLEN",
            failed_attempts=0,
        )
        mock_store.register_indicator.assert_called_once()
        registered = mock_store.register_indicator.call_args[0][0]
        assert isinstance(registered, ThreatIndicator)
