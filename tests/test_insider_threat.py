"""Tests for Insider Threat Detection Platform"""

import pytest
from src.insider_threat.models import (
    InsiderProfile,
    BehavioralBaseline,
    ActivityRecord,
    ThreatIndicator,
    InsiderCampaign,
    ThreatLevel,
    ActivityType,
)
from src.insider_threat.store import InsiderThreatStore, get_insider_store


class TestInsiderThreatModels:
    def test_create_insider_profile(self):
        profile = InsiderProfile(
            employee_id="EMP001",
            department="Engineering",
            role="Developer",
            threat_level=ThreatLevel.LOW,
        )
        assert profile.employee_id == "EMP001"
        assert profile.role == "Developer"
        assert profile.threat_level == ThreatLevel.LOW

    def test_create_behavioral_baseline(self):
        baseline = BehavioralBaseline(
            employee_id="EMP001",
            activity_type=ActivityType.LOGIN,
            avg_frequency=8.0,
            avg_duration=480.0,
            typical_hours=[9, 10, 11, 12, 13, 14, 15, 16, 17],
        )
        assert len(baseline.typical_hours) == 9
        assert baseline.avg_duration == 480.0

    def test_create_activity_record(self):
        record = ActivityRecord(
            employee_id="EMP001",
            activity_type=ActivityType.FILE_ACCESS,
            resource_accessed="/data/restricted",
            location="192.168.1.1",
            device_id="device123",
        )
        assert record.employee_id == "EMP001"
        assert record.activity_type == ActivityType.FILE_ACCESS

    def test_create_threat_indicator(self):
        indicator = ThreatIndicator(
            employee_id="EMP001",
            indicator_type="anomalous_access",
            severity=ThreatLevel.HIGH,
            description="Access to restricted resource after hours",
            confidence=0.85,
        )
        assert indicator.severity == ThreatLevel.HIGH
        assert indicator.confidence == 0.85

    def test_create_insider_campaign(self):
        campaign = InsiderCampaign(
            involved_employees=["EMP001", "EMP002"],
            threat_type="data_exfiltration",
            risk_score=0.85,
            threat_level=ThreatLevel.CRITICAL,
        )
        assert len(campaign.involved_employees) == 2
        assert campaign.threat_level == ThreatLevel.CRITICAL


class TestInsiderThreatStore:
    def setup_method(self):
        self.store = InsiderThreatStore()

    def test_save_and_get_profile(self):
        profile = InsiderProfile(
            employee_id="EMP005",
            department="HR",
            role="Manager",
        )
        self.store.store_profile(profile)
        retrieved = self.store.get_employee_profile("EMP005")
        assert retrieved is not None
        assert retrieved.department == "HR"

    def test_save_and_get_indicator(self):
        indicator = ThreatIndicator(
            employee_id="EMP006",
            indicator_type="policy_violation",
            severity=ThreatLevel.CRITICAL,
            description="Severe policy breach",
            confidence=0.9,
        )
        self.store.store_indicator(indicator)
        indicators = self.store.get_employee_indicators("EMP006")
        assert len(indicators) == 1
        assert indicators[0].confidence == 0.9

    def test_get_active_indicators(self):
        indicator = ThreatIndicator(
            employee_id="EMP007",
            indicator_type="anomaly",
            severity=ThreatLevel.HIGH,
            description="Anomalous behavior",
            confidence=0.8,
            resolved=False,
        )
        self.store.store_indicator(indicator)
        active = self.store.get_active_indicators()
        assert len(active) >= 1

    def test_get_stats(self):
        stats = self.store.get_stats()
        assert "profiles" in stats
        assert "active_indicators" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

