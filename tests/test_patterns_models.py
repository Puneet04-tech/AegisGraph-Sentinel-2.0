"""
Unit tests for fraud pattern models in src/patterns/models.py
"""

import pytest
from datetime import datetime

from src.patterns.models import (
    Pattern,
    PatternType,
    Detection,
    DetectionStatus,
)


class TestPatternType:
    """Tests for PatternType enum."""

    def test_all_expected_values(self):
        """PatternType has all expected enum values."""
        values = {e.value for e in PatternType}
        assert "STRUCTURAL" in values
        assert "BEHAVIORAL" in values
        assert "TRANSACTIONAL" in values
        assert "NETWORK" in values


class TestDetectionStatus:
    """Tests for DetectionStatus enum."""

    def test_all_expected_values(self):
        """DetectionStatus has all expected values."""
        values = {e.value for e in DetectionStatus}
        assert "DETECTED" in values
        assert "CONFIRMED" in values
        assert "FALSE_POSITIVE" in values
        assert "INVESTIGATING" in values


class TestPattern:
    """Tests for Pattern dataclass."""

    def test_create_pattern(self):
        """Pattern can be created with required fields."""
        pattern = Pattern(
            pattern_id="pattern-001",
            name="Mule Account Pattern",
            pattern_type=PatternType.TRANSACTIONAL,
            description="Detects known mule account behavior",
            rules=[{"field": "amount", "threshold": 5000}],
            severity="HIGH",
        )
        assert pattern.pattern_id == "pattern-001"
        assert pattern.pattern_type == PatternType.TRANSACTIONAL
        assert pattern.enabled is True
        assert pattern.rules == [{"field": "amount", "threshold": 5000}]

    def test_to_dict(self):
        """Pattern.to_dict() returns correct serialized form."""
        pattern = Pattern(
            pattern_id="pattern-002",
            name="Rapid Transactions",
            pattern_type=PatternType.TRANSACTIONAL,
            description="Rapid transaction burst",
            rules=[],
            severity="MEDIUM",
            enabled=False,
        )
        data = pattern.to_dict()
        assert isinstance(data, dict)
        assert data["pattern_id"] == "pattern-002"
        assert data["pattern_type"] == "TRANSACTIONAL"
        assert data["severity"] == "MEDIUM"
        assert data["enabled"] is False

    def test_enabled_defaults_to_true(self):
        """Pattern.enabled defaults to True when not specified."""
        pattern = Pattern(
            pattern_id="pattern-003",
            name="Test",
            pattern_type=PatternType.BEHAVIORAL,
            description="Test pattern",
            rules=[],
            severity="LOW",
        )
        assert pattern.enabled is True


class TestDetection:
    """Tests for Detection dataclass."""

    def test_create_detection(self):
        """Detection can be created with required fields."""
        detection = Detection(
            detection_id="det-001",
            pattern_id="pattern-001",
            entity_id="entity-42",
            status=DetectionStatus.DETECTED,
            confidence=0.85,
        )
        assert detection.detection_id == "det-001"
        assert detection.pattern_id == "pattern-001"
        assert detection.entity_id == "entity-42"
        assert detection.status == DetectionStatus.DETECTED
        assert detection.confidence == 0.85
        assert detection.details == {}

    def test_to_dict(self):
        """Detection.to_dict() serializes correctly."""
        detection = Detection(
            detection_id="det-002",
            pattern_id="pattern-002",
            entity_id="entity-99",
            status=DetectionStatus.CONFIRMED,
            confidence=0.92,
            details={"reason": "manual review"},
        )
        data = detection.to_dict()
        assert isinstance(data, dict)
        assert data["detection_id"] == "det-002"
        assert data["pattern_id"] == "pattern-002"
        assert data["status"] == "CONFIRMED"
        assert data["confidence"] == 0.92
        assert data["details"] == {"reason": "manual review"}

    def test_detected_at_defaults_to_utcnow(self):
        """detected_at defaults to current UTC time when not specified."""
        detection = Detection(
            detection_id="det-003",
            pattern_id="pattern-003",
            entity_id="entity-3",
            status=DetectionStatus.INVESTIGATING,
            confidence=0.6,
        )
        assert detection.detected_at is not None
        assert isinstance(detection.detected_at, datetime)

    def test_to_dict_includes_detected_at_isoformat(self):
        """to_dict() includes detected_at as an ISO string."""
        detection = Detection(
            detection_id="det-004",
            pattern_id="pattern-004",
            entity_id="entity-4",
            status=DetectionStatus.FALSE_POSITIVE,
            confidence=0.1,
        )
        data = detection.to_dict()
        assert "detected_at" in data
        assert isinstance(data["detected_at"], str)
