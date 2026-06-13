"""
Tests for Security Exposure Management Platform
"""

import pytest

from src.exposure_management.models import (
    Exposure,
    AssetInventory,
    AttackSurface,
    RemediationTask,
    SecurityPosture,
    ExposureSeverity,
    ExposureStatus,
    ExposureCategory,
    AssetType,
)
from src.exposure_management.store import get_exposure_store, reset_exposure_store
from src.exposure_management.service import ExposureService


class TestExposureModels:
    """Tests for exposure models."""

    def test_create_exposure(self):
        """Test creating an exposure."""
        exposure = Exposure(
            title="SQL Injection Vulnerability",
            description="SQL injection in login form",
            severity=ExposureSeverity.CRITICAL,
            category=ExposureCategory.VULNERABILITY,
            asset_id="server-001",
            asset_type=AssetType.SERVER,
        )
        assert exposure.title == "SQL Injection Vulnerability"
        assert exposure.severity == ExposureSeverity.CRITICAL
        assert exposure.status == ExposureStatus.OPEN

    def test_create_asset_inventory(self):
        """Test creating an asset inventory entry."""
        asset = AssetInventory(
            name="Production Server",
            asset_type=AssetType.SERVER,
            owner="admin@example.com",
            department="Engineering",
        )
        assert asset.name == "Production Server"
        assert asset.criticality == "MEDIUM"

    def test_create_attack_surface(self):
        """Test creating an attack surface."""
        surface = AttackSurface(
            asset_id="server-001",
            entry_points=[{"port": 443, "service": "https"}],
            exposed_services=["web-server"],
            open_ports=[80, 443],
            attack_vector_score=0.5,
        )
        assert len(surface.entry_points) == 1
        assert len(surface.open_ports) == 2

    def test_create_remediation_task(self):
        """Test creating a remediation task."""
        task = RemediationTask(
            exposure_id="exp-001",
            title="Fix SQL Injection",
            description="Apply input sanitization",
            priority=ExposureSeverity.CRITICAL,
        )
        assert task.exposure_id == "exp-001"
        assert task.status == "PENDING"

    def test_create_security_posture(self):
        """Test creating a security posture."""
        posture = SecurityPosture(
            overall_score=0.85,
            exposure_count_by_severity={"CRITICAL": 1, "HIGH": 5},
            total_exposures=10,
            remediated_exposures=4,
        )
        assert posture.overall_score == 0.85
        assert posture.total_exposures == 10


class TestExposureStore:
    """Tests for exposure store."""

    def setup_method(self):
        """Set up test store."""
        reset_exposure_store()
        self.store = get_exposure_store()

    def test_store_exposure(self):
        """Test storing an exposure."""
        exposure = Exposure(
            title="Test Exposure",
            description="Test description",
            severity=ExposureSeverity.HIGH,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        stored = self.store.store_exposure(exposure)
        assert stored.exposure_id == exposure.exposure_id

    def test_get_exposure(self):
        """Test getting an exposure."""
        exposure = Exposure(
            title="Test",
            description="Test",
            severity=ExposureSeverity.MEDIUM,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        self.store.store_exposure(exposure)
        retrieved = self.store.get_exposure(exposure.exposure_id)
        assert retrieved is not None
        assert retrieved.title == "Test"

    def test_get_exposures_by_severity(self):
        """Test getting exposures by severity."""
        for _ in range(3):
            self.store.store_exposure(Exposure(
                title="Test",
                description="Test",
                severity=ExposureSeverity.HIGH,
                category=ExposureCategory.VULNERABILITY,
                asset_id="asset-001",
                asset_type=AssetType.SERVER,
            ))
        results = self.store.get_exposures_by_severity(ExposureSeverity.HIGH)
        assert len(results) >= 3

    def test_get_exposures_by_status(self):
        """Test getting exposures by status."""
        self.store.store_exposure(Exposure(
            title="Test",
            description="Test",
            severity=ExposureSeverity.LOW,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
            status=ExposureStatus.REMEDIATED,
        ))
        results = self.store.get_exposures_by_status(ExposureStatus.REMEDIATED)
        assert len(results) >= 1

    def test_store_asset(self):
        """Test storing an asset."""
        asset = AssetInventory(
            name="Test Asset",
            asset_type=AssetType.SERVER,
            owner="admin",
            department="IT",
        )
        self.store.store_asset(asset)
        retrieved = self.store.get_asset(asset.asset_id)
        assert retrieved is not None
        assert retrieved.name == "Test Asset"

    def test_store_remediation_task(self):
        """Test storing a remediation task."""
        task = RemediationTask(
            exposure_id="exp-001",
            title="Fix it",
            description="Description",
            priority=ExposureSeverity.HIGH,
        )
        self.store.store_remediation_task(task)
        retrieved = self.store.get_remediation_task(task.task_id)
        assert retrieved is not None
        assert retrieved.title == "Fix it"

    def test_get_metrics(self):
        """Test getting metrics."""
        self.store.store_exposure(Exposure(
            title="Test",
            description="Test",
            severity=ExposureSeverity.CRITICAL,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        ))
        metrics = self.store.get_metrics()
        assert "total_exposures" in metrics
        assert metrics["total_exposures"] >= 1


class TestExposureService:
    """Tests for exposure service."""

    def setup_method(self):
        """Set up test service."""
        reset_exposure_store()
        self.service = ExposureService()

    def test_discover_exposure(self):
        """Test discovering an exposure."""
        exposure = self.service.discover_exposure(
            title="Vulnerability Test",
            description="Test vulnerability",
            severity=ExposureSeverity.HIGH,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        assert exposure.exposure_score > 0

    def test_get_exposure(self):
        """Test getting an exposure."""
        discovered = self.service.discover_exposure(
            title="Test",
            description="Test",
            severity=ExposureSeverity.MEDIUM,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        retrieved = self.service.get_exposure(discovered.exposure_id)
        assert retrieved is not None
        assert retrieved.title == "Test"

    def test_update_exposure_status(self):
        """Test updating exposure status."""
        exposure = self.service.discover_exposure(
            title="Test",
            description="Test",
            severity=ExposureSeverity.LOW,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        updated = self.service.update_exposure_status(
            exposure.exposure_id,
            ExposureStatus.REMEDIATED,
        )
        assert updated is not None
        assert updated.status == ExposureStatus.REMEDIATED

    def test_create_remediation_task(self):
        """Test creating a remediation task."""
        exposure = self.service.discover_exposure(
            title="Test",
            description="Test",
            severity=ExposureSeverity.HIGH,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        task = self.service.create_remediation_task(
            exposure_id=exposure.exposure_id,
            title="Fix it",
            description="Fix the issue",
            assigned_to="admin",
        )
        assert task.exposure_id == exposure.exposure_id
        assert task.status == "PENDING"

    def test_register_asset(self):
        """Test registering an asset."""
        asset = self.service.register_asset(
            name="Test Server",
            asset_type=AssetType.SERVER,
            owner="admin",
            department="IT",
        )
        assert asset.name == "Test Server"
        assert asset.exposure_count == 0

    def test_analyze_attack_surface(self):
        """Test analyzing attack surface."""
        self.service.register_asset(
            name="Test Server",
            asset_type=AssetType.SERVER,
            owner="admin",
            department="IT",
        )
        self.service.discover_exposure(
            title="Open Port",
            description="Port exposed",
            severity=ExposureSeverity.HIGH,
            category=ExposureCategory.NETWORK_EXPOSURE,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        surface = self.service.analyze_attack_surface("asset-001")
        assert surface.asset_id == "asset-001"
        assert surface.attack_vector_score > 0

    def test_assess_security_posture(self):
        """Test assessing security posture."""
        self.service.discover_exposure(
            title="Test",
            description="Test",
            severity=ExposureSeverity.HIGH,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        posture = self.service.assess_security_posture()
        assert posture.overall_score > 0
        assert len(posture.recommendations) > 0

    def test_get_metrics(self):
        """Test getting metrics."""
        self.service.discover_exposure(
            title="Test",
            description="Test",
            severity=ExposureSeverity.CRITICAL,
            category=ExposureCategory.VULNERABILITY,
            asset_id="asset-001",
            asset_type=AssetType.SERVER,
        )
        metrics = self.service.get_metrics()
        assert metrics.total_exposures >= 1
        assert metrics.critical_exposures >= 1


class TestExposureIntegration:
    """Integration tests for exposure management."""

    def setup_method(self):
        """Set up test environment."""
        reset_exposure_store()
        self.service = ExposureService()

    def test_full_exposure_lifecycle(self):
        """Test complete exposure lifecycle."""
        asset = self.service.register_asset(
            name="Production Server",
            asset_type=AssetType.SERVER,
            owner="admin",
            department="Engineering",
        )

        exposure = self.service.discover_exposure(
            title="Critical Vulnerability",
            description="Remote code execution vulnerability",
            severity=ExposureSeverity.CRITICAL,
            category=ExposureCategory.VULNERABILITY,
            asset_id=asset.asset_id,
            asset_type=AssetType.SERVER,
        )

        task = self.service.create_remediation_task(
            exposure_id=exposure.exposure_id,
            title="Apply security patch",
            description="Apply CVE-2024-XXXX patch",
            assigned_to="security-team",
            priority=ExposureSeverity.CRITICAL,
        )
        assert task.task_id

        posture = self.service.assess_security_posture()
        assert posture.total_exposures >= 1

        self.service.update_exposure_status(
            exposure.exposure_id,
            ExposureStatus.REMEDIATED,
        )

        updated = self.service.get_exposure(exposure.exposure_id)
        assert updated.status == ExposureStatus.REMEDIATED

        tasks = self.service.get_remediation_tasks(exposure.exposure_id)
        assert len(tasks) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
