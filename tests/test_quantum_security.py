"""
Tests for Quantum-Safe Security Platform.
"""

import asyncio
import pytest
from datetime import datetime, timezone

from src.quantum_security import (
    CryptoAlgorithm,
    CryptoAsset,
    CryptoType,
    Certificate,
    QuantumRiskAssessment,
    RiskLevel,
    QuantumSecurityStore,
    get_quantum_store,
    reset_quantum_store,
    CryptoInventoryEngine,
    RiskAnalyzer,
    KeyLifecycleManager,
    CertificateIntelligenceEngine,
    GovernanceEngine,
    ComplianceEngine,
    QuantumSecurityService,
)


class TestModels:
    """Test data models."""

    def test_crypto_asset_creation(self):
        """Test crypto asset creation."""
        asset = CryptoAsset(
            asset_id="crypto-1",
            name="Master Key",
            algorithm=CryptoAlgorithm.RSA_2048,
            crypto_type=CryptoType.ASYMMETRIC_KEY,
            key_size=2048,
            usage="encryption",
            system="production",
            location="hsm-1",
        )
        assert asset.asset_id == "crypto-1"
        assert asset.algorithm == CryptoAlgorithm.RSA_2048

    def test_certificate_creation(self):
        """Test certificate creation."""
        cert = Certificate(
            cert_id="cert-1",
            subject="example.com",
            issuer="DigiCert",
            serial_number="12345",
            algorithm=CryptoAlgorithm.RSA_2048,
            key_size=2048,
            public_key_fingerprint="abc123",
            valid_from=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc),
        )
        assert cert.cert_id == "cert-1"


class TestStore:
    """Test quantum security store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_quantum_store()
        self.store = get_quantum_store()

    def test_register_asset(self):
        """Test registering an asset."""
        asset = CryptoAsset(
            asset_id="crypto-1",
            name="Test Key",
            algorithm=CryptoAlgorithm.RSA_2048,
            crypto_type=CryptoType.ASYMMETRIC_KEY,
            key_size=2048,
            usage="encryption",
            system="test",
            location="test",
        )
        self.store.register_asset(asset)
        
        retrieved = self.store.get_asset("crypto-1")
        assert retrieved is not None

    def test_get_vulnerable_assets(self):
        """Test getting vulnerable assets."""
        asset = CryptoAsset(
            asset_id="crypto-1",
            name="Test Key",
            algorithm=CryptoAlgorithm.RSA_2048,
            crypto_type=CryptoType.ASYMMETRIC_KEY,
            key_size=2048,
            usage="encryption",
            system="test",
            location="test",
            quantum_resistant=False,
        )
        self.store.register_asset(asset)
        
        vulnerable = self.store.get_vulnerable_assets()
        assert len(vulnerable) >= 1


class TestCryptoInventory:
    """Test crypto inventory engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_quantum_store()
        self.engine = CryptoInventoryEngine()

    def test_register_asset(self):
        """Test registering an asset."""
        asset = self.engine.register_asset(
            name="Test Key",
            algorithm="RSA-2048",
            crypto_type="asymmetric_key",
            key_size=2048,
            usage="encryption",
            system="test",
            location="test",
        )
        
        assert asset.asset_id is not None

    def test_get_inventory_summary(self):
        """Test getting inventory summary."""
        summary = self.engine.get_inventory_summary()
        assert "total_assets" in summary


class TestRiskAnalyzer:
    """Test risk analyzer."""

    def setup_method(self):
        """Reset store before each test."""
        reset_quantum_store()
        self.inventory = CryptoInventoryEngine()
        self.analyzer = RiskAnalyzer()

    def test_assess_vulnerable_asset(self):
        """Test assessing vulnerable asset."""
        asset = self.inventory.register_asset(
            name="RSA Key",
            algorithm="RSA-2048",
            crypto_type="asymmetric_key",
            key_size=2048,
            usage="encryption",
            system="test",
            location="test",
        )
        
        assessment = self.analyzer.assess_asset(asset.asset_id)
        
        assert assessment.quantum_vulnerable is True
        assert assessment.risk_score > 0

    def test_assess_resistant_asset(self):
        """Test assessing quantum-resistant asset."""
        asset = self.inventory.register_asset(
            name="PQ Key",
            algorithm="AES-256",
            crypto_type="symmetric_key",
            key_size=256,
            usage="encryption",
            system="test",
            location="test",
            quantum_resistant=True,
        )
        
        assessment = self.analyzer.assess_asset(asset.asset_id)
        
        assert assessment.quantum_vulnerable is False


class TestKeyLifecycleManager:
    """Test key lifecycle manager."""

    def setup_method(self):
        """Reset store before each test."""
        reset_quantum_store()
        self.manager = KeyLifecycleManager()

    def test_create_key(self):
        """Test creating a key record."""
        result = self.manager.create_key(
            key_id="key-1",
            algorithm="RSA-2048",
            created_by="admin",
        )
        
        assert result["key_id"] == "key-1"

    def test_rotate_key(self):
        """Test rotating a key."""
        self.manager.create_key("key-1", "RSA-2048", "admin")
        
        result = self.manager.rotate_key("key-1", "admin", "scheduled")
        
        assert result["event"] == "rotated"

    def test_get_key_history(self):
        """Test getting key history."""
        self.manager.create_key("key-1", "RSA-2048", "admin")
        
        history = self.manager.get_key_history("key-1")
        assert len(history) >= 1


class TestCertificateEngine:
    """Test certificate intelligence engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_quantum_store()
        self.engine = CertificateIntelligenceEngine()

    def test_register_certificate(self):
        """Test registering a certificate."""
        cert = self.engine.register_certificate(
            subject="example.com",
            issuer="DigiCert",
            serial_number="12345",
            algorithm="RSA-2048",
            key_size=2048,
            public_key_fingerprint="abc123",
            valid_from=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc),
        )
        
        assert cert.cert_id is not None

    def test_get_certificate_summary(self):
        """Test getting certificate summary."""
        summary = self.engine.get_certificate_summary()
        assert "total_certificates" in summary


class TestGovernanceEngine:
    """Test governance engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_quantum_store()
        self.engine = GovernanceEngine()

    def test_create_policy(self):
        """Test creating a policy."""
        policy = self.engine.create_policy(
            name="Encryption Policy",
            description="Minimum encryption standards",
            rules=[{"type": "key_size_requirement", "minimum_key_size": 2048}],
        )
        
        assert policy.policy_id is not None

    def test_validate_compliance(self):
        """Test compliance validation."""
        result = self.engine.validate_compliance("RSA-2048", 2048)
        assert "compliant" in result


class TestComplianceEngine:
    """Test compliance engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_quantum_store()
        self.engine = ComplianceEngine()

    def test_generate_report(self):
        """Test generating a report."""
        report = self.engine.generate_report("NIST-PQ")
        
        assert report.report_id is not None
        assert "total_assets" in dir(report)


class TestQuantumSecurityService:
    """Test main service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_quantum_store()
        self.service = QuantumSecurityService()

    def test_register_asset(self):
        """Test registering an asset."""
        result = asyncio.run(self.service.register_asset(
            name="Test Key",
            algorithm="RSA-2048",
            crypto_type="asymmetric_key",
            key_size=2048,
            usage="encryption",
            system="test",
            location="test",
        ))
        
        assert "asset_id" in result

    def test_get_compliance(self):
        """Test getting compliance report."""
        result = asyncio.run(self.service.get_compliance("NIST-PQ"))
        assert "framework" in result

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = asyncio.run(self.service.get_dashboard())
        assert "total_assets" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])