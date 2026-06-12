"""
Tests for Digital Risk Protection Platform.
"""

import asyncio
import pytest

from src.digital_risk_protection import (
    Alert,
    BrandImpersonation,
    CredentialExposure,
    DarkWebIntelligence,
    Domain,
    PhishingAlert,
    RiskLevel,
    ThreatStatus,
    ThreatType,
    DRPStore,
    get_drp_store,
    reset_drp_store,
    BrandProtectionEngine,
    PhishingDetectionEngine,
    DomainIntelligenceEngine,
    CredentialMonitor,
    DarkWebIntelligenceEngine,
    SocialMediaMonitor,
    RiskScoringEngine,
    DigitalRiskProtectionService,
)


class TestModels:
    """Test data models."""

    def test_domain_creation(self):
        """Test domain creation."""
        domain = Domain(
            domain_id="dom-1",
            domain="example.com",
            registrar="GoDaddy",
        )
        assert domain.domain == "example.com"
        assert domain.registrar == "GoDaddy"

    def test_phishing_alert_creation(self):
        """Test phishing alert creation."""
        alert = PhishingAlert(
            alert_id="phish-1",
            target_domain="example.com",
            phishing_url="http://evil.com",
            confidence=0.8,
        )
        assert alert.alert_id == "phish-1"
        assert alert.confidence == 0.8

    def test_credential_exposure_creation(self):
        """Test credential exposure creation."""
        exposure = CredentialExposure(
            exposure_id="cred-1",
            email="test@example.com",
            source="breach_db",
        )
        assert exposure.exposure_id == "cred-1"


class TestStore:
    """Test DRP store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.store = get_drp_store()

    def test_register_domain(self):
        """Test registering a domain."""
        domain = Domain(
            domain_id="dom-1",
            domain="example.com",
        )
        self.store.register_domain(domain)
        
        retrieved = self.store.get_domain("dom-1")
        assert retrieved is not None
        assert retrieved.domain == "example.com"

    def test_add_phishing_alert(self):
        """Test adding phishing alert."""
        alert = PhishingAlert(
            alert_id="phish-1",
            target_domain="example.com",
            phishing_url="http://evil.com",
        )
        self.store.add_phishing_alert(alert)
        
        retrieved = self.store.get_phishing_alert("phish-1")
        assert retrieved is not None


class TestBrandProtection:
    """Test brand protection engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.engine = BrandProtectionEngine()

    def test_register_brand(self):
        """Test registering a brand."""
        result = self.engine.register_brand(
            brand_name="TestCorp",
            protected_domains=["testcorp.com"],
        )
        
        assert "brand_id" in result
        assert result["brand_name"] == "TestCorp"

    def test_detect_impersonation(self):
        """Test detecting impersonation."""
        self.engine.register_brand(
            brand_name="PayPal",
            protected_domains=["paypal.com"],
        )
        
        result = self.engine.detect_impersonation("paypal-secure.com")
        
        assert result is not None
        assert result.brand_name == "PayPal"


class TestPhishingDetection:
    """Test phishing detection engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.engine = PhishingDetectionEngine()

    def test_scan_domain(self):
        """Test scanning a domain."""
        result = self.engine.scan_domain("http://paypa1-secure.xyz/login")
        
        assert "alert_id" in result
        assert "risk_score" in result
        assert result["target_brand"] == "paypal"

    def test_get_phishing_alerts(self):
        """Test getting phishing alerts."""
        self.engine.scan_domain("http://evil.com")
        
        alerts = self.engine.get_phishing_alerts()
        assert len(alerts) >= 1


class TestDomainIntelligence:
    """Test domain intelligence engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.engine = DomainIntelligenceEngine()

    def test_register_domain(self):
        """Test registering a domain."""
        domain = self.engine.register_domain(
            domain="example.com",
            registrar="GoDaddy",
        )
        
        assert domain.domain_id is not None
        assert domain.domain == "example.com"

    def test_analyze_domain(self):
        """Test analyzing a domain."""
        result = self.engine.analyze_domain("paypal-secure-login.xyz")
        
        assert "risk_score" in result
        assert len(result["risk_indicators"]) >= 1


class TestCredentialMonitor:
    """Test credential monitor."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.engine = CredentialMonitor()

    def test_add_exposure(self):
        """Test adding an exposure."""
        exposure = self.engine.add_exposure(
            email="test@example.com",
            source="breach_db",
        )
        
        assert exposure.exposure_id is not None

    def test_get_exposures(self):
        """Test getting exposures."""
        self.engine.add_exposure("test@example.com", "source1")
        
        exposures = self.engine.get_exposures()
        assert len(exposures) >= 1


class TestDarkWebIntelligence:
    """Test dark web intelligence engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.engine = DarkWebIntelligenceEngine()

    def test_add_intelligence(self):
        """Test adding intelligence."""
        intel = self.engine.add_intelligence(
            source="darkweb_forum",
            content_type="credential_leak",
            title="Database Dump",
            description="Credentials leaked",
            confidence=0.8,
        )
        
        assert intel.intel_id is not None

    def test_get_intelligence(self):
        """Test getting intelligence."""
        self.engine.add_intelligence(
            source="source1",
            content_type="forum_post",
            title="Test",
            description="Description",
        )
        
        intel = self.engine.get_intelligence()
        assert len(intel) >= 1


class TestSocialMediaMonitor:
    """Test social media monitor."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.engine = SocialMediaMonitor()

    def test_report_abuse(self):
        """Test reporting abuse."""
        abuse = self.engine.report_abuse(
            platform="twitter",
            account_handle="@fake_account",
            content="This is a scam account!",
            abuse_type="impersonation",
        )
        
        assert abuse.abuse_id is not None

    def test_get_abuse_reports(self):
        """Test getting abuse reports."""
        self.engine.report_abuse(
            platform="facebook",
            account_handle="fake_page",
            content="Scam content",
            abuse_type="scam",
        )
        
        reports = self.engine.get_abuse_reports()
        assert len(reports) >= 1


class TestRiskScoring:
    """Test risk scoring engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.engine = RiskScoringEngine()

    def test_calculate_risk_score(self):
        """Test calculating risk score."""
        score = self.engine.calculate_risk_score("org-1")
        
        assert score.score_id is not None
        assert score.overall_score >= 0

    def test_get_risk_score(self):
        """Test getting risk score."""
        self.engine.calculate_risk_score("org-1")
        
        result = self.engine.get_risk_score("org-1")
        assert result is not None


class TestDRPService:
    """Test main DRP service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_drp_store()
        self.service = DigitalRiskProtectionService()

    def test_scan_domain(self):
        """Test domain scanning."""
        result = asyncio.run(self.service.scan_domain("http://test.com"))
        
        assert "alert_id" in result

    def test_get_phishing_alerts(self):
        """Test getting phishing alerts."""
        asyncio.run(self.service.scan_domain("http://evil.com"))
        
        alerts = asyncio.run(self.service.get_phishing_alerts())
        assert isinstance(alerts, list)

    def test_create_alert(self):
        """Test creating an alert."""
        result = asyncio.run(self.service.create_alert(
            alert_type="phishing",
            title="Test Alert",
            description="Test description",
            severity="high",
        ))
        
        assert "alert_id" in result

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = asyncio.run(self.service.get_dashboard())
        
        assert "total_phishing_alerts" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])