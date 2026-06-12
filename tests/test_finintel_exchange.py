"""
Tests for Financial Crime Intelligence Exchange.
"""

import pytest

from src.finintel_exchange import (
    CaseStatus,
    CrossBorderInvestigation,
    FraudAlert,
    Institution,
    InstitutionType,
    ShareLevel,
    FinIntelStore,
    get_finintel_store,
    reset_finintel_store,
    FinIntelEngine,
)


class TestModels:
    """Test data models."""

    def test_institution_creation(self):
        """Test institution creation."""
        inst = Institution(
            institution_id="inst-1",
            name="Test Bank",
            institution_type=InstitutionType.BANK,
            country="US",
        )
        assert inst.institution_id == "inst-1"
        assert inst.institution_type == InstitutionType.BANK

    def test_fraud_alert_creation(self):
        """Test fraud alert creation."""
        alert = FraudAlert(
            alert_id="alert-1",
            source_institution="inst-1",
            alert_type="account_takeover",
            account_identifier="ACC123",
            amount=5000.00,
            description="Suspicious transaction",
        )
        assert alert.alert_id == "alert-1"


class TestStore:
    """Test FinIntel store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_finintel_store()
        self.store = get_finintel_store()

    def test_add_institution(self):
        """Test adding an institution."""
        inst = Institution(
            institution_id="inst-1",
            name="Test Bank",
            institution_type=InstitutionType.BANK,
            country="US",
        )
        self.store.add_institution(inst)
        
        retrieved = self.store.get_institution("inst-1")
        assert retrieved is not None


class TestFinIntelEngine:
    """Test FinIntel engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_finintel_store()
        self.engine = FinIntelEngine()

    def test_register_institution(self):
        """Test registering an institution."""
        inst = self.engine.register_institution(
            name="Global Bank",
            institution_type="bank",
            country="UK",
        )
        
        assert inst.institution_id is not None
        assert inst.name == "Global Bank"

    def test_share_fraud_alert(self):
        """Test sharing a fraud alert."""
        inst = self.engine.register_institution(
            name="Test Bank",
            institution_type="bank",
            country="US",
        )
        
        alert = self.engine.share_fraud_alert(
            source_institution=inst.institution_id,
            alert_type="phishing",
            account_identifier="ACC123",
            amount=1000.00,
            description="Phishing attempt",
        )
        
        assert alert.alert_id is not None

    def test_identify_pattern(self):
        """Test identifying a fraud pattern."""
        pattern = self.engine.identify_pattern(
            pattern_type=" mule_account",
            description="Series of small transactions",
            indicators=["round_amounts", "new_account"],
        )
        
        assert pattern.pattern_id is not None

    def test_create_shared_case(self):
        """Test creating a shared case."""
        inst = self.engine.register_institution(
            name="Test Bank",
            institution_type="bank",
            country="US",
        )
        
        case = self.engine.create_shared_case(
            source_institution=inst.institution_id,
            title="Cross-Border Fraud",
            description="Investigating fraud ring",
            case_type="fraud",
        )
        
        assert case.case_id is not None

    def test_share_aml_intelligence(self):
        """Test sharing AML intelligence."""
        inst = self.engine.register_institution(
            name="Test Bank",
            institution_type="bank",
            country="US",
        )
        
        intel = self.engine.share_aml_intelligence(
            source_institution=inst.institution_id,
            subject_type="individual",
            subject_identifier="PERSON123",
            risk_indicators=["structuring", "high_risk_country"],
        )
        
        assert intel.intel_id is not None

    def test_initiate_investigation(self):
        """Test initiating cross-border investigation."""
        inst = self.engine.register_institution(
            name="Test Bank",
            institution_type="bank",
            country="US",
        )
        
        investigation = self.engine.initiate_cross_border_investigation(
            title="Multi-National Fraud Ring",
            primary_institution=inst.institution_id,
            subjects=["account1", "account2"],
        )
        
        assert investigation.investigation_id is not None

    def test_search_fraud_alerts(self):
        """Test searching fraud alerts."""
        inst = self.engine.register_institution(
            name="Test Bank",
            institution_type="bank",
            country="US",
        )
        
        self.engine.share_fraud_alert(
            source_institution=inst.institution_id,
            alert_type="phishing",
            account_identifier="ACC123",
            amount=1000.00,
            description="Phishing attack detected",
        )
        
        results = self.engine.search_fraud_alerts("phishing")
        assert len(results) >= 1

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = self.engine.get_dashboard()
        
        assert "total_institutions" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])