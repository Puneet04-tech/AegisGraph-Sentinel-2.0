"""
Tests for Explainable AI & Compliance Engine.

Comprehensive tests for:
    - SHAP Explainer
    - LIME Explainer
    - Decision Tracer
    - Compliance Reporter
    - Model Auditor
"""

import pytest
from datetime import datetime, timezone

from src.explainable_ai import (
    ExplanationType,
    ComplianceFramework,
    BiasMetric,
    ModelAuditStatus,
    ExplainableAIStore,
    SHAPExplainer,
    LIMEExplainer,
    DecisionTracer,
    ComplianceReporter,
    ModelAuditor,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh XAI store for testing."""
    return ExplainableAIStore(max_items=1000)


@pytest.fixture
def shap_explainer(store):
    """Create a SHAP explainer."""
    return SHAPExplainer(store=store)


@pytest.fixture
def lime_explainer(store):
    """Create a LIME explainer."""
    return LIMEExplainer(store=store)


@pytest.fixture
def decision_tracer(store):
    """Create a decision tracer."""
    return DecisionTracer(store=store)


@pytest.fixture
def compliance_reporter(store):
    """Create a compliance reporter."""
    return ComplianceReporter(store=store)


@pytest.fixture
def model_auditor(store):
    """Create a model auditor."""
    return ModelAuditor(store=store)


# =============================================================================
# Store Tests
# =============================================================================

class TestXAIStore:
    """Tests for ExplainableAIStore."""
    
    def test_store_explanation(self, store):
        """Test storing an explanation."""
        from src.explainable_ai import Explanation, FeatureImportance
        
        explanation = Explanation(
            decision_id="test_decision",
            explanation_type=ExplanationType.SHAP,
            model_id="model_1",
            model_version="v1.0",
            features=[FeatureImportance(feature="feature1", importance=0.5)],
            summary="Test explanation",
        )
        
        stored = store.store_explanation(explanation)
        assert stored.explanation_id is not None
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "explanations_stored" in stats
        assert "traces_stored" in stats


# =============================================================================
# SHAP Explainer Tests
# =============================================================================

class TestSHAPExplainer:
    """Tests for SHAPExplainer."""
    
    def test_explain(self, shap_explainer):
        """Test generating SHAP explanation."""
        explanation = shap_explainer.explain(
            decision_id="decision_1",
            model_id="model_1",
            model_version="v1.0",
            input_features={"feature1": 0.5, "feature2": 0.3, "feature3": 0.2},
            prediction_value=0.8,
        )
        
        assert explanation.explanation_id is not None
        assert explanation.explanation_type == ExplanationType.SHAP
        assert explanation.confidence > 0
    
    def test_get_global_importance(self, shap_explainer):
        """Test getting global feature importance."""
        # First create some explanations
        for i in range(5):
            shap_explainer.explain(
                decision_id=f"decision_{i}",
                model_id="global_test_model",
                model_version="v1.0",
                input_features={"f1": 0.5, "f2": 0.3, "f3": 0.2},
                prediction_value=0.7,
            )
        
        importance = shap_explainer.get_global_importance("global_test_model", num_samples=10)
        
        assert len(importance) > 0
    
    def test_explain_batch(self, shap_explainer):
        """Test batch explanation."""
        decisions = [
            {
                "decision_id": f"batch_{i}",
                "model_id": "batch_model",
                "model_version": "v1.0",
                "features": {"f1": 0.5, "f2": 0.3},
                "prediction": 0.8,
            }
            for i in range(3)
        ]
        
        explanations = shap_explainer.explain_batch(decisions)
        
        assert len(explanations) == 3


# =============================================================================
# LIME Explainer Tests
# =============================================================================

class TestLIMEExplainer:
    """Tests for LIMEExplainer."""
    
    def test_explain(self, lime_explainer):
        """Test generating LIME explanation."""
        explanation = lime_explainer.explain(
            decision_id="lime_decision_1",
            model_id="model_1",
            model_version="v1.0",
            input_features={"feature1": 0.5, "feature2": 0.3},
            prediction_value=0.6,
        )
        
        assert explanation.explanation_id is not None
        assert explanation.explanation_type == ExplanationType.LIME
        assert explanation.summary is not None
    
    def test_get_local_explanation(self, lime_explainer):
        """Test getting local explanation details."""
        explanation = lime_explainer.explain(
            decision_id="local_test",
            model_id="model_1",
            model_version="v1.0",
            input_features={"f1": 0.5, "f2": 0.3},
            prediction_value=0.7,
        )
        
        local = lime_explainer.get_local_explanation("local_test")
        
        assert "feature_weights" in local


# =============================================================================
# Decision Tracer Tests
# =============================================================================

class TestDecisionTracer:
    """Tests for DecisionTracer."""
    
    def test_trace_decision(self, decision_tracer):
        """Test tracing a decision."""
        trace = decision_tracer.trace_decision(
            decision_id="trace_1",
            model_id="model_1",
            model_name="Fraud Detection Model",
            model_version="v1.0",
            input_features={"feature1": 0.5, "feature2": 0.3},
            output_decision="FRAUD",
            output_score=0.85,
            user_id="user_1",
        )
        
        assert trace.trace_id is not None
        assert trace.decision_id == "trace_1"
    
    def test_get_trace(self, decision_tracer):
        """Test getting a trace."""
        trace = decision_tracer.trace_decision(
            decision_id="get_trace_test",
            model_id="model_1",
            model_name="Test Model",
            model_version="v1.0",
            input_features={"f1": 0.5},
            output_decision="NO_FRAUD",
            output_score=0.2,
        )
        
        retrieved = decision_tracer.get_decision_trace("get_trace_test")
        assert retrieved is not None
    
    def test_get_trace_summary(self, decision_tracer):
        """Test getting trace summary."""
        decision_tracer.trace_decision(
            decision_id="summary_test",
            model_id="model_1",
            model_name="Test Model",
            model_version="v1.0",
            input_features={"f1": 0.5, "f2": 0.3},
            output_decision="FRAUD",
            output_score=0.9,
        )
        
        summary = decision_tracer.get_trace_summary("summary_test")
        
        assert "model" in summary
        assert "decision" in summary


# =============================================================================
# Compliance Reporter Tests
# =============================================================================

class TestComplianceReporter:
    """Tests for ComplianceReporter."""
    
    def test_generate_report(self, compliance_reporter):
        """Test generating compliance report."""
        now = datetime.now(timezone.utc)
        report = compliance_reporter.generate_compliance_report(
            report_type="test_report",
            framework=ComplianceFramework.GDPR,
            period_start=now,
            period_end=now,
        )
        
        assert report.report_id is not None
        assert report.framework == ComplianceFramework.GDPR
    
    def test_analyze_bias(self, compliance_reporter):
        """Test bias analysis."""
        analysis = compliance_reporter.analyze_bias(
            model_id="model_1",
            protected_attribute="age",
            metric=BiasMetric.DISPARATE_IMPACT,
        )
        
        assert analysis.analysis_id is not None
        assert analysis.model_id == "model_1"
    
    def test_generate_adverse_action_notice(self, compliance_reporter):
        """Test adverse action notice."""
        notice = compliance_reporter.generate_adverse_action_notice(
            decision_id="adverse_decision",
            reason_codes=["HIGH_RISK", "VELOCITY"],
            recipient="customer@example.com",
        )
        
        assert notice.notice_id is not None
        assert len(notice.reason_codes) == 2


# =============================================================================
# Model Auditor Tests
# =============================================================================

class TestModelAuditor:
    """Tests for ModelAuditor."""
    
    def test_create_audit(self, model_auditor):
        """Test creating an audit."""
        audit = model_auditor.create_audit(
            model_id="model_1",
            model_name="Test Model",
            model_version="v1.0",
        )
        
        assert audit.audit_id is not None
        assert audit.status == ModelAuditStatus.PENDING
    
    def test_approve_audit(self, model_auditor):
        """Test approving an audit."""
        audit = model_auditor.create_audit(
            model_id="model_1",
            model_name="Test Model",
            model_version="v1.0",
        )
        
        approved = model_auditor.approve_audit(audit.audit_id, "admin")
        
        assert approved.status == ModelAuditStatus.APPROVED
        assert approved.approved_by == "admin"
    
    def test_detect_drift(self, model_auditor):
        """Test drift detection."""
        drift = model_auditor.detect_drift(
            model_id="model_1",
            reference_data=[{"f1": 0.5}] * 100,
            current_data=[{"f1": 0.6}] * 100,
        )
        
        assert "drift_detected" in drift
        assert "feature_drift_score" in drift


# =============================================================================
# Integration Tests
# =============================================================================

class TestXAIIntegration:
    """Integration tests for XAI workflow."""
    
    def test_full_xai_workflow(
        self,
        shap_explainer,
        lime_explainer,
        decision_tracer,
        compliance_reporter,
        model_auditor,
    ):
        """Test full XAI workflow."""
        # 1. Trace decision
        trace = decision_tracer.trace_decision(
            decision_id="integration_test",
            model_id="integration_model",
            model_name="Integration Test Model",
            model_version="v1.0",
            input_features={"f1": 0.5, "f2": 0.3, "f3": 0.2},
            output_decision="FRAUD",
            output_score=0.85,
        )
        
        # 2. Generate SHAP explanation
        shap_exp = shap_explainer.explain(
            decision_id="integration_test",
            model_id="integration_model",
            model_version="v1.0",
            input_features={"f1": 0.5, "f2": 0.3, "f3": 0.2},
            prediction_value=0.85,
        )
        
        # 3. Generate LIME explanation
        lime_exp = lime_explainer.explain(
            decision_id="integration_test",
            model_id="integration_model",
            model_version="v1.0",
            input_features={"f1": 0.5, "f2": 0.3, "f3": 0.2},
            prediction_value=0.85,
        )
        
        # 4. Generate compliance report
        now = datetime.now(timezone.utc)
        report = compliance_reporter.generate_compliance_report(
            report_type="integration_test",
            framework=ComplianceFramework.GDPR,
            period_start=now,
            period_end=now,
        )
        
        # 5. Audit model
        audit = model_auditor.create_audit(
            model_id="integration_model",
            model_name="Integration Test Model",
            model_version="v1.0",
        )
        
        # Verify
        assert trace.trace_id is not None
        assert shap_exp.explanation_id is not None
        assert lime_exp.explanation_id is not None
        assert report.report_id is not None
        assert audit.audit_id is not None