"""
Tests for AI Governance Module
"""
import pytest
from datetime import datetime, timezone

from src.ai_governance import (
    ModelRegistry,
    get_model_registry,
    AIGovernanceEngine,
    get_governance_engine,
    DriftDetectionEngine,
    BiasDetectionEngine,
    ExplainabilityEngine,
    Model,
    ModelStatus,
    ModelRisk,
    ModelDrift,
    DriftType,
    BiasReport,
    BiasMetric,
    ModelExplanation,
)


class TestModelRegistry:
    """Tests for ModelRegistry."""
    
    def setup_method(self):
        self.registry = ModelRegistry()
    
    def test_register_model(self):
        """Test model registration."""
        model_id = self.registry.register_model(
            name="FraudDetector",
            version="1.0.0",
            model_type="XGBoost",
            framework="scikit-learn",
            owner="data-science",
        )
        
        assert model_id is not None
        assert self.registry.get_model(model_id) is not None
    
    def test_get_model(self):
        """Test getting a model."""
        model_id = self.registry.register_model(
            name="TestModel",
            version="1.0.0",
            model_type="NeuralNet",
        )
        
        model = self.registry.get_model(model_id)
        assert model is not None
        assert model.name == "TestModel"
    
    def test_update_model(self):
        """Test updating a model."""
        model_id = self.registry.register_model(
            name="TestModel",
            version="1.0.0",
            model_type="NeuralNet",
        )
        
        success = self.registry.update_model(
            model_id=model_id,
            status=ModelStatus.PRODUCTION,
            metrics={"accuracy": 0.95},
        )
        
        assert success is True
        model = self.registry.get_model(model_id)
        assert model.status == ModelStatus.PRODUCTION
        assert model.metrics["accuracy"] == 0.95
    
    def test_deprecate_model(self):
        """Test deprecating a model."""
        model_id = self.registry.register_model(
            name="OldModel",
            version="1.0.0",
            model_type="Linear",
        )
        
        success = self.registry.deprecate_model(model_id)
        assert success is True
        
        model = self.registry.get_model(model_id)
        assert model.status == ModelStatus.DEPRECATED
    
    def test_list_models(self):
        """Test listing models."""
        self.registry.register_model("Model1", "1.0", "type1")
        self.registry.register_model("Model2", "1.0", "type2")
        
        models = self.registry.list_models()
        assert len(models) >= 2
    
    def test_get_registry_stats(self):
        """Test getting registry stats."""
        self.registry.register_model("StatModel", "1.0", "type1")
        
        stats = self.registry.get_registry_stats()
        assert "total_models" in stats
        assert "by_status" in stats


class TestDriftDetectionEngine:
    """Tests for DriftDetectionEngine."""
    
    def setup_method(self):
        self.engine = DriftDetectionEngine()
        self.registry = get_model_registry()
        self.model_id = self.registry.register_model(
            name="DriftTest",
            version="1.0.0",
            model_type="Test",
        )
    
    def test_detect_drift(self):
        """Test drift detection."""
        current = [{"feature1": 1, "feature2": 2}]
        baseline = [{"feature1": 1, "feature2": 2}]
        
        drift = self.engine.detect_drift(
            model_id=self.model_id,
            current_data=current,
            baseline_data=baseline,
        )
        
        assert drift is not None
        assert drift.model_id == self.model_id
        assert drift.drift_type == DriftType.DATA_DRIFT
    
    def test_get_drift_history(self):
        """Test getting drift history."""
        current = [{"a": 1}]
        baseline = [{"b": 2}]
        
        self.engine.detect_drift(self.model_id, current, baseline)
        
        history = self.engine.get_drift_history(self.model_id)
        assert len(history) >= 1


class TestBiasDetectionEngine:
    """Tests for BiasDetectionEngine."""
    
    def setup_method(self):
        self.engine = BiasDetectionEngine()
        self.registry = get_model_registry()
        self.model_id = self.registry.register_model(
            name="BiasTest",
            version="1.0.0",
            model_type="Classifier",
        )
    
    def test_detect_bias(self):
        """Test bias detection."""
        predictions = [
            {"prediction": 1, "group": "A"},
            {"prediction": 0, "group": "B"},
        ]
        
        reports = self.engine.detect_bias(
            model_id=self.model_id,
            predictions=predictions,
            protected_attributes=["group"],
        )
        
        assert len(reports) == len(BiasMetric)
        assert all(isinstance(r, BiasReport) for r in reports)


class TestExplainabilityEngine:
    """Tests for ExplainabilityEngine."""
    
    def setup_method(self):
        self.engine = ExplainabilityEngine()
        self.registry = get_model_registry()
        self.model_id = self.registry.register_model(
            name="ExplainTest",
            version="1.0.0",
            model_type="NeuralNet",
        )
    
    def test_explain_prediction(self):
        """Test prediction explanation."""
        explanation = self.engine.explain_prediction(
            model_id=self.model_id,
            prediction_id="pred-123",
            input_features={"feature1": 0.5, "feature2": 0.3},
        )
        
        assert explanation is not None
        assert explanation.model_id == self.model_id
        assert "feature_importance" in explanation.to_dict()


class TestAIGovernanceEngine:
    """Tests for AIGovernanceEngine."""
    
    def setup_method(self):
        self.engine = AIGovernanceEngine()
        self.registry = get_model_registry()
        self.model_id = self.registry.register_model(
            name="GovernanceTest",
            version="1.0.0",
            model_type="Model",
        )
    
    def test_log_action(self):
        """Test audit logging."""
        record = self.engine.log_action(
            model_id=self.model_id,
            action="MODEL_DEPLOYED",
            user="admin",
            details={"version": "1.0.0"},
        )
        
        assert record is not None
        assert record.action == "MODEL_DEPLOYED"
    
    def test_get_audit_log(self):
        """Test getting audit log."""
        self.engine.log_action(
            model_id=self.model_id,
            action="TEST",
            user="tester",
        )
        
        entries = self.engine.get_audit_log(model_id=self.model_id)
        assert len(entries) >= 1
    
    def test_get_compliance_status(self):
        """Test compliance status."""
        status = self.engine.get_compliance_status(self.model_id)
        
        assert "model_id" in status
        assert "compliance_score" in status
        assert "requires_review" in status


class TestModels:
    """Tests for model classes."""
    
    def test_model_to_dict(self):
        """Test Model serialization."""
        model = Model(
            model_id="test-1",
            name="Test Model",
            version="1.0.0",
            model_type="Test",
        )
        
        data = model.to_dict()
        assert data["model_id"] == "test-1"
        assert data["name"] == "Test Model"
    
    def test_model_status_values(self):
        """Test ModelStatus enum."""
        assert ModelStatus.DEVELOPMENT.value == "DEVELOPMENT"
        assert ModelStatus.PRODUCTION.value == "PRODUCTION"
        assert len(ModelStatus) > 0
    
    def test_model_risk_values(self):
        """Test ModelRisk enum."""
        assert ModelRisk.CRITICAL.value == "CRITICAL"
        assert ModelRisk.LOW.value == "LOW"
        assert len(ModelRisk) > 0
    
    def test_drift_type_values(self):
        """Test DriftType enum."""
        assert DriftType.CONCEPT_DRIFT.value == "CONCEPT_DRIFT"
        assert DriftType.DATA_DRIFT.value == "DATA_DRIFT"
    
    def test_bias_metric_values(self):
        """Test BiasMetric enum."""
        assert BiasMetric.DEMOGRAPHIC_PARITY.value == "DEMOGRAPHIC_PARITY"
        assert len(BiasMetric) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])