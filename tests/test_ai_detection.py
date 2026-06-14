"""
Tests for AI Threat Detection Studio
"""

import pytest

from src.ai_detection.models import (
    ModelVersion,
    TrainingJob,
    DetectionRule,
    DetectionResult,
    BenchmarkResult,
    ModelType,
    ModelStatus,
)
from src.ai_detection.store import get_ai_detection_store, reset_ai_detection_store
from src.ai_detection.service import AIDetectionService


class TestAIDetectionModels:
    """Tests for AI detection models."""

    def test_create_model_version(self):
        """Test creating a model version."""
        model = ModelVersion(
            model_name="FraudNet",
            model_type=ModelType.FRAUD_DETECTION,
            version="1.0.0",
        )
        assert model.model_name == "FraudNet"
        assert model.accuracy == 0.0

    def test_create_training_job(self):
        """Test creating a training job."""
        job = TrainingJob(
            model_name="ThreatNet",
            model_type=ModelType.THREAT_DETECTION,
        )
        assert job.status == "PENDING"
        assert job.progress == 0.0

    def test_create_detection_rule(self):
        """Test creating a detection rule."""
        rule = DetectionRule(
            name="High Amount Transaction",
            description="Detect high value transactions",
            model_version_id="model-001",
            conditions=[{"field": "amount", "operator": ">", "value": 10000}],
            severity="HIGH",
        )
        assert rule.enabled is True
        assert rule.severity == "HIGH"

    def test_create_detection_result(self):
        """Test creating a detection result."""
        result = DetectionResult(
            model_version_id="model-001",
            entity_id="entity-001",
            score=0.85,
            is_threat=True,
            confidence=0.9,
        )
        assert result.is_threat is True
        assert result.score > 0.7

    def test_create_benchmark_result(self):
        """Test creating a benchmark result."""
        result = BenchmarkResult(
            model_version_id="model-001",
            dataset_name="test_dataset",
            accuracy=0.95,
            precision=0.92,
        )
        assert result.accuracy > 0.9


class TestAIDetectionStore:
    """Tests for AI detection store."""

    def setup_method(self):
        """Set up test store."""
        reset_ai_detection_store()
        self.store = get_ai_detection_store()

    def test_store_model(self):
        """Test storing a model."""
        model = ModelVersion(
            model_name="TestModel",
            model_type=ModelType.FRAUD_DETECTION,
            version="1.0.0",
        )
        self.store.store_model(model)
        retrieved = self.store.get_model(model.version_id)
        assert retrieved is not None
        assert retrieved.model_name == "TestModel"

    def test_get_models_by_type(self):
        """Test getting models by type."""
        self.store.store_model(ModelVersion(
            model_name="Test",
            model_type=ModelType.ANOMALY_DETECTION,
            version="1.0.0",
        ))
        results = self.store.get_models_by_type(ModelType.ANOMALY_DETECTION)
        assert len(results) >= 1

    def test_store_job(self):
        """Test storing a job."""
        job = TrainingJob(
            model_name="Test",
            model_type=ModelType.THREAT_DETECTION,
        )
        self.store.store_job(job)
        retrieved = self.store.get_job(job.job_id)
        assert retrieved is not None

    def test_store_rule(self):
        """Test storing a rule."""
        rule = DetectionRule(
            name="Test Rule",
            description="Test",
            model_version_id="model-001",
            conditions=[],
        )
        self.store.store_rule(rule)
        retrieved = self.store.get_rule(rule.rule_id)
        assert retrieved is not None

    def test_store_result(self):
        """Test storing a result."""
        result = DetectionResult(
            model_version_id="model-001",
            entity_id="entity-001",
            score=0.5,
        )
        self.store.store_result(result)
        results = self.store.get_results_by_model("model-001")
        assert len(results) >= 1

    def test_get_metrics(self):
        """Test getting metrics."""
        self.store.store_model(ModelVersion(
            model_name="Test",
            model_type=ModelType.FRAUD_DETECTION,
            version="1.0.0",
            status=ModelStatus.DEPLOYED,
        ))
        metrics = self.store.get_metrics()
        assert "active_models" in metrics
        assert metrics["active_models"] >= 1


class TestAIDetectionService:
    """Tests for AI detection service."""

    def setup_method(self):
        """Set up test service."""
        reset_ai_detection_store()
        self.service = AIDetectionService()

    def test_register_model(self):
        """Test registering a model."""
        model = self.service.register_model(
            model_name="TestModel",
            model_type=ModelType.ANOMALY_DETECTION,
            version="1.0.0",
        )
        assert model.version_id is not None
        assert model.status == ModelStatus.TRAINING

    def test_get_model(self):
        """Test getting a model."""
        created = self.service.register_model(
            model_name="Test",
            model_type=ModelType.FRAUD_DETECTION,
            version="1.0.0",
        )
        retrieved = self.service.get_model(created.version_id)
        assert retrieved is not None
        assert retrieved.model_name == "Test"

    def test_train_model(self):
        """Test creating a training job."""
        job = self.service.train_model(
            model_name="TestModel",
            model_type=ModelType.THREAT_DETECTION,
        )
        assert job.job_id is not None
        assert job.status == "PENDING"

    def test_update_job_status(self):
        """Test updating job status."""
        job = self.service.train_model(
            model_name="Test",
            model_type=ModelType.INSIDER_THREAT,
        )
        updated = self.service.update_job_status(job.job_id, "RUNNING", 0.5)
        assert updated is not None
        assert updated.status == "RUNNING"
        assert updated.progress == 0.5

    def test_deploy_model(self):
        """Test deploying a model."""
        model = self.service.register_model(
            model_name="Test",
            model_type=ModelType.FRAUD_DETECTION,
            version="1.0.0",
        )
        deployed = self.service.deploy_model(model.version_id)
        assert deployed is not None
        assert deployed.status == ModelStatus.DEPLOYED
        assert deployed.deployed_at is not None

    def test_deprecate_model(self):
        """Test deprecating a model."""
        model = self.service.register_model(
            model_name="Test",
            model_type=ModelType.COMPLIANCE,
            version="1.0.0",
        )
        deprecated = self.service.deprecate_model(model.version_id)
        assert deprecated is not None
        assert deprecated.status == ModelStatus.DEPRECATED

    def test_create_rule(self):
        """Test creating a detection rule."""
        model = self.service.register_model(
            model_name="Test",
            model_type=ModelType.ANOMALY_DETECTION,
            version="1.0.0",
        )
        rule = self.service.create_rule(
            name="Test Rule",
            description="Test rule",
            model_version_id=model.version_id,
            conditions=[{"field": "score", "operator": ">", "value": 0.8}],
            severity="HIGH",
        )
        assert rule.rule_id is not None
        assert rule.enabled is True

    def test_enable_disable_rule(self):
        """Test enabling and disabling rules."""
        model = self.service.register_model(
            model_name="Test",
            model_type=ModelType.THREAT_DETECTION,
            version="1.0.0",
        )
        rule = self.service.create_rule(
            name="Test",
            description="Test",
            model_version_id=model.version_id,
            conditions=[],
        )
        self.service.disable_rule(rule.rule_id)
        disabled = self.service.get_rule(rule.rule_id)
        assert disabled.enabled is False

        self.service.enable_rule(rule.rule_id)
        enabled = self.service.get_rule(rule.rule_id)
        assert enabled.enabled is True

    def test_detect(self):
        """Test detection."""
        model = self.service.register_model(
            model_name="Test",
            model_type=ModelType.FRAUD_DETECTION,
            version="1.0.0",
        )
        result = self.service.detect(
            model_version_id=model.version_id,
            entity_id="entity-001",
            data={"transaction_amount": 5000},
        )
        assert result.result_id is not None
        assert result.model_version_id == model.version_id

    def test_benchmark_model(self):
        """Test benchmarking a model."""
        model = self.service.register_model(
            model_name="Test",
            model_type=ModelType.ANOMALY_DETECTION,
            version="1.0.0",
        )
        result = self.service.benchmark_model(
            model_version_id=model.version_id,
            dataset_name="test_data",
        )
        assert result.benchmark_id is not None
        assert result.accuracy > 0.9

    def test_get_metrics(self):
        """Test getting metrics."""
        model = self.service.register_model(
            model_name="Test",
            model_type=ModelType.FRAUD_DETECTION,
            version="1.0.0",
        )
        self.service.deploy_model(model.version_id)
        metrics = self.service.get_metrics()
        assert metrics.active_models >= 1


class TestAIDetectionIntegration:
    """Integration tests for AI detection."""

    def setup_method(self):
        """Set up test environment."""
        reset_ai_detection_store()
        self.service = AIDetectionService()

    def test_full_detection_lifecycle(self):
        """Test complete detection lifecycle."""
        model = self.service.register_model(
            model_name="FraudDetectionNet",
            model_type=ModelType.FRAUD_DETECTION,
            version="2.0.0",
            hyperparameters={"learning_rate": 0.001},
        )

        job = self.service.train_model(
            model_name="FraudDetectionNet",
            model_type=ModelType.FRAUD_DETECTION,
            config={"epochs": 100},
        )
        self.service.update_job_status(job.job_id, "RUNNING", 0.5)
        self.service.update_job_status(job.job_id, "COMPLETED", 1.0)

        self.service.create_rule(
            name="High Value Transaction",
            description="Flag high value transactions",
            model_version_id=model.version_id,
            conditions=[{"field": "amount", "operator": ">", "value": 10000}],
            severity="HIGH",
        )

        self.service.create_rule(
            name="Multiple Failed Attempts",
            description="Flag multiple failed attempts",
            model_version_id=model.version_id,
            conditions=[{"field": "attempts", "operator": ">", "value": 3}],
            severity="MEDIUM",
        )

        deployed = self.service.deploy_model(model.version_id)
        assert deployed.status == ModelStatus.DEPLOYED

        result = self.service.detect(
            model_version_id=model.version_id,
            entity_id="customer-001",
            data={"amount": 15000, "attempts": 1},
        )
        assert result.entity_id == "customer-001"

        benchmark = self.service.benchmark_model(
            model_version_id=model.version_id,
            dataset_name="validation_set",
        )
        assert benchmark.accuracy > 0.9

        metrics = self.service.get_metrics()
        assert metrics.active_models >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
