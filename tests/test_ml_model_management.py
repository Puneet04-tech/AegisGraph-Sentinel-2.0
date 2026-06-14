"""
Tests for Machine Learning Model Management & A/B Testing Platform.

Comprehensive tests for:
    - Model Registry
    - Model Deployment
    - Experiment Tracker
    - A/B Testing
"""

import pytest
from datetime import datetime, timezone

from src.ml_model_management import (
    ModelType,
    ModelStatus,
    ExperimentStatus,
    ABTestStatus,
    MLModelStore,
    get_ml_store,
    ModelRegistry,
    get_model_registry,
    ModelDeploymentManager,
    get_deployment_manager,
    ExperimentTracker,
    get_experiment_tracker,
    ABTestingEngine,
    get_ab_testing_engine,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh ML store for testing."""
    return MLModelStore()


@pytest.fixture
def model_registry(store):
    """Create a model registry."""
    return ModelRegistry(store=store)


@pytest.fixture
def deployment_manager(store):
    """Create a deployment manager."""
    return ModelDeploymentManager(store=store)


@pytest.fixture
def experiment_tracker(store):
    """Create an experiment tracker."""
    return ExperimentTracker(store=store)


@pytest.fixture
def ab_testing(store):
    """Create an A/B testing engine."""
    return ABTestingEngine(store=store)


# =============================================================================
# Store Tests
# =============================================================================

class TestMLStore:
    """Tests for MLModelStore."""
    
    def test_store_model(self, store):
        """Test storing a model."""
        from src.ml_model_management import MLModel
        
        model = MLModel(
            name="Test Model",
            version="1.0.0",
            model_type=ModelType.FRAUD_DETECTION,
            description="Test",
            framework="sklearn",
        )
        
        stored = store.store_model(model)
        retrieved = store.get_model(model.model_id)
        
        assert retrieved is not None
        assert retrieved.name == "Test Model"
    
    def test_get_production_models(self, store):
        """Test getting production models."""
        models = store.get_production_models()
        assert isinstance(models, list)
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "models_stored" in stats
        assert "deployments_stored" in stats


# =============================================================================
# Model Registry Tests
# =============================================================================

class TestModelRegistry:
    """Tests for ModelRegistry."""
    
    def test_register_model(self, model_registry):
        """Test registering a model."""
        model = model_registry.register_model(
            name="Test Model",
            version="1.0.0",
            model_type=ModelType.FRAUD_DETECTION,
            description="Test model",
            framework="sklearn",
            metrics={"accuracy": 0.95},
        )
        
        assert model.model_id is not None
        assert model.name == "Test Model"
    
    def test_update_model_metrics(self, model_registry):
        """Test updating model metrics."""
        model = model_registry.register_model(
            name="Update Test",
            version="1.0.0",
            model_type=ModelType.RISK_SCORING,
            description="Test",
            framework="xgboost",
        )
        
        updated = model_registry.update_model_metrics(
            model.model_id,
            {"accuracy": 0.96, "f1": 0.90},
        )
        
        assert updated.metrics["accuracy"] == 0.96
    
    def test_compare_models(self, model_registry):
        """Test comparing models."""
        model_a = model_registry.register_model(
            name="Model A",
            version="1.0.0",
            model_type=ModelType.FRAUD_DETECTION,
            description="A",
            framework="sklearn",
            metrics={"accuracy": 0.90},
        )
        
        model_b = model_registry.register_model(
            name="Model B",
            version="1.0.0",
            model_type=ModelType.FRAUD_DETECTION,
            description="B",
            framework="sklearn",
            metrics={"accuracy": 0.95},
        )
        
        comparison = model_registry.compare_models(model_a.model_id, model_b.model_id)
        
        assert "metric_comparison" in comparison


# =============================================================================
# Deployment Manager Tests
# =============================================================================

class TestDeploymentManager:
    """Tests for ModelDeploymentManager."""
    
    def test_create_deployment(self, deployment_manager, model_registry):
        """Test creating a deployment."""
        model = model_registry.register_model(
            name="Deploy Test",
            version="1.0.0",
            model_type=ModelType.ANOMALY_DETECTION,
            description="Test",
            framework="sklearn",
        )
        
        deployment = deployment_manager.create_deployment(
            model_id=model.model_id,
            environment="staging",
        )
        
        assert deployment.deployment_id is not None
        assert deployment.model_id == model.model_id
    
    def test_canary_deploy(self, deployment_manager, model_registry):
        """Test canary deployment."""
        model = model_registry.register_model(
            name="Canary Test",
            version="1.0.0",
            model_type=ModelType.PATTERN_RECOGNITION,
            description="Test",
            framework="pytorch",
        )
        
        deployment = deployment_manager.canary_deploy(
            model_id=model.model_id,
            canary_percentage=10.0,
        )
        
        assert deployment.traffic_percentage == 10.0


# =============================================================================
# Experiment Tracker Tests
# =============================================================================

class TestExperimentTracker:
    """Tests for ExperimentTracker."""
    
    def test_create_experiment(self, experiment_tracker):
        """Test creating an experiment."""
        experiment = experiment_tracker.create_experiment(
            name="Test Experiment",
            description="Testing new parameters",
            model_type=ModelType.FRAUD_DETECTION,
            parameters={"learning_rate": 0.01, "epochs": 100},
        )
        
        assert experiment.experiment_id is not None
        assert experiment.name == "Test Experiment"
    
    def test_start_complete_experiment(self, experiment_tracker):
        """Test starting and completing an experiment."""
        experiment = experiment_tracker.create_experiment(
            name="Complete Test",
            description="Test",
            model_type=ModelType.RISK_SCORING,
        )
        
        experiment_tracker.start_experiment(experiment.experiment_id)
        updated = experiment_tracker.complete_experiment(
            experiment.experiment_id,
            {"accuracy": 0.95, "auc": 0.92},
        )
        
        assert updated.status == ExperimentStatus.COMPLETED
    
    def test_compare_experiments(self, experiment_tracker):
        """Test comparing experiments."""
        exp1 = experiment_tracker.create_experiment(
            name="Exp 1",
            description="Test",
            model_type=ModelType.FRAUD_DETECTION,
        )
        
        exp2 = experiment_tracker.create_experiment(
            name="Exp 2",
            description="Test",
            model_type=ModelType.FRAUD_DETECTION,
        )
        
        experiment_tracker.complete_experiment(exp1.experiment_id, {"accuracy": 0.90})
        experiment_tracker.complete_experiment(exp2.experiment_id, {"accuracy": 0.95})
        
        comparison = experiment_tracker.compare_experiments(
            [exp1.experiment_id, exp2.experiment_id],
        )
        
        assert "metric_comparison" in comparison


# =============================================================================
# A/B Testing Tests
# =============================================================================

class TestABTesting:
    """Tests for ABTestingEngine."""
    
    def test_create_test(self, ab_testing):
        """Test creating an A/B test."""
        test = ab_testing.create_test(
            name="A/B Test 1",
            description="Testing model versions",
            model_a_id="model_a_123",
            model_b_id="model_b_456",
            traffic_split=0.5,
        )
        
        assert test.test_id is not None
        assert test.traffic_split == 0.5
    
    def test_start_pause_test(self, ab_testing):
        """Test starting and pausing a test."""
        test = ab_testing.create_test(
            name="Pause Test",
            description="Test",
            model_a_id="model_a",
            model_b_id="model_b",
        )
        
        ab_testing.start_test(test.test_id)
        test = ab_testing.get_test(test.test_id)
        assert test.status == ABTestStatus.RUNNING
        
        ab_testing.pause_test(test.test_id)
        test = ab_testing.get_test(test.test_id)
        assert test.status == ABTestStatus.PAUSED
    
    def test_complete_test(self, ab_testing):
        """Test completing a test."""
        test = ab_testing.create_test(
            name="Complete Test",
            description="Test",
            model_a_id="model_a",
            model_b_id="model_b",
        )
        
        ab_testing.start_test(test.test_id)
        ab_testing.log_metric(test.test_id, "A", "accuracy", 0.90)
        ab_testing.log_metric(test.test_id, "B", "accuracy", 0.95)
        
        completed = ab_testing.complete_test(test.test_id)
        
        assert completed.status == ABTestStatus.COMPLETED
        assert completed.winner in ["A", "B", "TIE", "INCONCLUSIVE"]


# =============================================================================
# Integration Tests
# =============================================================================

class TestMLIntegration:
    """Integration tests for ML workflow."""
    
    def test_full_ml_workflow(
        self,
        model_registry,
        deployment_manager,
        experiment_tracker,
        ab_testing,
    ):
        """Test full ML workflow."""
        # 1. Register models
        model_a = model_registry.register_model(
            name="Model A",
            version="1.0.0",
            model_type=ModelType.FRAUD_DETECTION,
            description="Control model",
            framework="sklearn",
            metrics={"accuracy": 0.90},
        )
        
        model_b = model_registry.register_model(
            name="Model B",
            version="2.0.0",
            model_type=ModelType.FRAUD_DETECTION,
            description="Variant model",
            framework="sklearn",
            metrics={"accuracy": 0.95},
            parent_model_id=model_a.model_id,
        )
        
        # 2. Create experiment
        experiment = experiment_tracker.create_experiment(
            name="Model Comparison",
            description="Compare A vs B",
            model_type=ModelType.FRAUD_DETECTION,
        )
        
        # 3. Deploy model
        deployment = deployment_manager.create_deployment(
            model_id=model_a.model_id,
            environment="production",
        )
        
        # 4. Create A/B test
        test = ab_testing.create_test(
            name="Production A/B Test",
            description="Real-world test",
            model_a_id=model_a.model_id,
            model_b_id=model_b.model_id,
        )
        
        # Verify
        assert model_a.model_id is not None
        assert model_b.model_id is not None
        assert experiment.experiment_id is not None
        assert deployment.deployment_id is not None
        assert test.test_id is not None