"""
Tests for Research Laboratory Module
"""
import pytest
from datetime import datetime, timezone

from src.research_lab import (
    ResearchEngine,
    get_research_engine,
    ExperimentManager,
    BenchmarkingFramework,
    ModelEvaluationService,
    ResearchDatasetManager,
    ResearchExperiment,
    ExperimentStatus,
    ModelType,
    BenchmarkResult,
    BenchmarkType,
    Dataset,
)


class TestExperimentManager:
    """Tests for ExperimentManager."""
    
    def setup_method(self):
        self.manager = ExperimentManager()
    
    def test_create_experiment(self):
        """Test creating an experiment."""
        exp_id = self.manager.create_experiment(
            name="Test Experiment",
            description="Test description",
            model_type=ModelType.FRAUD_DETECTOR,
            created_by="researcher",
        )
        
        assert exp_id is not None
        assert self.manager.get_experiment(exp_id) is not None
    
    def test_start_experiment(self):
        """Test starting an experiment."""
        exp_id = self.manager.create_experiment(
            name="Start Test",
            description="Test",
            model_type=ModelType.THREAT_MODEL,
        )
        
        success = self.manager.start_experiment(exp_id)
        assert success is True
        
        exp = self.manager.get_experiment(exp_id)
        assert exp.status == ExperimentStatus.RUNNING
    
    def test_complete_experiment(self):
        """Test completing an experiment."""
        exp_id = self.manager.create_experiment(
            name="Complete Test",
            description="Test",
            model_type=ModelType.AML_CLASSIFIER,
        )
        
        self.manager.start_experiment(exp_id)
        
        success = self.manager.complete_experiment(
            exp_id,
            results={"accuracy": 0.95},
        )
        
        assert success is True
        exp = self.manager.get_experiment(exp_id)
        assert exp.status == ExperimentStatus.COMPLETED
    
    def test_fail_experiment(self):
        """Test failing an experiment."""
        exp_id = self.manager.create_experiment(
            name="Fail Test",
            description="Test",
            model_type=ModelType.ANOMALY_DETECTOR,
        )
        
        self.manager.start_experiment(exp_id)
        
        success = self.manager.fail_experiment(exp_id, "Test error")
        assert success is True
        
        exp = self.manager.get_experiment(exp_id)
        assert exp.status == ExperimentStatus.FAILED
    
    def test_get_experiments_by_status(self):
        """Test getting experiments by status."""
        self.manager.create_experiment("Test 1", "Desc", ModelType.FRAUD_DETECTOR)
        exp2_id = self.manager.create_experiment("Test 2", "Desc", ModelType.FRAUD_DETECTOR)
        self.manager.start_experiment(exp2_id)
        
        running = self.manager.get_experiments_by_status(ExperimentStatus.RUNNING)
        assert len(running) >= 1


class TestBenchmarkingFramework:
    """Tests for BenchmarkingFramework."""
    
    def setup_method(self):
        self.benchmarking = BenchmarkingFramework()
    
    def test_run_benchmark(self):
        """Test running a benchmark."""
        benchmark_id = self.benchmarking.run_benchmark(
            experiment_id="exp-1",
            benchmark_type=BenchmarkType.ACCURACY,
            score=0.92,
            baseline_score=0.85,
        )
        
        assert benchmark_id is not None
        
        results = self.benchmarking.get_benchmark_results("exp-1")
        assert len(results) >= 1
    
    def test_compare_benchmarks(self):
        """Test comparing benchmarks."""
        self.benchmarking.run_benchmark("exp-1", BenchmarkType.ACCURACY, 0.92)
        self.benchmarking.run_benchmark("exp-2", BenchmarkType.ACCURACY, 0.88)
        
        comparison = self.benchmarking.compare_benchmarks("exp-1", "exp-2")
        
        assert "experiment1_avg_score" in comparison
        assert "experiment2_avg_score" in comparison


class TestModelEvaluationService:
    """Tests for ModelEvaluationService."""
    
    def setup_method(self):
        self.service = ModelEvaluationService()
    
    def test_evaluate_model(self):
        """Test evaluating a model."""
        eval_id = self.service.evaluate_model(
            model_id="model-1",
            model_version="1.0",
            test_results={"accuracy": 0.95},
        )
        
        assert eval_id is not None
        
        evaluation = self.service.get_evaluation(eval_id)
        assert evaluation is not None
        assert evaluation.model_id == "model-1"
    
    def test_get_evaluations_by_model(self):
        """Test getting evaluations by model."""
        self.service.evaluate_model("model-x", "1.0", {})
        self.service.evaluate_model("model-x", "2.0", {})
        
        evals = self.service.get_evaluations_by_model("model-x")
        assert len(evals) >= 2


class TestResearchDatasetManager:
    """Tests for ResearchDatasetManager."""
    
    def setup_method(self):
        self.manager = ResearchDatasetManager()
    
    def test_initialization(self):
        """Test manager initialization."""
        assert len(self.manager.datasets) > 0
    
    def test_create_dataset(self):
        """Test creating a dataset."""
        ds_id = self.manager.create_dataset(
            name="Test Dataset",
            description="Test description",
            size=1000,
            features=["f1", "f2"],
            labels=["l1", "l2"],
        )
        
        assert ds_id is not None
        assert self.manager.get_dataset(ds_id) is not None
    
    def test_get_dataset(self):
        """Test getting a dataset."""
        ds = self.manager.get_dataset("ds-001")
        assert ds is not None
        assert ds.name == "Fraud Detection Dataset"


class TestResearchEngine:
    """Tests for ResearchEngine."""
    
    def setup_method(self):
        self.engine = ResearchEngine()
    
    def test_create_research(self):
        """Test creating research."""
        exp_id = self.engine.create_research(
            name="Research Test",
            description="Test",
            model_type=ModelType.RISK_SCORER,
        )
        
        assert exp_id is not None
    
    def test_run_experiment(self):
        """Test running an experiment."""
        exp_id = self.engine.create_research(
            name="Run Test",
            description="Test",
            model_type=ModelType.GRAPH_ANALYZER,
        )
        
        results = self.engine.run_experiment(
            experiment_id=exp_id,
            parameters={"epochs": 10},
        )
        
        assert "training_accuracy" in results
        assert "validation_accuracy" in results
    
    def test_get_research_results(self):
        """Test getting research results."""
        exp_id = self.engine.create_research(
            name="Results Test",
            description="Test",
            model_type=ModelType.FRAUD_DETECTOR,
        )
        
        self.engine.run_experiment(exp_id, {})
        
        results = self.engine.get_research_results(exp_id)
        
        assert "experiment" in results
        assert "benchmarks" in results


class TestModels:
    """Tests for model classes."""
    
    def test_research_experiment_to_dict(self):
        """Test ResearchExperiment serialization."""
        exp = ResearchExperiment(
            experiment_id="test-1",
            name="Test",
            description="Test",
            model_type=ModelType.FRAUD_DETECTOR,
        )
        
        data = exp.to_dict()
        assert data["experiment_id"] == "test-1"
        assert data["model_type"] == "FRAUD_DETECTOR"
    
    def test_model_type_values(self):
        """Test ModelType enum."""
        assert ModelType.FRAUD_DETECTOR.value == "FRAUD_DETECTOR"
        assert len(ModelType) > 0
    
    def test_experiment_status_values(self):
        """Test ExperimentStatus enum."""
        assert ExperimentStatus.PENDING.value == "PENDING"
        assert ExperimentStatus.COMPLETED.value == "COMPLETED"
    
    def test_benchmark_type_values(self):
        """Test BenchmarkType enum."""
        assert BenchmarkType.ACCURACY.value == "ACCURACY"
        assert BenchmarkType.F1_SCORE.value == "F1_SCORE"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])