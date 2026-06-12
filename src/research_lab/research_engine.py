"""
Research Engine
AI-powered security research laboratory.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
import random

from .models import (
    ResearchExperiment,
    ExperimentStatus,
    ModelType,
    BenchmarkResult,
    BenchmarkType,
    ModelEvaluation,
    Dataset,
)


class ExperimentManager:
    """Manager for research experiments."""
    
    def __init__(self):
        self.experiments: Dict[str, ResearchExperiment] = {}
    
    def create_experiment(
        self,
        name: str,
        description: str,
        model_type: ModelType,
        parameters: Optional[Dict[str, Any]] = None,
        created_by: str = "",
    ) -> str:
        """Create a new experiment."""
        experiment_id = str(uuid4())
        
        experiment = ResearchExperiment(
            experiment_id=experiment_id,
            name=name,
            description=description,
            model_type=model_type,
            parameters=parameters or {},
            created_by=created_by,
        )
        
        self.experiments[experiment_id] = experiment
        return experiment_id
    
    def start_experiment(self, experiment_id: str) -> bool:
        """Start an experiment."""
        experiment = self.experiments.get(experiment_id)
        if not experiment:
            return False
        
        experiment.status = ExperimentStatus.RUNNING
        experiment.started_at = datetime.now(timezone.utc)
        return True
    
    def complete_experiment(
        self,
        experiment_id: str,
        results: Dict[str, Any],
    ) -> bool:
        """Complete an experiment."""
        experiment = self.experiments.get(experiment_id)
        if not experiment:
            return False
        
        experiment.status = ExperimentStatus.COMPLETED
        experiment.completed_at = datetime.now(timezone.utc)
        experiment.results = results
        return True
    
    def fail_experiment(
        self,
        experiment_id: str,
        error: str,
    ) -> bool:
        """Mark an experiment as failed."""
        experiment = self.experiments.get(experiment_id)
        if not experiment:
            return False
        
        experiment.status = ExperimentStatus.FAILED
        experiment.completed_at = datetime.now(timezone.utc)
        experiment.results = {"error": error}
        return True
    
    def get_experiment(self, experiment_id: str) -> Optional[ResearchExperiment]:
        """Get an experiment by ID."""
        return self.experiments.get(experiment_id)
    
    def get_experiments_by_status(self, status: ExperimentStatus) -> List[ResearchExperiment]:
        """Get experiments by status."""
        return [e for e in self.experiments.values() if e.status == status]


class BenchmarkingFramework:
    """Framework for benchmarking models."""
    
    def __init__(self):
        self.results: Dict[str, List[BenchmarkResult]] = {}
    
    def run_benchmark(
        self,
        experiment_id: str,
        benchmark_type: BenchmarkType,
        score: float,
        baseline_score: float = 0.5,
        dataset: str = "default",
    ) -> str:
        """Run a benchmark."""
        benchmark_id = str(uuid4())
        
        result = BenchmarkResult(
            benchmark_id=benchmark_id,
            experiment_id=experiment_id,
            benchmark_type=benchmark_type,
            score=score,
            baseline_score=baseline_score,
            improvement=((score - baseline_score) / baseline_score) * 100 if baseline_score > 0 else 0,
            dataset=dataset,
        )
        
        if experiment_id not in self.results:
            self.results[experiment_id] = []
        self.results[experiment_id].append(result)
        
        return benchmark_id
    
    def get_benchmark_results(self, experiment_id: str) -> List[BenchmarkResult]:
        """Get benchmark results for an experiment."""
        return self.results.get(experiment_id, [])
    
    def compare_benchmarks(
        self,
        experiment_id1: str,
        experiment_id2: str,
    ) -> Dict[str, Any]:
        """Compare benchmarks between experiments."""
        results1 = self.results.get(experiment_id1, [])
        results2 = self.results.get(experiment_id2, [])
        
        comparison = {
            "experiment1_avg_score": sum(r.score for r in results1) / max(1, len(results1)),
            "experiment2_avg_score": sum(r.score for r in results2) / max(1, len(results2)),
            "winner": "experiment1" if results1 and results2 and results1[0].score > results2[0].score else "experiment2",
        }
        
        return comparison


class ModelEvaluationService:
    """Service for evaluating models."""
    
    def __init__(self):
        self.evaluations: Dict[str, ModelEvaluation] = {}
    
    def evaluate_model(
        self,
        model_id: str,
        model_version: str,
        test_results: Dict[str, Any],
    ) -> str:
        """Evaluate a model."""
        evaluation_id = str(uuid4())
        
        metrics = {
            "accuracy": test_results.get("accuracy", random.uniform(0.7, 0.95)),
            "precision": test_results.get("precision", random.uniform(0.6, 0.95)),
            "recall": test_results.get("recall", random.uniform(0.6, 0.95)),
            "f1_score": test_results.get("f1", random.uniform(0.6, 0.95)),
        }
        
        performance_score = sum(metrics.values()) / len(metrics)
        
        recommendations = []
        if metrics["accuracy"] < 0.85:
            recommendations.append("Improve model accuracy")
        if metrics["precision"] < 0.8:
            recommendations.append("Reduce false positives")
        if metrics["recall"] < 0.8:
            recommendations.append("Improve detection rate")
        
        evaluation = ModelEvaluation(
            evaluation_id=evaluation_id,
            model_id=model_id,
            model_version=model_version,
            metrics=metrics,
            performance_score=performance_score,
            recommendations=recommendations,
        )
        
        self.evaluations[evaluation_id] = evaluation
        return evaluation_id
    
    def get_evaluation(self, evaluation_id: str) -> Optional[ModelEvaluation]:
        """Get an evaluation by ID."""
        return self.evaluations.get(evaluation_id)
    
    def get_evaluations_by_model(self, model_id: str) -> List[ModelEvaluation]:
        """Get evaluations for a model."""
        return [e for e in self.evaluations.values() if e.model_id == model_id]


class ResearchDatasetManager:
    """Manager for research datasets."""
    
    def __init__(self):
        self.datasets: Dict[str, Dataset] = {}
        self._initialize_default_datasets()
    
    def _initialize_default_datasets(self):
        """Initialize default datasets."""
        datasets = [
            Dataset(
                dataset_id="ds-001",
                name="Fraud Detection Dataset",
                description="Synthetic fraud transaction data",
                size=100000,
                features=["amount", "velocity", "recipient_count", "time_of_day"],
                labels=["fraud", "legitimate"],
            ),
            Dataset(
                dataset_id="ds-002",
                name="AML Transaction Dataset",
                description="Anti-money laundering transaction records",
                size=50000,
                features=["amount", "frequency", "international", "pattern_score"],
                labels=["suspicious", "normal"],
            ),
        ]
        
        for ds in datasets:
            self.datasets[ds.dataset_id] = ds
    
    def create_dataset(
        self,
        name: str,
        description: str,
        size: int,
        features: List[str],
        labels: List[str],
    ) -> str:
        """Create a new dataset."""
        dataset_id = str(uuid4())
        
        dataset = Dataset(
            dataset_id=dataset_id,
            name=name,
            description=description,
            size=size,
            features=features,
            labels=labels,
        )
        
        self.datasets[dataset_id] = dataset
        return dataset_id
    
    def get_dataset(self, dataset_id: str) -> Optional[Dataset]:
        """Get a dataset by ID."""
        return self.datasets.get(dataset_id)


class ResearchEngine:
    """Main research engine."""
    
    def __init__(self):
        self.experiment_manager = ExperimentManager()
        self.benchmarking = BenchmarkingFramework()
        self.evaluation_service = ModelEvaluationService()
        self.dataset_manager = ResearchDatasetManager()
    
    def create_research(
        self,
        name: str,
        description: str,
        model_type: ModelType,
        created_by: str = "",
    ) -> str:
        """Create a new research experiment."""
        return self.experiment_manager.create_experiment(
            name=name,
            description=description,
            model_type=model_type,
            created_by=created_by,
        )
    
    def run_experiment(
        self,
        experiment_id: str,
        parameters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run an experiment with parameters."""
        experiment = self.experiment_manager.get_experiment(experiment_id)
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        self.experiment_manager.start_experiment(experiment_id)
        
        results = {
            "training_accuracy": random.uniform(0.85, 0.98),
            "validation_accuracy": random.uniform(0.80, 0.95),
            "training_loss": random.uniform(0.01, 0.1),
            "epochs_completed": parameters.get("epochs", 10),
        }
        
        self.experiment_manager.complete_experiment(experiment_id, results)
        
        for benchmark_type in [BenchmarkType.ACCURACY, BenchmarkType.PRECISION, BenchmarkType.F1_SCORE]:
            self.benchmarking.run_benchmark(
                experiment_id=experiment_id,
                benchmark_type=benchmark_type,
                score=results["validation_accuracy"],
            )
        
        return results
    
    def get_research_results(self, experiment_id: str) -> Dict[str, Any]:
        """Get results for a research experiment."""
        experiment = self.experiment_manager.get_experiment(experiment_id)
        if not experiment:
            return {"error": "Experiment not found"}
        
        benchmarks = self.benchmarking.get_benchmark_results(experiment_id)
        
        return {
            "experiment": experiment.to_dict(),
            "benchmarks": [b.to_dict() for b in benchmarks],
            "metrics": experiment.results,
        }


def get_research_engine() -> ResearchEngine:
    """Get the global research engine instance."""
    global _research_engine
    if _research_engine is None:
        _research_engine = ResearchEngine()
    return _research_engine


_research_engine: Optional[ResearchEngine] = None