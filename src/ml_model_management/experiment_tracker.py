"""
Experiment Tracker Module.

ML experiment tracking, parameter logging, and result comparison.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    Experiment,
    ExperimentStatus,
    ModelType,
)
from .store import MLModelStore, get_ml_store

logger = logging.getLogger(__name__)


class ExperimentTracker:
    """Experiment Tracker for ML experiments.
    
    Provides:
        - Experiment creation
        - Parameter tracking
        - Metric logging
        - Result comparison
    """
    
    def __init__(self, store: Optional[MLModelStore] = None):
        """Initialize the experiment tracker."""
        self._store = store or get_ml_store()
        self._module_id = "experiment_tracker"
    
    def create_experiment(
        self,
        name: str,
        description: str,
        model_type: ModelType,
        parameters: Dict[str, Any] = None,
        tags: List[str] = None,
        parent_experiment_id: str = None,
    ) -> Experiment:
        """Create a new experiment."""
        logger.info(f"Creating experiment: {name}")
        
        experiment = Experiment(
            name=name,
            description=description,
            model_type=model_type,
            parameters=parameters or {},
            tags=tags or [],
            parent_experiment_id=parent_experiment_id,
        )
        
        self._store.store_experiment(experiment)
        return experiment
    
    def start_experiment(self, experiment_id: str) -> Experiment:
        """Start an experiment."""
        experiment = self._store.get_experiment(experiment_id)
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        experiment.status = ExperimentStatus.RUNNING
        experiment.started_at = datetime.now(timezone.utc)
        self._store.store_experiment(experiment)
        
        return experiment
    
    def complete_experiment(
        self,
        experiment_id: str,
        metrics: Dict[str, float],
    ) -> Experiment:
        """Complete an experiment with final metrics."""
        experiment = self._store.get_experiment(experiment_id)
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        experiment.status = ExperimentStatus.COMPLETED
        experiment.metrics = metrics
        experiment.completed_at = datetime.now(timezone.utc)
        self._store.store_experiment(experiment)
        
        return experiment
    
    def fail_experiment(
        self,
        experiment_id: str,
        error: str = None,
    ) -> Experiment:
        """Mark experiment as failed."""
        experiment = self._store.get_experiment(experiment_id)
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        experiment.status = ExperimentStatus.FAILED
        experiment.completed_at = datetime.now(timezone.utc)
        self._store.store_experiment(experiment)
        
        return experiment
    
    def log_metric(
        self,
        experiment_id: str,
        metric_name: str,
        value: float,
    ) -> None:
        """Log a metric for an experiment."""
        experiment = self._store.get_experiment(experiment_id)
        if not experiment:
            return
        
        experiment.metrics[metric_name] = value
        self._store.store_experiment(experiment)
    
    def get_experiment(self, experiment_id: str) -> Optional[Experiment]:
        """Get experiment by ID."""
        return self._store.get_experiment(experiment_id)
    
    def list_experiments(
        self,
        status: ExperimentStatus = None,
        model_type: ModelType = None,
    ) -> List[Experiment]:
        """List experiments with filters."""
        experiments = self._store.get_all_experiments()
        
        if status:
            experiments = [e for e in experiments if e.status == status]
        if model_type:
            experiments = [e for e in experiments if e.model_type == model_type]
        
        return sorted(experiments, key=lambda e: e.created_at, reverse=True)
    
    def compare_experiments(
        self,
        experiment_ids: List[str],
    ) -> Dict[str, Any]:
        """Compare multiple experiments."""
        experiments = [
            self._store.get_experiment(eid)
            for eid in experiment_ids
        ]
        experiments = [e for e in experiments if e]
        
        if len(experiments) < 2:
            return {"error": "Need at least 2 experiments to compare"}
        
        # Get all metrics
        all_metrics = set()
        for exp in experiments:
            all_metrics.update(exp.metrics.keys())
        
        metric_comparison = {}
        for metric in all_metrics:
            values = [(i, exp.metrics.get(metric, 0)) for i, exp in enumerate(experiments)]
            best_idx = max(values, key=lambda x: x[1])[0]
            metric_comparison[metric] = {
                "values": values,
                "best_experiment": experiment_ids[best_idx],
            }
        
        return {
            "experiments": [
                {"id": e.experiment_id, "name": e.name, "status": e.status.value}
                for e in experiments
            ],
            "metric_comparison": metric_comparison,
        }


# Global singleton
_experiment_tracker: Optional[ExperimentTracker] = None


def get_experiment_tracker(store: Optional[MLModelStore] = None) -> ExperimentTracker:
    """Get or create the singleton ExperimentTracker instance."""
    global _experiment_tracker
    
    if _experiment_tracker is None:
        _experiment_tracker = ExperimentTracker(store=store)
    return _experiment_tracker