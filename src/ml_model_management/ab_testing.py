"""
A/B Testing Module.

Controlled experiments for model comparison and traffic splitting.
"""

import random
import math
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    ABTest,
    ABTestStatus,
)
from .store import MLModelStore, get_ml_store

logger = logging.getLogger(__name__)


class ABTestingEngine:
    """A/B Testing Engine for controlled experiments.
    
    Provides:
        - A/B test creation
        - Traffic splitting
        - Statistical significance calculation
        - Winner determination
    """
    
    def __init__(self, store: Optional[MLModelStore] = None):
        """Initialize the A/B testing engine."""
        self._store = store or get_ml_store()
        self._module_id = "ab_testing"
    
    def create_test(
        self,
        name: str,
        description: str,
        model_a_id: str,
        model_b_id: str,
        traffic_split: float = 0.5,
        sample_size: int = 1000,
        confidence_level: float = 0.95,
    ) -> ABTest:
        """Create a new A/B test."""
        logger.info(f"Creating A/B test: {name}")
        
        test = ABTest(
            name=name,
            description=description,
            model_a_id=model_a_id,
            model_b_id=model_b_id,
            traffic_split=traffic_split,
            sample_size=sample_size,
            confidence_level=confidence_level,
        )
        
        self._store.store_ab_test(test)
        return test
    
    def start_test(self, test_id: str) -> ABTest:
        """Start an A/B test."""
        test = self._store.get_ab_test(test_id)
        if not test:
            raise ValueError(f"Test {test_id} not found")
        
        test.status = ABTestStatus.RUNNING
        test.started_at = datetime.now(timezone.utc)
        self._store.store_ab_test(test)
        
        return test
    
    def pause_test(self, test_id: str) -> ABTest:
        """Pause an A/B test."""
        test = self._store.get_ab_test(test_id)
        if not test:
            raise ValueError(f"Test {test_id} not found")
        
        test.status = ABTestStatus.PAUSED
        self._store.store_ab_test(test)
        
        return test
    
    def complete_test(self, test_id: str) -> ABTest:
        """Complete an A/B test and determine winner."""
        test = self._store.get_ab_test(test_id)
        if not test:
            raise ValueError(f"Test {test_id} not found")
        
        test.status = ABTestStatus.COMPLETED
        test.completed_at = datetime.now(timezone.utc)
        
        # Determine winner using statistical significance
        winner = self._calculate_winner(test)
        test.winner = winner
        
        self._store.store_ab_test(test)
        return test
    
    def log_metric(
        self,
        test_id: str,
        variant: str,
        metric_name: str,
        value: float,
    ) -> None:
        """Log a metric for a test variant."""
        test = self._store.get_ab_test(test_id)
        if not test:
            return
        
        if variant == "A":
            test.metrics[metric_name] = value
        else:
            test.variant_metrics[metric_name] = value
        
        self._store.store_ab_test(test)
    
    def get_test(self, test_id: str) -> Optional[ABTest]:
        """Get test by ID."""
        return self._store.get_ab_test(test_id)
    
    def list_tests(self, status: ABTestStatus = None) -> List[ABTest]:
        """List A/B tests."""
        tests = self._store.get_all_ab_tests()
        
        if status:
            tests = [t for t in tests if t.status == status]
        
        return sorted(tests, key=lambda t: t.created_at, reverse=True)
    
    def get_running_tests(self) -> List[ABTest]:
        """Get running tests."""
        return self._store.get_running_ab_tests()
    
    def _calculate_winner(self, test: ABTest) -> str:
        """Calculate statistical winner of A/B test."""
        # Simple comparison based on primary metric
        primary_metric = "accuracy"  # Default metric
        
        metric_a = test.metrics.get(primary_metric, 0)
        metric_b = test.variant_metrics.get(primary_metric, 0)
        
        # Calculate statistical significance (simplified)
        n_a = test.sample_size * test.traffic_split
        n_b = test.sample_size * (1 - test.traffic_split)
        
        # Standard error (simplified)
        se_a = math.sqrt(metric_a * (1 - metric_a) / n_a) if n_a > 0 else 0
        se_b = math.sqrt(metric_b * (1 - metric_b) / n_b) if n_b > 0 else 0
        
        # Z-score for difference
        diff = abs(metric_b - metric_a)
        se_combined_sq = se_a**2 + se_b**2
        se_diff = math.sqrt(se_combined_sq) if se_combined_sq > 0 else 0
        
        if se_diff == 0:
            return "TIE"
        
        z_score = diff / se_diff
        
        # Determine winner based on confidence level
        if z_score > 1.96:  # 95% confidence
            return "B" if metric_b > metric_a else "A"
        elif z_score > 1.645:  # 90% confidence
            return "B" if metric_b > metric_a else "A"
        else:
            return "INCONCLUSIVE"
    
    def get_test_summary(self, test_id: str) -> Dict[str, Any]:
        """Get A/B test summary."""
        test = self._store.get_ab_test(test_id)
        if not test:
            return {"error": "Test not found"}
        
        return {
            "test_id": test_id,
            "name": test.name,
            "status": test.status.value,
            "model_a": test.model_a_id,
            "model_b": test.model_b_id,
            "traffic_split": f"{test.traffic_split * 100}% / {(1 - test.traffic_split) * 100}%",
            "model_a_metrics": test.metrics,
            "model_b_metrics": test.variant_metrics,
            "winner": test.winner,
            "started_at": test.started_at.isoformat() if test.started_at else None,
            "completed_at": test.completed_at.isoformat() if test.completed_at else None,
        }


# Global singleton
_ab_testing_engine: Optional[ABTestingEngine] = None


def get_ab_testing_engine(store: Optional[MLModelStore] = None) -> ABTestingEngine:
    """Get or create the singleton ABTestingEngine instance."""
    global _ab_testing_engine
    
    if _ab_testing_engine is None:
        _ab_testing_engine = ABTestingEngine(store=store)
    return _ab_testing_engine