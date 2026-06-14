"""
Decision Tracer Module.

Complete audit trail for all AI decisions.
"""

import random
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import DecisionTrace
from .store import ExplainableAIStore, get_xai_store

logger = logging.getLogger(__name__)


class DecisionTracer:
    """Decision Tracer for complete audit trail.
    
    Provides:
        - Decision audit trail
        - Factor tracking
        - Model versioning
        - Timestamp logging
    """
    
    def __init__(self, store: Optional[ExplainableAIStore] = None):
        """Initialize the decision tracer."""
        self._store = store or get_xai_store()
        self._module_id = "decision_tracer"
    
    def trace_decision(
        self,
        decision_id: str,
        model_id: str,
        model_name: str,
        model_version: str,
        input_features: Dict[str, Any],
        output_decision: str,
        output_score: float,
        user_id: str = None,
        case_id: str = None,
        transaction_id: str = None,
    ) -> DecisionTrace:
        """Create a complete decision trace."""
        logger.info(f"Tracing decision {decision_id}")
        
        start_time = time.time()
        
        # Extract decision factors
        factors = self._extract_decision_factors(input_features, output_score)
        
        # Create trace
        trace = DecisionTrace(
            decision_id=decision_id,
            model_id=model_id,
            model_version=model_version,
            model_name=model_name,
            input_features=input_features,
            output_decision=output_decision,
            output_score=output_score,
            decision_factors=factors,
            user_id=user_id,
            case_id=case_id,
            transaction_id=transaction_id,
            processing_time_ms=(time.time() - start_time) * 1000,
        )
        
        self._store.store_trace(trace)
        
        # Update metrics
        self._store.store_metrics({
            "event": "decision_traced",
            "model_id": model_id,
            "decision": output_decision,
            "score": output_score,
            "processing_time_ms": trace.processing_time_ms,
        })
        
        return trace
    
    def _extract_decision_factors(
        self,
        features: Dict[str, Any],
        score: float,
    ) -> List[Dict[str, Any]]:
        """Extract key decision factors from features."""
        factors = []
        
        # Sort features by absolute value
        sorted_features = sorted(
            features.items(),
            key=lambda x: abs(x[1]) if isinstance(x[1], (int, float)) else 0,
            reverse=True,
        )
        
        for feature, value in sorted_features[:10]:  # Top 10 factors
            if isinstance(value, (int, float)):
                factors.append({
                    "feature": feature,
                    "value": value,
                    "contribution": value * score,
                    "direction": "positive" if value > 0 else "negative",
                    "weight": abs(value) / (sum(abs(v) for _, v in sorted_features[:10] if isinstance(v, (int, float))) + 0.001),
                })
        
        return factors
    
    def get_trace(self, trace_id: str) -> Optional[DecisionTrace]:
        """Get decision trace by ID."""
        return self._store.get_trace(trace_id)
    
    def get_decision_trace(self, decision_id: str) -> Optional[DecisionTrace]:
        """Get trace for a decision."""
        traces = self._store.get_decision_traces(decision_id)
        return traces[0] if traces else None
    
    def get_recent_traces(self, limit: int = 100) -> List[DecisionTrace]:
        """Get recent decision traces."""
        return self._store.get_recent_traces(limit)
    
    def get_model_traces(self, model_id: str, limit: int = 100) -> List[DecisionTrace]:
        """Get traces for a model."""
        return self._store.get_model_traces(model_id, limit)
    
    def get_traces_by_user(self, user_id: str, limit: int = 100) -> List[DecisionTrace]:
        """Get traces for a user."""
        all_traces = self._store.get_recent_traces(limit * 2)
        return [t for t in all_traces if t.user_id == user_id][:limit]
    
    def get_traces_by_case(self, case_id: str) -> List[DecisionTrace]:
        """Get traces for a case."""
        all_traces = self._store.get_recent_traces(limit=1000)
        return [t for t in all_traces if t.case_id == case_id]
    
    def get_trace_summary(self, decision_id: str) -> Dict[str, Any]:
        """Get summary of a decision trace."""
        trace = self.get_decision_trace(decision_id)
        
        if not trace:
            return {"error": "Trace not found"}
        
        return {
            "decision_id": decision_id,
            "model": {
                "id": trace.model_id,
                "name": trace.model_name,
                "version": trace.model_version,
            },
            "decision": {
                "outcome": trace.output_decision,
                "score": trace.output_score,
                "timestamp": trace.timestamp.isoformat(),
            },
            "context": {
                "user_id": trace.user_id,
                "case_id": trace.case_id,
                "transaction_id": trace.transaction_id,
            },
            "top_factors": [
                {
                    "feature": f["feature"],
                    "contribution": f["contribution"],
                    "direction": f["direction"],
                }
                for f in sorted(trace.decision_factors, key=lambda x: abs(x["contribution"]), reverse=True)[:5]
            ],
            "processing_time_ms": trace.processing_time_ms,
        }
    
    def get_trace_analytics(self, period_hours: int = 24) -> Dict[str, Any]:
        """Get analytics for traces in a time period."""
        traces = self._store.get_recent_traces(limit=10000)
        
        if not traces:
            return {"error": "No traces available"}
        
        # Filter by time period
        cutoff = datetime.now(timezone.utc).timestamp() - (period_hours * 3600)
        recent_traces = [t for t in traces if t.timestamp.timestamp() > cutoff]
        
        # Calculate statistics
        total_traces = len(recent_traces)
        avg_score = sum(t.output_score for t in recent_traces) / total_traces if total_traces else 0
        avg_processing_time = sum(t.processing_time_ms for t in recent_traces) / total_traces if total_traces else 0
        
        # Count by decision
        decision_counts = {}
        for t in recent_traces:
            decision_counts[t.output_decision] = decision_counts.get(t.output_decision, 0) + 1
        
        # Count by model
        model_counts = {}
        for t in recent_traces:
            model_counts[t.model_name] = model_counts.get(t.model_name, 0) + 1
        
        return {
            "period_hours": period_hours,
            "total_traces": total_traces,
            "average_score": avg_score,
            "average_processing_time_ms": avg_processing_time,
            "decisions_by_outcome": decision_counts,
            "decisions_by_model": model_counts,
        }


# Global singleton
_decision_tracer: Optional[DecisionTracer] = None


def get_decision_tracer(store: Optional[ExplainableAIStore] = None) -> DecisionTracer:
    """Get or create the singleton DecisionTracer instance."""
    global _decision_tracer
    
    if _decision_tracer is None:
        _decision_tracer = DecisionTracer(store=store)
    return _decision_tracer