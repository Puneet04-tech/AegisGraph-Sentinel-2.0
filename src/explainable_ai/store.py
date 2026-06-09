"""
Explainable AI Storage Engine.

Thread-safe storage for explanations, traces, and compliance data.
"""

from collections import deque
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    Explanation,
    DecisionTrace,
    ComplianceReport,
    BiasAnalysis,
    ModelAudit,
    CounterfactualExplanation,
    AdverseActionNotice,
)

logger = logging.getLogger(__name__)


class ExplainableAIStore:
    """Thread-safe storage for XAI data.
    
    Provides:
        - O(1) lookup by ID
        - Thread-safe operations
        - Bounded retention
        - Full audit trail
    """
    
    def __init__(self, max_items: int = 10000):
        """Initialize the XAI store."""
        self._max_items = max_items
        self._lock = Lock()
        
        # Explanations
        self._explanations: Dict[str, Explanation] = {}
        
        # Decision traces
        self._traces: Dict[str, DecisionTrace] = {}
        self._traces_by_decision: Dict[str, List[str]] = {}
        
        # Compliance reports
        self._compliance_reports: Dict[str, ComplianceReport] = {}
        
        # Bias analyses
        self._bias_analyses: Dict[str, BiasAnalysis] = {}
        
        # Model audits
        self._audits: Dict[str, ModelAudit] = {}
        
        # Counterfactual explanations
        self._counterfactuals: Dict[str, CounterfactualExplanation] = {}
        
        # Adverse action notices
        self._adverse_actions: Dict[str, AdverseActionNotice] = {}
        
        # Metrics history (bounded)
        self._metrics_history: deque = deque(maxlen=max_items)
        
        logger.info("Explainable AI store initialized")
    
    # Explanation Methods
    def store_explanation(self, explanation: Explanation) -> Explanation:
        """Store an explanation."""
        with self._lock:
            self._explanations[explanation.explanation_id] = explanation
        return explanation
    
    def get_explanation(self, explanation_id: str) -> Optional[Explanation]:
        """Get explanation by ID."""
        return self._explanations.get(explanation_id)
    
    def get_decision_explanation(self, decision_id: str) -> Optional[Explanation]:
        """Get explanation for a decision."""
        for exp in self._explanations.values():
            if exp.decision_id == decision_id:
                return exp
        return None
    
    def get_model_explanations(self, model_id: str, limit: int = 100) -> List[Explanation]:
        """Get explanations for a model."""
        explanations = [e for e in self._explanations.values() if e.model_id == model_id]
        return sorted(explanations, key=lambda e: e.created_at, reverse=True)[:limit]
    
    # Decision Trace Methods
    def store_trace(self, trace: DecisionTrace) -> DecisionTrace:
        """Store a decision trace."""
        with self._lock:
            self._traces[trace.trace_id] = trace
            
            if trace.decision_id not in self._traces_by_decision:
                self._traces_by_decision[trace.decision_id] = []
            self._traces_by_decision[trace.decision_id].append(trace.trace_id)
        
        return trace
    
    def get_trace(self, trace_id: str) -> Optional[DecisionTrace]:
        """Get trace by ID."""
        return self._traces.get(trace_id)
    
    def get_decision_traces(self, decision_id: str) -> List[DecisionTrace]:
        """Get traces for a decision."""
        trace_ids = self._traces_by_decision.get(decision_id, [])
        return [self._traces[tid] for tid in trace_ids if tid in self._traces]
    
    def get_recent_traces(self, limit: int = 100) -> List[DecisionTrace]:
        """Get recent decision traces."""
        traces = list(self._traces.values())
        return sorted(traces, key=lambda t: t.timestamp, reverse=True)[:limit]
    
    def get_model_traces(self, model_id: str, limit: int = 100) -> List[DecisionTrace]:
        """Get traces for a model."""
        traces = [t for t in self._traces.values() if t.model_id == model_id]
        return sorted(traces, key=lambda t: t.timestamp, reverse=True)[:limit]
    
    # Compliance Report Methods
    def store_compliance_report(self, report: ComplianceReport) -> ComplianceReport:
        """Store a compliance report."""
        with self._lock:
            self._compliance_reports[report.report_id] = report
        return report
    
    def get_compliance_report(self, report_id: str) -> Optional[ComplianceReport]:
        """Get compliance report by ID."""
        return self._compliance_reports.get(report_id)
    
    def get_recent_reports(self, limit: int = 50) -> List[ComplianceReport]:
        """Get recent compliance reports."""
        reports = list(self._compliance_reports.values())
        return sorted(reports, key=lambda r: r.created_at, reverse=True)[:limit]
    
    # Bias Analysis Methods
    def store_bias_analysis(self, analysis: BiasAnalysis) -> BiasAnalysis:
        """Store a bias analysis."""
        with self._lock:
            self._bias_analyses[analysis.analysis_id] = analysis
        return analysis
    
    def get_bias_analysis(self, analysis_id: str) -> Optional[BiasAnalysis]:
        """Get bias analysis by ID."""
        return self._bias_analyses.get(analysis_id)
    
    def get_model_bias_analyses(self, model_id: str) -> List[BiasAnalysis]:
        """Get bias analyses for a model."""
        return [b for b in self._bias_analyses.values() if b.model_id == model_id]
    
    def get_recent_bias_analyses(self, limit: int = 50) -> List[BiasAnalysis]:
        """Get recent bias analyses."""
        analyses = list(self._bias_analyses.values())
        return sorted(analyses, key=lambda a: a.analyzed_at, reverse=True)[:limit]
    
    # Model Audit Methods
    def store_audit(self, audit: ModelAudit) -> ModelAudit:
        """Store a model audit."""
        with self._lock:
            self._audits[audit.audit_id] = audit
        return audit
    
    def get_audit(self, audit_id: str) -> Optional[ModelAudit]:
        """Get audit by ID."""
        return self._audits.get(audit_id)
    
    def get_model_audits(self, model_id: str) -> List[ModelAudit]:
        """Get audits for a model."""
        return [a for a in self._audits.values() if a.model_id == model_id]
    
    # Counterfactual Methods
    def store_counterfactual(self, cf: CounterfactualExplanation) -> CounterfactualExplanation:
        """Store a counterfactual explanation."""
        with self._lock:
            self._counterfactuals[cf.cf_id] = cf
        return cf
    
    def get_counterfactual(self, cf_id: str) -> Optional[CounterfactualExplanation]:
        """Get counterfactual by ID."""
        return self._counterfactuals.get(cf_id)
    
    def get_decision_counterfactuals(self, decision_id: str) -> List[CounterfactualExplanation]:
        """Get counterfactuals for a decision."""
        return [c for c in self._counterfactuals.values() if c.decision_id == decision_id]
    
    # Adverse Action Methods
    def store_adverse_action(self, notice: AdverseActionNotice) -> AdverseActionNotice:
        """Store an adverse action notice."""
        with self._lock:
            self._adverse_actions[notice.notice_id] = notice
        return notice
    
    def get_adverse_action(self, notice_id: str) -> Optional[AdverseActionNotice]:
        """Get adverse action by ID."""
        return self._adverse_actions.get(notice_id)
    
    def get_decision_adverse_action(self, decision_id: str) -> Optional[AdverseActionNotice]:
        """Get adverse action for a decision."""
        for notice in self._adverse_actions.values():
            if notice.decision_id == decision_id:
                return notice
        return None
    
    # Metrics History
    def store_metrics(self, metrics: Dict[str, Any]) -> None:
        """Store metrics entry."""
        with self._lock:
            metrics["timestamp"] = datetime.now(timezone.utc)
            self._metrics_history.append(metrics)
    
    def get_metrics_history(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get metrics history."""
        return list(self._metrics_history)[-limit:]
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "explanations_stored": len(self._explanations),
            "traces_stored": len(self._traces),
            "compliance_reports": len(self._compliance_reports),
            "bias_analyses": len(self._bias_analyses),
            "model_audits": len(self._audits),
            "counterfactuals": len(self._counterfactuals),
            "adverse_actions": len(self._adverse_actions),
            "metrics_history": len(self._metrics_history),
        }


# Global singleton
_xai_store: Optional[ExplainableAIStore] = None


def get_xai_store() -> ExplainableAIStore:
    """Get or create the singleton XAI store instance."""
    global _xai_store
    
    if _xai_store is None:
        _xai_store = ExplainableAIStore()
    return _xai_store