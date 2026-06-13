"""
Explainable AI & Compliance Engine.

A production-grade XAI module for transparent, auditable,
and compliant fraud detection decisions.

Modules:
    - SHAP Explainer: SHAP value computation
    - LIME Explainer: Local interpretable explanations
    - Decision Tracer: Complete audit trail
    - Compliance Reporter: Regulatory reporting
    - Model Auditor: Model auditability
"""

from .models import (
    ExplanationType,
    ComplianceFramework,
    BiasMetric,
    ModelAuditStatus,
    FeatureImportance,
    Explanation,
    DecisionTrace,
    ComplianceReport,
    BiasAnalysis,
    ModelAudit,
    CounterfactualExplanation,
    AdverseActionNotice,
)
from .store import ExplainableAIStore, get_xai_store
from .shap_explainer import SHAPExplainer, get_shap_explainer
from .lime_explainer import LIMEExplainer, get_lime_explainer
from .decision_tracer import DecisionTracer, get_decision_tracer
from .compliance_reporter import ComplianceReporter, get_compliance_reporter
from .model_auditor import ModelAuditor, get_model_auditor

__all__ = [
    # Enums
    "ExplanationType",
    "ComplianceFramework",
    "BiasMetric",
    "ModelAuditStatus",
    # Models
    "FeatureImportance",
    "Explanation",
    "DecisionTrace",
    "ComplianceReport",
    "BiasAnalysis",
    "ModelAudit",
    "CounterfactualExplanation",
    "AdverseActionNotice",
    # Store
    "ExplainableAIStore",
    "get_xai_store",
    # Modules
    "SHAPExplainer",
    "get_shap_explainer",
    "LIMEExplainer",
    "get_lime_explainer",
    "DecisionTracer",
    "get_decision_tracer",
    "ComplianceReporter",
    "get_compliance_reporter",
    "ModelAuditor",
    "get_model_auditor",
]