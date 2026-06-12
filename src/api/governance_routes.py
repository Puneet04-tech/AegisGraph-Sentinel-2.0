"""
AI Governance API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.ai_governance import (
    ModelRegistry,
    get_model_registry,
    AIGovernanceEngine,
    get_governance_engine,
    ModelStatus,
    ModelRisk,
    DriftType,
    BiasMetric,
)


router = APIRouter(prefix="/api/v1/governance", tags=["governance"])


class ModelRegisterRequest(BaseModel):
    """Request to register a model."""
    name: str
    version: str
    model_type: str
    framework: str = ""
    owner: str = ""
    description: str = ""
    risk_level: str = "MEDIUM"


class ModelUpdateRequest(BaseModel):
    """Request to update a model."""
    status: Optional[str] = None
    metrics: Optional[Dict[str, float]] = None


class DriftDetectRequest(BaseModel):
    """Request to detect drift."""
    current_data: List[Dict[str, Any]]
    baseline_data: List[Dict[str, Any]]


class BiasDetectRequest(BaseModel):
    """Request to detect bias."""
    predictions: List[Dict[str, Any]]
    protected_attributes: List[str]


class ExplainRequest(BaseModel):
    """Request to explain a prediction."""
    prediction_id: str
    input_features: Dict[str, Any]


class AuditActionRequest(BaseModel):
    """Request to log an audit action."""
    model_id: str
    action: str
    user: str
    details: Optional[Dict[str, Any]] = None


def verify_api_key(x_api_key: str = Header(None)) -> str:
    """Verify API key."""
    if x_api_key != "SUPER_ADMIN":
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "module": "ai_governance",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/models")
async def list_models(
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    api_key: str = Header(None),
):
    """List all models in the registry."""
    verify_api_key(api_key)
    registry = get_model_registry()
    
    status_enum = ModelStatus(status) if status else None
    risk_enum = ModelRisk(risk_level) if risk_level else None
    
    models = registry.list_models(status=status_enum, risk_level=risk_enum)
    
    return {
        "count": len(models),
        "models": [m.to_dict() for m in models],
    }


@router.post("/models")
async def register_model(
    request: ModelRegisterRequest,
    api_key: str = Header(None),
):
    """Register a new model."""
    verify_api_key(api_key)
    registry = get_model_registry()
    
    risk_enum = ModelRisk(request.risk_level)
    
    model_id = registry.register_model(
        name=request.name,
        version=request.version,
        model_type=request.model_type,
        framework=request.framework,
        owner=request.owner,
        description=request.description,
        risk_level=risk_enum,
    )
    
    return {
        "model_id": model_id,
        "status": "registered",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/models/{model_id}")
async def get_model(
    model_id: str,
    api_key: str = Header(None),
):
    """Get a model by ID."""
    verify_api_key(api_key)
    registry = get_model_registry()
    
    model = registry.get_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    
    return {"model": model.to_dict()}


@router.patch("/models/{model_id}")
async def update_model(
    model_id: str,
    request: ModelUpdateRequest,
    api_key: str = Header(None),
):
    """Update a model."""
    verify_api_key(api_key)
    registry = get_model_registry()
    
    status_enum = ModelStatus(request.status) if request.status else None
    
    success = registry.update_model(
        model_id=model_id,
        status=status_enum,
        metrics=request.metrics,
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Model not found")
    
    return {"status": "updated"}


@router.delete("/models/{model_id}")
async def deprecate_model(
    model_id: str,
    api_key: str = Header(None),
):
    """Deprecate a model."""
    verify_api_key(api_key)
    registry = get_model_registry()
    
    success = registry.deprecate_model(model_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Model not found")
    
    return {"status": "deprecated"}


@router.get("/models/{model_id}/versions")
async def get_model_versions(
    model_id: str,
    api_key: str = Header(None),
):
    """Get all versions of a model."""
    verify_api_key(api_key)
    registry = get_model_registry()
    
    model = registry.get_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    
    versions = registry.get_model_versions(model.name)
    
    return {
        "model_name": model.name,
        "versions": [v.to_dict() for v in versions],
    }


@router.post("/drift/detect")
async def detect_drift(
    model_id: str,
    request: DriftDetectRequest,
    api_key: str = Header(None),
):
    """Detect drift for a model."""
    verify_api_key(api_key)
    governance = get_governance_engine()
    
    drift = governance.drift_engine.detect_drift(
        model_id=model_id,
        current_data=request.current_data,
        baseline_data=request.baseline_data,
    )
    
    return {"drift": drift.to_dict()}


@router.get("/models/{model_id}/drift")
async def get_drift_history(
    model_id: str,
    api_key: str = Header(None),
):
    """Get drift history for a model."""
    verify_api_key(api_key)
    governance = get_governance_engine()
    
    history = governance.drift_engine.get_drift_history(model_id)
    
    return {
        "model_id": model_id,
        "drift_count": len(history),
        "drifts": [d.to_dict() for d in history],
    }


@router.post("/bias/detect")
async def detect_bias(
    model_id: str,
    request: BiasDetectRequest,
    api_key: str = Header(None),
):
    """Detect bias in a model."""
    verify_api_key(api_key)
    governance = get_governance_engine()
    
    reports = governance.bias_engine.detect_bias(
        model_id=model_id,
        predictions=request.predictions,
        protected_attributes=request.protected_attributes,
    )
    
    return {
        "model_id": model_id,
        "reports": [r.to_dict() for r in reports],
    }


@router.get("/models/{model_id}/bias")
async def get_bias_reports(
    model_id: str,
    api_key: str = Header(None),
):
    """Get bias reports for a model."""
    verify_api_key(api_key)
    governance = get_governance_engine()
    
    reports = governance.bias_engine.get_bias_reports(model_id)
    
    return {
        "model_id": model_id,
        "report_count": len(reports),
        "reports": [r.to_dict() for r in reports],
    }


@router.post("/explain")
async def explain_prediction(
    model_id: str,
    request: ExplainRequest,
    api_key: str = Header(None),
):
    """Generate explanation for a prediction."""
    verify_api_key(api_key)
    governance = get_governance_engine()
    
    explanation = governance.explainability_engine.explain_prediction(
        model_id=model_id,
        prediction_id=request.prediction_id,
        input_features=request.input_features,
    )
    
    return {"explanation": explanation.to_dict()}


@router.post("/audit")
async def log_audit_action(
    request: AuditActionRequest,
    api_key: str = Header(None),
):
    """Log an audit action."""
    verify_api_key(api_key)
    governance = get_governance_engine()
    
    record = governance.log_action(
        model_id=request.model_id,
        action=request.action,
        user=request.user,
        details=request.details,
    )
    
    return {
        "audit_id": record.audit_id,
        "status": "logged",
    }


@router.get("/audit")
async def get_audit_log(
    model_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    api_key: str = Header(None),
):
    """Get audit log."""
    verify_api_key(api_key)
    governance = get_governance_engine()
    
    entries = governance.get_audit_log(model_id=model_id, limit=limit)
    
    return {
        "count": len(entries),
        "entries": [e.to_dict() for e in entries],
    }


@router.get("/models/{model_id}/compliance")
async def get_compliance_status(
    model_id: str,
    api_key: str = Header(None),
):
    """Get compliance status for a model."""
    verify_api_key(api_key)
    governance = get_governance_engine()
    
    status = governance.get_compliance_status(model_id)
    
    return status