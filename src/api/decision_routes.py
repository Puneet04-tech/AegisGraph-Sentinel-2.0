"""
AI Decision Intelligence Fabric API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from src.api.security import Role, require_role
from src.decision_fabric import (
    DecisionEngine,
    get_decision_engine,
    DecisionType,
    DecisionStatus,
)


router = APIRouter(prefix="/api/v1/decision", tags=["decision"])


class EvaluateRequest(BaseModel):
    """Request to evaluate a decision."""
    decision_type: str
    context: Dict[str, Any]
    decided_by: str = "SYSTEM"


class AuditRequest(BaseModel):
    """Request to log an audit."""
    decision_id: str
    action: str
    user: str
    details: Optional[Dict[str, Any]] = None




@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "module": "decision_fabric",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/evaluate", dependencies=[Depends(require_role(Role.SUPER_ADMIN))])
async def evaluate_decision(
    request: EvaluateRequest,
):
    """Evaluate a decision."""
    engine = get_decision_engine()
    
    try:
        dtype = DecisionType(request.decision_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid decision type")
    
    decision = engine.evaluate(
        decision_type=dtype,
        context=request.context,
        decided_by=request.decided_by,
    )
    
    return {"decision": decision.to_dict()}


@router.get("/history", dependencies=[Depends(require_role(Role.SUPER_ADMIN))])
async def get_decision_history(
    decision_type: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Get decision history."""
    engine = get_decision_engine()
    
    dtype = None
    if decision_type:
        try:
            dtype = DecisionType(decision_type)
        except ValueError:
            pass
    
    decisions = engine.get_decision_history(decision_type=dtype, limit=limit)
    
    return {
        "count": len(decisions),
        "decisions": [d.to_dict() for d in decisions],
    }


@router.get("/explain/{decision_id}", dependencies=[Depends(require_role(Role.SUPER_ADMIN))])
async def explain_decision(
    decision_id: str,
):
    """Get explanation for a decision."""
    engine = get_decision_engine()
    
    explanation = engine.explain_decision(decision_id)
    if not explanation:
        raise HTTPException(status_code=404, detail="Decision not found")
    
    return {"explanation": explanation.to_dict()}


@router.get("/recommend", dependencies=[Depends(require_role(Role.SUPER_ADMIN))])
async def get_recommendations(
    context: Dict[str, Any],
    decision_type: str = Query(...),
):
    """Get decision recommendations."""
    engine = get_decision_engine()
    
    try:
        dtype = DecisionType(decision_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid decision type")
    
    reasoning_result = engine.reasoning.evaluate(context, dtype)
    
    recommendations = []
    if reasoning_result["confidence"] < 0.7:
        recommendations.append("Escalate for human review")
    if reasoning_result["risk_indicators"] > 2:
        recommendations.append("Apply additional verification")
    
    return {
        "recommendations": recommendations,
        "confidence": reasoning_result["confidence"],
        "factors": reasoning_result["factors"],
    }


@router.post("/audit", dependencies=[Depends(require_role(Role.SUPER_ADMIN))])
async def log_audit(
    request: AuditRequest,
):
    """Log a decision audit."""
    engine = get_decision_engine()
    
    audit = engine.log_audit(
        decision_id=request.decision_id,
        action=request.action,
        user=request.user,
        details=request.details,
    )
    
    return {
        "audit_id": audit.audit_id,
        "status": "logged",
    }


@router.get("/audit", dependencies=[Depends(require_role(Role.SUPER_ADMIN))])
async def get_audit_log(
    decision_id: Optional[str] = None,
):
    """Get audit log."""
    engine = get_decision_engine()
    
    log = engine.get_audit_log(decision_id=decision_id)
    
    return {
        "count": len(log),
        "entries": [a.to_dict() for a in log],
    }


@router.get("/governance/stats", dependencies=[Depends(require_role(Role.SUPER_ADMIN))])
async def get_governance_stats():
    """Get governance statistics."""
    engine = get_decision_engine()
    
    decisions = list(engine.decisions.values())
    
    status_counts = {}
    type_counts = {}
    
    for d in decisions:
        status_counts[d.status.value] = status_counts.get(d.status.value, 0) + 1
        type_counts[d.decision_type.value] = type_counts.get(d.decision_type.value, 0) + 1
    
    return {
        "total_decisions": len(decisions),
        "by_status": status_counts,
        "by_type": type_counts,
        "audit_entries": len(engine.audit_log),
    }