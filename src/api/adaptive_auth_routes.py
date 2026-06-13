"""
Adaptive Authentication API Endpoints.

Provides endpoints for risk-based authentication, continuous authorization,
and session management.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from src.adaptive_auth import (
    AdaptiveAuthService,
    AuthenticationRequest,
    ChallengeType,
    RiskEvaluationRequest,
    get_adaptive_auth_service,
)
from src.api.security import Role, require_role

router = APIRouter(prefix="/api/v1/adaptive-auth", tags=["Adaptive Authentication"])

# Pydantic models for request/response


class RiskEvaluationRequestModel(BaseModel):
    """Request model for risk evaluation."""
    user_id: str
    session_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""
    device_fingerprint: str = ""
    location: Optional[Dict[str, Any]] = None
    action: str = ""
    resource: str = ""
    context: Dict[str, Any] = Field(default_factory=dict)


class ChallengeRequest(BaseModel):
    """Request model for initiating a challenge."""
    challenge_type: str
    metadata: Optional[Dict[str, Any]] = None


class ChallengeVerifyRequest(BaseModel):
    """Request model for verifying a challenge."""
    response: str
    context: Optional[Dict[str, Any]] = None


class PolicyCreateRequest(BaseModel):
    """Request model for creating a policy."""
    name: str
    description: str
    resource_pattern: str
    required_trust_level: str = "low"
    required_risk_level: str = "high"
    step_up_required: bool = False
    step_up_challenge_types: Optional[List[str]] = None
    action_on_violation: str = "deny"
    conditions: Optional[Dict[str, Any]] = None
    priority: int = 50


class SessionReassessRequest(BaseModel):
    """Request model for session reassessment."""
    reason: str = "user_requested"


# ========== Risk Evaluation ==========


@router.post(
    "/evaluate",
    summary="Evaluate authentication risk",
    description="Evaluate risk for a login attempt or session action",
)
async def evaluate_risk(
    request: RiskEvaluationRequestModel,
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Evaluate risk for an authentication request."""
    try:
        risk_request = RiskEvaluationRequest(
            user_id=request.user_id,
            session_id=request.session_id,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
            device_fingerprint=request.device_fingerprint,
            location=request.location,
            action=request.action,
            resource=request.resource,
            context=request.context,
        )
        
        result = await service.evaluate_risk(risk_request)
        
        return {
            "session_id": result.session_id,
            "user_id": result.user_id,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level.value,
            "signals": result.signals,
            "recommendation": result.recommendation,
            "requires_step_up": result.requires_step_up,
            "timestamp": result.timestamp.isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ========== Step-Up Authentication ==========


@router.post(
    "/challenge",
    summary="Initiate step-up authentication challenge",
    description="Start a step-up authentication challenge for a session",
)
async def initiate_challenge(
    session_id: str,
    user_id: str,
    request: ChallengeRequest,
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Initiate a step-up authentication challenge."""
    try:
        result = await service.initiate_challenge(
            session_id=session_id,
            user_id=user_id,
            challenge_type=request.challenge_type,
            metadata=request.metadata,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/verify",
    summary="Verify step-up challenge response",
    description="Verify the user's response to a step-up challenge",
)
async def verify_challenge(
    challenge_id: str,
    request: ChallengeVerifyRequest,
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Verify a step-up challenge response."""
    try:
        result = await service.verify_challenge(
            challenge_id=challenge_id,
            response=request.response,
            context=request.context,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ========== Session Management ==========


@router.get(
    "/session/{session_id}",
    summary="Get session information",
    description="Retrieve information about an active session",
)
async def get_session(
    session_id: str,
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Get session information."""
    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.post(
    "/session/reassess",
    summary="Reassess session",
    description="Trigger a reassessment of a session's trust and risk level",
)
async def reassess_session(
    session_id: str,
    request: SessionReassessRequest,
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Reassess a session."""
    try:
        result = await service.reassess_session(
            session_id=session_id,
            reason=request.reason,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== Policy Management ==========


@router.get(
    "/policies",
    summary="List authorization policies",
    description="Get all authorization policies",
)
async def list_policies(
    enabled_only: bool = Query(False, description="Only return enabled policies"),
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """List authorization policies."""
    policies = await service.get_policies()
    if enabled_only:
        policies = [p for p in policies if p.get("enabled", True)]
    return {"policies": policies, "total": len(policies)}


@router.post(
    "/policies",
    summary="Create authorization policy",
    description="Create a new authorization policy",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
async def create_policy(
    request: PolicyCreateRequest,
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Create a new authorization policy."""
    try:
        result = await service.create_policy(
            name=request.name,
            description=request.description,
            resource_pattern=request.resource_pattern,
            required_trust_level=request.required_trust_level,
            required_risk_level=request.required_risk_level,
            step_up_required=request.step_up_required,
            step_up_challenge_types=request.step_up_challenge_types,
            action_on_violation=request.action_on_violation,
            conditions=request.conditions,
            priority=request.priority,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== Audit ==========


@router.get(
    "/audit",
    summary="Query audit events",
    description="Query authentication and authorization audit events",
)
async def get_audit_events(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    start_time: Optional[str] = Query(None, description="Start time (ISO format)"),
    end_time: Optional[str] = Query(None, description="End time (ISO format)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum events to return"),
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Query audit events."""
    events = await service.get_audit_events(
        user_id=user_id,
        session_id=session_id,
        event_type=event_type,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )
    return {"events": events, "total": len(events)}


@router.get(
    "/audit/summary",
    summary="Get audit summary",
    description="Get a summary of recent audit events",
)
async def get_audit_summary(
    start_time: Optional[str] = Query(None, description="Start time (ISO format)"),
    end_time: Optional[str] = Query(None, description="End time (ISO format)"),
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Get audit summary."""
    from src.adaptive_auth import get_audit_service
    from datetime import timedelta
    
    audit_service = get_audit_service()
    
    start = datetime.fromisoformat(start_time) if start_time else datetime.utcnow() - timedelta(hours=24)
    end = datetime.fromisoformat(end_time) if end_time else datetime.utcnow()
    
    summary = audit_service.get_summary(start, end)
    
    return {
        "total_events": summary.total_events,
        "events_by_type": summary.events_by_type,
        "events_by_severity": summary.events_by_severity,
        "events_by_outcome": summary.events_by_outcome,
        "recent_events": summary.recent_events,
        "time_range": summary.time_range,
    }


# ========== Statistics ==========


@router.get(
    "/stats",
    summary="Get service statistics",
    description="Get statistics about the adaptive authentication service",
)
async def get_stats(
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Get service statistics."""
    return await service.get_stats()


@router.get(
    "/challenge-types",
    summary="Get available challenge types",
    description="Get list of available step-up authentication challenge types",
)
async def get_challenge_types(
    service: AdaptiveAuthService = Depends(get_adaptive_auth_service),
):
    """Get available challenge types."""
    from src.adaptive_auth import get_stepup_auth_service
    
    stepup_service = get_stepup_auth_service()
    return {"challenge_types": stepup_service.get_available_challenge_types()}


def register_routes(app):
    """Register adaptive auth routes with the main application."""
    app.include_router(router)