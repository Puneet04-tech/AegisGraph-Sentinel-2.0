"""
API routes for AegisGraph Sentinel Omega Platform.

Provides endpoints for unified platform access and cross-layer intelligence.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..security import require_api_key, Role, require_role


router = APIRouter(prefix="/api/v1/omega", tags=["Omega Platform"])


def get_omega_platform():
    from src.omega_platform import get_omega_platform, initialize_omega
    omega = get_omega_platform()
    if not omega._initialized:
        initialize_omega()
    return omega


# Endpoints
@router.get("/status")
async def get_omega_status():
    """Get Omega platform status."""
    omega = get_omega_platform()
    return omega.get_status()


@router.get("/dashboard")
async def get_omega_dashboard():
    """Get unified Omega dashboard."""
    omega = get_omega_platform()
    dashboard = omega.get_unified_dashboard()
    return {
        "dashboard_id": dashboard.dashboard_id,
        "generated_at": dashboard.generated_at.isoformat(),
        "overall_status": dashboard.overall_status.value,
        "total_threats": dashboard.total_threats,
        "active_defenses": dashboard.active_defenses,
        "compliance_score": dashboard.compliance_score,
        "fraud_risk_score": dashboard.fraud_risk_score,
        "threat_level": dashboard.threat_level,
        "components": dashboard.components,
        "recent_events": dashboard.recent_events,
        "recommendations": dashboard.recommendations,
    }


@router.get("/capabilities")
async def get_omega_capabilities():
    """Get Omega platform capabilities by layer."""
    omega = get_omega_platform()
    return omega.get_capabilities()


@router.get("/layers")
async def list_intelligence_layers():
    """List all intelligence layers."""
    from src.omega_platform import IntelligenceLayer
    return {
        "layers": [
            {
                "name": layer.value,
                "description": _get_layer_description(layer),
            }
            for layer in IntelligenceLayer
        ]
    }


def _get_layer_description(layer) -> str:
    """Get description for an intelligence layer."""
    descriptions = {
        "FRAUD": "Real-time fraud detection and prevention",
        "THREAT": "Threat actor and campaign intelligence",
        "COMPLIANCE": "Regulatory compliance monitoring",
        "DEFENSE": "Autonomous defense and self-healing",
        "PREDICTIVE": "Fraud forecasting and risk prediction",
        "REGULATORY": "Regulatory change tracking",
        "GOVERNANCE": "Executive oversight and reporting",
        "DIGITAL_TWIN": "Environment simulation and testing",
    }
    return descriptions.get(layer.value, "")


@router.post("/analyze/{entity_id}")
async def cross_layer_analysis(
    entity_id: str,
    layers: Optional[List[str]] = Query(None),
):
    """Perform cross-layer analysis for an entity."""
    omega = get_omega_platform()
    
    layer_enums = None
    if layers:
        from src.omega_platform import IntelligenceLayer
        try:
            layer_enums = [IntelligenceLayer(l) for l in layers]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid layer: {str(e)}")
    
    analysis = omega.analyze_cross_layer(entity_id, layer_enums)
    
    return {
        "analysis_id": analysis.analysis_id,
        "title": analysis.title,
        "layers_analyzed": [l.value for l in analysis.layers_analyzed],
        "findings": analysis.findings,
        "risk_score": analysis.risk_score,
        "recommended_actions": analysis.recommended_actions,
        "generated_at": analysis.generated_at.isoformat(),
    }


@router.post("/initialize")
async def initialize_platform():
    """Initialize the Omega platform."""
    from src.omega_platform import initialize_omega
    result = initialize_omega()
    return result


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    omega = get_omega_platform()
    status = omega.get_status()
    
    return {
        "status": "healthy" if status["initialized"] else "initializing",
        "components_healthy": status["active_components"],
        "total_components": status["total_components"],
    }