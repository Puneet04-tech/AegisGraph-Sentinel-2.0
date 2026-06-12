"""
API routes for Cyber-Fraud Warfare Intelligence Platform.

Provides endpoints for threat actor analysis, campaign tracking, and strategic reporting.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..security import require_api_key, Role, require_role


router = APIRouter(prefix="/api/v1/warfare", tags=["Cyber-Fraud Warfare"])


# Request/Response Models
class ThreatActorCreate(BaseModel):
    name: str
    type: str
    sponsor: Optional[str] = None
    country: Optional[str] = None
    description: str = ""
    capabilities: List[str] = []
    primary_targets: List[str] = []


class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    target_sectors: List[str] = []
    target_regions: List[str] = []
    attack_types: List[str] = []


class RiskAssessmentRequest(BaseModel):
    entity_type: str
    entity_id: str


# Store dependency
def get_warfare_store():
    from src.cyber_fraud_warfare import get_warfare_store
    return get_warfare_store()


def get_actor_engine():
    from src.cyber_fraud_warfare import get_threat_actor_engine
    return get_threat_actor_engine()


def get_attribution_engine():
    from src.cyber_fraud_warfare import get_attribution_engine
    return get_attribution_engine()


def get_dashboard():
    from src.cyber_fraud_warfare import get_strategic_dashboard
    return get_strategic_dashboard()


# Endpoints
@router.get("/actors")
async def list_threat_actors(
    actor_type: Optional[str] = Query(None),
    sponsor: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    store=Depends(get_warfare_store),
):
    """List all threat actors."""
    actors = store.list_threat_actors(
        actor_type=actor_type,
        sponsor=sponsor,
        threat_level=threat_level,
    )
    return {"actors": actors, "count": len(actors)}


@router.post("/actors")
async def create_threat_actor(
    actor: ThreatActorCreate,
    store=Depends(get_warfare_store),
):
    """Create a new threat actor."""
    actor_data = {
        "name": actor.name,
        "type": actor.type,
        "sponsor": actor.sponsor,
        "country": actor.country,
        "description": actor.description,
        "capabilities": actor.capabilities,
        "primary_targets": actor.primary_targets,
        "threat_level": "MEDIUM",
    }
    actor_id = store.add_threat_actor(actor_data)
    return {"actor_id": actor_id}


@router.get("/actors/{actor_id}")
async def get_threat_actor(
    actor_id: str,
    store=Depends(get_warfare_store),
):
    """Get a specific threat actor."""
    actor = store.get_threat_actor(actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return actor


@router.get("/actors/{actor_id}/analysis")
async def analyze_threat_actor(
    actor_id: str,
    engine=Depends(get_actor_engine),
):
    """Analyze a threat actor."""
    try:
        analysis = engine.analyze_actor(actor_id)
        return {
            "actor_id": analysis.actor_id,
            "threat_score": analysis.threat_score,
            "activity_level": analysis.activity_level,
            "associated_campaigns": analysis.associated_campaigns,
            "detected_ttps": analysis.detected_ttps,
            "risk_factors": analysis.risk_factors,
            "recommended_posture": analysis.recommended_posture,
            "analysis_date": analysis.analysis_date.isoformat(),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/campaigns")
async def list_campaigns(
    status: Optional[str] = Query(None),
    target_sector: Optional[str] = Query(None),
    store=Depends(get_warfare_store),
):
    """List all campaigns."""
    campaigns = store.list_campaigns(
        status=status,
        target_sector=target_sector,
    )
    return {"campaigns": campaigns, "count": len(campaigns)}


@router.post("/campaigns")
async def create_campaign(
    campaign: CampaignCreate,
    store=Depends(get_warfare_store),
):
    """Create a new campaign."""
    campaign_data = {
        "name": campaign.name,
        "description": campaign.description,
        "target_sectors": campaign.target_sectors,
        "target_regions": campaign.target_regions,
        "attack_types": campaign.attack_types,
        "status": "EMERGING",
    }
    campaign_id = store.add_campaign(campaign_data)
    return {"campaign_id": campaign_id}


@router.get("/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    store=Depends(get_warfare_store),
):
    """Get a specific campaign."""
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.post("/campaigns/{campaign_id}/attribute")
async def attribute_campaign(
    campaign_id: str,
    engine=Depends(get_attribution_engine),
):
    """Attribute a campaign to threat actors."""
    try:
        result = engine.attribute_campaign(campaign_id)
        return {
            "campaign_id": result.campaign_id,
            "primary_actor_id": result.primary_actor_id,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "alternative_hypotheses": result.alternative_hypotheses,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/attack-patterns")
async def list_attack_patterns(
    category: Optional[str] = Query(None),
    store=Depends(get_warfare_store),
):
    """List attack patterns."""
    patterns = store.list_attack_patterns(category=category)
    return {"patterns": patterns, "count": len(patterns)}


@router.get("/assessments")
async def list_risk_assessments(
    store=Depends(get_warfare_store),
):
    """List risk assessments."""
    assessments = list(store.risk_assessments.values())
    return {"assessments": assessments, "count": len(assessments)}


@router.post("/assessments")
async def create_risk_assessment(
    request: RiskAssessmentRequest,
    store=Depends(get_warfare_store),
):
    """Create a risk assessment."""
    assessment_data = {
        "entity_type": request.entity_type,
        "entity_id": request.entity_id,
        "risk_score": 50.0,
        "risk_level": "MEDIUM",
    }
    assessment_id = store.add_risk_assessment(assessment_data)
    return {"assessment_id": assessment_id}


@router.get("/dashboard")
async def get_warfare_dashboard(
    dashboard=Depends(get_dashboard),
):
    """Get strategic warfare dashboard."""
    return dashboard.generate_dashboard()


@router.get("/executive-brief")
async def get_executive_brief(
    dashboard=Depends(get_dashboard),
):
    """Get executive threat briefing."""
    return dashboard.generate_executive_brief()


@router.get("/stats")
async def get_warfare_stats(
    store=Depends(get_warfare_store),
):
    """Get warfare intelligence statistics."""
    return store.get_warfare_stats()