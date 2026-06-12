"""
API routes for Regulatory Intelligence & Compliance Fabric.

Provides endpoints for compliance monitoring, assessment, and reporting.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..security import require_api_key, Role, require_role


router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])


# Request/Response Models
class RegulationCreate(BaseModel):
    domain: str
    name: str
    version: str = "1.0"
    description: str = ""
    requirements: List[dict] = []


class ControlCreate(BaseModel):
    control_name: str
    control_number: Optional[str] = None
    description: str = ""
    category: str = ""
    implementation: str = ""
    owner: str = ""


class AssessmentRequest(BaseModel):
    regulation_id: str
    scope: List[str] = []


class EvidenceCollectionRequest(BaseModel):
    control_id: str
    evidence_type: str
    description: str = ""


class PolicyMappingRequest(BaseModel):
    control_id: str
    regulation_id: str
    requirement_id: Optional[str] = None
    mapping_type: str = "DIRECT"
    justification: str = ""


# Store dependency
def get_compliance_store():
    from src.regulatory_fabric import get_compliance_store
    return get_compliance_store()


def get_intelligence_engine():
    from src.regulatory_fabric import get_intelligence_engine
    return get_intelligence_engine()


def get_dashboard_service():
    from src.regulatory_fabric import get_dashboard_service
    return get_dashboard_service()


# Endpoints
@router.get("/regulations")
async def list_regulations(
    domain: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    store=Depends(get_compliance_store),
):
    """List all regulations."""
    regulations = store.list_regulations(domain=domain, status=status)
    return {"regulations": regulations, "count": len(regulations)}


@router.post("/regulations")
async def create_regulation(
    regulation: RegulationCreate,
    store=Depends(get_compliance_store),
):
    """Create a new regulation."""
    reg_data = {
        "domain": regulation.domain,
        "name": regulation.name,
        "version": regulation.version,
        "description": regulation.description,
        "requirements": regulation.requirements,
    }
    reg_id = store.add_regulation(reg_data)
    return {"regulation_id": reg_id}


@router.get("/regulations/{regulation_id}")
async def get_regulation(
    regulation_id: str,
    store=Depends(get_compliance_store),
):
    """Get a specific regulation."""
    regulation = store.get_regulation(regulation_id)
    if not regulation:
        raise HTTPException(status_code=404, detail="Regulation not found")
    return regulation


@router.get("/controls")
async def list_controls(
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    store=Depends(get_compliance_store),
):
    """List all controls."""
    controls = store.list_controls(status=status, category=category)
    return {"controls": controls, "count": len(controls)}


@router.post("/controls")
async def create_control(
    control: ControlCreate,
    store=Depends(get_compliance_store),
):
    """Create a new control."""
    ctrl_data = {
        "control_name": control.control_name,
        "control_number": control.control_number,
        "description": control.description,
        "category": control.category,
        "implementation": control.implementation,
        "owner": control.owner,
    }
    ctrl_id = store.add_control(ctrl_data)
    return {"control_id": ctrl_id}


@router.get("/controls/{control_id}")
async def get_control(
    control_id: str,
    store=Depends(get_compliance_store),
):
    """Get a specific control."""
    control = store.get_control(control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    return control


@router.post("/mappings")
async def create_control_mapping(
    mapping: PolicyMappingRequest,
    store=Depends(get_compliance_store),
):
    """Create a control-regulation mapping."""
    from src.regulatory_fabric import get_policy_mapper
    mapper = get_policy_mapper()
    
    result = mapper.map_control_to_requirement(
        control_id=mapping.control_id,
        regulation_id=mapping.regulation_id,
        requirement_id=mapping.requirement_id,
        mapping_type=mapping.mapping_type,
        justification=mapping.justification,
    )
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return result


@router.get("/assessments")
async def list_assessments(
    regulation_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    store=Depends(get_compliance_store),
):
    """List compliance assessments."""
    assessments = store.list_assessments(regulation_id=regulation_id, status=status)
    return {"assessments": assessments, "count": len(assessments)}


@router.post("/assess")
async def run_assessment(
    request: AssessmentRequest,
    store=Depends(get_compliance_store),
):
    """Run a compliance assessment."""
    from src.regulatory_fabric import get_audit_engine
    
    engine = get_audit_engine()
    
    # Create audit plan
    plan = engine.create_audit_plan(
        regulation_id=request.regulation_id,
        title=f"Assessment for {request.regulation_id}",
        scope=request.scope,
        start_date=datetime.now(timezone.utc),
        end_date=datetime.now(timezone.utc),
    )
    
    # Execute assessment
    result = engine.execute_audit(plan["plan_id"])
    
    return result


@router.get("/evidence")
async def list_evidence(
    control_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    store=Depends(get_compliance_store),
):
    """List audit evidence."""
    evidence = store.list_evidence(control_id=control_id, status=status)
    return {"evidence": evidence, "count": len(evidence)}


@router.post("/evidence")
async def collect_evidence(
    request: EvidenceCollectionRequest,
    store=Depends(get_compliance_store),
):
    """Collect audit evidence for a control."""
    from src.regulatory_fabric import get_evidence_collector
    
    collector = get_evidence_collector()
    
    job = collector.collect_evidence(
        control_id=request.control_id,
        evidence_type=request.evidence_type,
        description=request.description,
    )
    
    return {
        "job_id": job.job_id,
        "status": job.status,
        "evidence_id": job.evidence_id,
    }


@router.get("/dashboard")
async def get_compliance_dashboard(
    dashboard=Depends(get_dashboard_service),
):
    """Get executive compliance dashboard."""
    dashboard_data = dashboard.generate_dashboard()
    return dashboard_data.to_dict()


@router.get("/risks")
async def list_risks(
    regulation_id: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    store=Depends(get_compliance_store),
):
    """List compliance risks."""
    risks = store.list_risks(regulation_id=regulation_id, risk_level=risk_level)
    return {"risks": risks, "count": len(risks)}


@router.get("/stats")
async def get_compliance_stats(
    store=Depends(get_compliance_store),
):
    """Get compliance statistics."""
    return store.get_dashboard_stats()


from datetime import datetime, timezone