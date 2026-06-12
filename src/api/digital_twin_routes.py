"""
Digital Twin Platform API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.digital_twin import (
    DigitalTwinEngine,
    get_digital_twin_engine,
    TwinType,
    SimulationStatus,
    ScenarioType,
)


router = APIRouter(prefix="/api/v1/digital-twin", tags=["digital-twin"])


class CreateTwinRequest(BaseModel):
    """Request to create a twin."""
    name: str
    twin_type: str
    entities: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = []


class SimulationRequest(BaseModel):
    """Request to run a simulation."""
    scenario_id: str
    parameters: Optional[Dict[str, Any]] = None


class ScenarioRequest(BaseModel):
    """Request to create a scenario."""
    name: str
    description: str
    scenario_type: str
    twin_type: str
    steps: List[Dict[str, Any]]
    expected_outcomes: List[str]
    success_criteria: Optional[Dict[str, Any]] = None


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
        "module": "digital_twin",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/create")
async def create_twin(
    request: CreateTwinRequest,
    api_key: str = Header(None),
):
    """Create a digital twin."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    try:
        twin_type = TwinType(request.twin_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid twin type")
    
    twin_id = engine.create_twin(
        name=request.name,
        twin_type=twin_type,
        entities=request.entities,
        relationships=request.relationships,
    )
    
    return {
        "twin_id": twin_id,
        "status": "created",
    }


@router.get("/twins")
async def list_twins(api_key: str = Header(None)):
    """List all digital twins."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    twins = list(engine.twins.values())
    
    return {
        "count": len(twins),
        "twins": [t.to_dict() for t in twins],
    }


@router.get("/twins/{twin_id}")
async def get_twin(
    twin_id: str,
    api_key: str = Header(None),
):
    """Get a digital twin."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    twin = engine.get_twin(twin_id)
    if not twin:
        raise HTTPException(status_code=404, detail="Twin not found")
    
    return {"twin": twin.to_dict()}


@router.patch("/twins/{twin_id}")
async def update_twin(
    twin_id: str,
    entities: Optional[List[Dict[str, Any]]] = None,
    relationships: Optional[List[Dict[str, Any]]] = None,
    metrics: Optional[Dict[str, float]] = None,
    api_key: str = Header(None),
):
    """Update a digital twin."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    success = engine.update_twin(
        twin_id=twin_id,
        entities=entities,
        relationships=relationships,
        metrics=metrics,
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Twin not found")
    
    return {"status": "updated"}


@router.post("/simulate")
async def simulate(
    twin_id: str,
    request: SimulationRequest,
    api_key: str = Header(None),
):
    """Run a simulation."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    try:
        simulation_id = engine.simulate(
            twin_id=twin_id,
            scenario_id=request.scenario_id,
            parameters=request.parameters,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return {
        "simulation_id": simulation_id,
        "status": "completed",
    }


@router.get("/simulations")
async def list_simulations(
    twin_id: Optional[str] = None,
    api_key: str = Header(None),
):
    """List simulations."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    if twin_id:
        sims = engine.simulation_manager.get_simulations_by_twin(twin_id)
    else:
        sims = list(engine.simulation_manager.simulations.values())
    
    return {
        "count": len(sims),
        "simulations": [s.to_dict() for s in sims],
    }


@router.get("/simulations/{simulation_id}")
async def get_simulation(
    simulation_id: str,
    api_key: str = Header(None),
):
    """Get a simulation."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    sim = engine.simulation_manager.get_simulation(simulation_id)
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    
    return {"simulation": sim.to_dict()}


@router.post("/scenarios")
async def create_scenario(
    request: ScenarioRequest,
    api_key: str = Header(None),
):
    """Create a scenario."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    try:
        scenario_type = ScenarioType(request.scenario_type)
        twin_type = TwinType(request.twin_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid type")
    
    scenario_id = engine.scenario_builder.create_scenario(
        name=request.name,
        description=request.description,
        scenario_type=scenario_type,
        twin_type=twin_type,
        steps=request.steps,
        expected_outcomes=request.expected_outcomes,
        success_criteria=request.success_criteria,
    )
    
    return {
        "scenario_id": scenario_id,
        "status": "created",
    }


@router.get("/scenarios")
async def list_scenarios(
    scenario_type: Optional[str] = None,
    api_key: str = Header(None),
):
    """List scenarios."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    scenarios = list(engine.scenario_builder.scenarios.values())
    
    if scenario_type:
        try:
            stype = ScenarioType(scenario_type)
            scenarios = [s for s in scenarios if s.scenario_type == stype]
        except ValueError:
            pass
    
    return {
        "count": len(scenarios),
        "scenarios": [s.to_dict() for s in scenarios],
    }


@router.get("/risk")
async def analyze_risk(
    twin_id: str,
    affected_entities: List[str],
    threat_level: float = Query(default=0.5, ge=0, le=1),
    api_key: str = Header(None),
):
    """Analyze risk."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    analysis = engine.risk_analyzer.analyze(
        twin_id=twin_id,
        affected_entities=affected_entities,
        threat_level=threat_level,
    )
    
    return {"analysis": analysis.to_dict()}


@router.get("/dashboard/{twin_id}")
async def get_dashboard(
    twin_id: str,
    api_key: str = Header(None),
):
    """Get dashboard for a twin."""
    verify_api_key(api_key)
    engine = get_digital_twin_engine()
    
    dashboard = engine.get_dashboard(twin_id)
    
    return dashboard