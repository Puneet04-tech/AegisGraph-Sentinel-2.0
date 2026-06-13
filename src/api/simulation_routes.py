"""
Threat Simulation Environment API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.threat_simulation import (
    ThreatSimulator,
    get_threat_simulator,
    AttackType,
)


router = APIRouter(prefix="/api/v1/simulation", tags=["simulation"])


class StartSimulationRequest(BaseModel):
    """Request to start a simulation."""
    scenario_id: str
    actor_id: str


class CompleteSimulationRequest(BaseModel):
    """Request to complete a simulation."""
    results: Optional[Dict[str, Any]] = None


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
        "module": "threat_simulation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/start")
async def start_simulation(
    request: StartSimulationRequest,
    api_key: str = Header(None),
):
    """Start a simulation run."""
    verify_api_key(api_key)
    simulator = get_threat_simulator()
    
    try:
        run_id = simulator.start_simulation(
            scenario_id=request.scenario_id,
            actor_id=request.actor_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return {
        "run_id": run_id,
        "status": "running",
    }


@router.post("/complete/{run_id}")
async def complete_simulation(
    run_id: str,
    request: CompleteSimulationRequest,
    api_key: str = Header(None),
):
    """Complete a simulation run."""
    verify_api_key(api_key)
    simulator = get_threat_simulator()
    
    success = simulator.complete_simulation(
        run_id=run_id,
        results=request.results,
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Run not found")
    
    return {"status": "completed"}


@router.get("/results/{run_id}")
async def get_results(
    run_id: str,
    api_key: str = Header(None),
):
    """Get simulation results."""
    verify_api_key(api_key)
    simulator = get_threat_simulator()
    
    run = simulator.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    return {"run": run.to_dict()}


@router.get("/runs")
async def list_runs(
    scenario_id: Optional[str] = None,
    api_key: str = Header(None),
):
    """List simulation runs."""
    verify_api_key(api_key)
    simulator = get_threat_simulator()
    
    if scenario_id:
        runs = simulator.get_runs_by_scenario(scenario_id)
    else:
        runs = list(simulator.runs.values())
    
    return {
        "count": len(runs),
        "runs": [r.to_dict() for r in runs],
    }


@router.get("/analytics/{run_id}")
async def get_analytics(
    run_id: str,
    api_key: str = Header(None),
):
    """Get simulation analytics."""
    verify_api_key(api_key)
    simulator = get_threat_simulator()
    
    analytics = simulator.simulator.simulator.evaluate_threat(run_id)
    
    return {"analytics": analytics.to_dict()}


@router.get("/evaluations")
async def list_evaluations(api_key: str = Header(None)):
    """List all threat evaluations."""
    verify_api_key(api_key)
    simulator = get_threat_simulator()
    
    from src.threat_simulation import SimulationAnalytics
    analytics = SimulationAnalytics(simulator)
    
    return analytics.get_summary_report()


@router.get("/actors")
async def list_actors(api_key: str = Header(None)):
    """List threat actors."""
    verify_api_key(api_key)
    simulator = get_threat_simulator()
    
    actors = list(simulator.adversary_engine.actors.values())
    
    return {
        "count": len(actors),
        "actors": [a.to_dict() for a in actors],
    }


@router.get("/scenarios")
async def list_scenarios(api_key: str = Header(None)):
    """List attack scenarios."""
    verify_api_key(api_key)
    simulator = get_threat_simulator()
    
    scenarios = list(simulator.scenario_builder.scenarios.values())
    
    return {
        "count": len(scenarios),
        "scenarios": [s.to_dict() for s in scenarios],
    }