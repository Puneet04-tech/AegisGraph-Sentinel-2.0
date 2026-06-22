"""
Threat Simulation Environment API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel, Field, field_validator

from src.api.security import verify_api_key
from src.threat_simulation import (
    ThreatSimulator,
    get_threat_simulator,
    AttackType,
)


router = APIRouter(prefix="/api/v1/simulation", tags=["simulation"])


class SimulationParameters(BaseModel):
    """Validated simulation scenario parameters."""
    transaction_amount: Optional[float] = Field(
        default=None, ge=0.01, le=1_000_000_000.0,
        description="Transaction amount in USD (0.01 to 1e9)",
    )
    account_id: Optional[str] = Field(
        default=None, min_length=1, max_length=64,
        pattern=r"^[A-Za-z0-9_\-\.]+$",
        description="Account identifier (alphanumeric, underscore, hyphen, dot)",
    )
    timestamp: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp (e.g., 2026-06-21T12:00:00Z)",
    )

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            raise ValueError(
                "timestamp must be a valid ISO-8601 string "
                "(e.g., 2026-06-21T12:00:00Z)"
            )
        return v


class StartSimulationRequest(BaseModel):
    """Request to start a simulation."""
    scenario_id: str = Field(..., min_length=1, max_length=128,
                             description="Non-empty scenario identifier")
    actor_id: str = Field(..., min_length=1, max_length=128,
                          description="Non-empty threat actor identifier")
    parameters: Optional[SimulationParameters] = None


class CompleteSimulationRequest(BaseModel):
    """Request to complete a simulation."""
    results: Optional[Dict[str, Any]] = None


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
    scenario_id: Optional[str] = Query(default=None, min_length=1, max_length=128, description="Filter by scenario ID"),
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