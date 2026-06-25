"""
Research Laboratory API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.api.security import verify_api_key
from src.research_lab import (
    ResearchEngine,
    get_research_engine,
    ModelType,
    ExperimentStatus,
)


router = APIRouter(prefix="/api/v1/research", tags=["research"])


class CreateExperimentRequest(BaseModel):
    """Request to create an experiment."""
    name: str
    description: str
    model_type: str
    parameters: Optional[Dict[str, Any]] = None
    created_by: str = ""


class RunExperimentRequest(BaseModel):
    """Request to run an experiment."""
    parameters: Dict[str, Any] = {}


class EvaluateModelRequest(BaseModel):
    """Request to evaluate a model."""
    model_id: str
    model_version: str
    test_results: Dict[str, Any] = {}


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "module": "research_lab",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/create")
async def create_experiment(
    request: CreateExperimentRequest,
    api_key: str = Header(None),
):
    """Create a new research experiment."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    try:
        model_type = ModelType(request.model_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid model type")
    
    experiment_id = engine.create_research(
        name=request.name,
        description=request.description,
        model_type=model_type,
        created_by=request.created_by,
    )
    
    return {
        "experiment_id": experiment_id,
        "status": "created",
    }


@router.get("/experiments")
async def list_experiments(
    status: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=100),
    api_key: str = Header(None),
):
    """List research experiments."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    experiments = list(engine.experiment_manager.experiments.values())
    
    if status:
        try:
            st = ExperimentStatus(status)
            experiments = [e for e in experiments if e.status == st]
        except ValueError:
            pass
    
    return {
        "count": len(experiments),
        "experiments": [e.to_dict() for e in experiments[:limit]],
    }


@router.get("/experiments/{experiment_id}")
async def get_experiment(
    experiment_id: str,
    api_key: str = Header(None),
):
    """Get a research experiment."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    experiment = engine.experiment_manager.get_experiment(experiment_id)
    if not experiment:
        raise HTTPException(status_code=404, detail="Experiment not found")
    
    return {"experiment": experiment.to_dict()}


@router.post("/experiments/{experiment_id}/run")
async def run_experiment(
    experiment_id: str,
    request: RunExperimentRequest,
    api_key: str = Header(None),
):
    """Run a research experiment."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    try:
        results = engine.run_experiment(
            experiment_id=experiment_id,
            parameters=request.parameters,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return {
        "experiment_id": experiment_id,
        "status": "completed",
        "results": results,
    }


@router.get("/experiments/{experiment_id}/results")
async def get_experiment_results(
    experiment_id: str,
    api_key: str = Header(None),
):
    """Get results for an experiment."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    results = engine.get_research_results(experiment_id)
    
    return results


@router.get("/benchmark")
async def list_benchmarks(
    experiment_id: Optional[str] = None,
    api_key: str = Header(None),
):
    """List benchmark results."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    if experiment_id:
        benchmarks = engine.benchmarking.get_benchmark_results(experiment_id)
    else:
        benchmarks = []
        for results in engine.benchmarking.results.values():
            benchmarks.extend(results)
    
    return {
        "count": len(benchmarks),
        "benchmarks": [b.to_dict() for b in benchmarks],
    }


@router.post("/models/evaluate")
async def evaluate_model(
    request: EvaluateModelRequest,
    api_key: str = Header(None),
):
    """Evaluate a model."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    evaluation_id = engine.evaluation_service.evaluate_model(
        model_id=request.model_id,
        model_version=request.model_version,
        test_results=request.test_results,
    )
    
    return {
        "evaluation_id": evaluation_id,
        "status": "completed",
    }


@router.get("/models/evaluations")
async def list_evaluations(
    model_id: Optional[str] = None,
    api_key: str = Header(None),
):
    """List model evaluations."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    if model_id:
        evaluations = engine.evaluation_service.get_evaluations_by_model(model_id)
    else:
        evaluations = list(engine.evaluation_service.evaluations.values())
    
    return {
        "count": len(evaluations),
        "evaluations": [e.to_dict() for e in evaluations],
    }


@router.get("/datasets")
async def list_datasets(api_key: str = Header(None)):
    """List research datasets."""
    verify_api_key(api_key)
    engine = get_research_engine()
    
    datasets = list(engine.dataset_manager.datasets.values())
    
    return {
        "count": len(datasets),
        "datasets": [d.to_dict() for d in datasets],
    }