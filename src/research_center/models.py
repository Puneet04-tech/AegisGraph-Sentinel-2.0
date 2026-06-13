"""
Fraud Intelligence Research Center - Data Models

Research and experimentation platform for advanced fraud intelligence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class ProjectStatus(str, Enum):
    """Project status."""
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


class ExperimentStatus(str, Enum):
    """Experiment status."""
    PROPOSED = "PROPOSED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ResearchProject(BaseModel):
    """Research project."""
    project_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    hypothesis: str
    status: ProjectStatus = ProjectStatus.DRAFT
    owner: str = ""
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Experiment(BaseModel):
    """Research experiment."""
    experiment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    name: str
    description: str
    status: ExperimentStatus = ExperimentStatus.PROPOSED
    config: Dict[str, Any] = Field(default_factory=dict)
    results: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class SimulationScenario(BaseModel):
    """Fraud simulation scenario."""
    scenario_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    attack_type: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    expected_outcome: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BehaviorProfile(BaseModel):
    """Behavior analytics profile."""
    profile_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str
    entity_id: str
    normal_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    anomaly_indicators: List[str] = Field(default_factory=list)
    risk_factors: Dict[str, float] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatPattern(BaseModel):
    """Threat pattern."""
    pattern_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    category: str
    description: str
    indicators: List[str] = Field(default_factory=list)
    severity: str = "MEDIUM"
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: Optional[datetime] = None


class ResearchFinding(BaseModel):
    """Research finding."""
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    title: str
    description: str
    confidence: float = 0.0
    impact: str = "MEDIUM"
    recommendations: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ResearchMetrics(BaseModel):
    """Research metrics."""
    total_projects: int = 0
    active_projects: int = 0
    total_experiments: int = 0
    completed_experiments: int = 0
    threat_patterns_identified: int = 0
    simulations_run: int = 0
