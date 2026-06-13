"""
Fraud Intelligence Research Center Service - Core business logic
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    ResearchProject,
    Experiment,
    SimulationScenario,
    BehaviorProfile,
    ThreatPattern,
    ResearchFinding,
    ResearchMetrics,
    ProjectStatus,
    ExperimentStatus,
)
from .store import get_research_center_store, ResearchCenterStore, reset_research_center_store


class ResearchCenterService:
    """Core research center service."""

    def __init__(self, store: Optional[ResearchCenterStore] = None):
        self._store = store or get_research_center_store()

    def create_project(
        self,
        name: str,
        description: str,
        hypothesis: str,
        owner: str = "",
        tags: List[str] = None,
    ) -> ResearchProject:
        """Create a research project."""
        project = ResearchProject(
            name=name,
            description=description,
            hypothesis=hypothesis,
            owner=owner,
            tags=tags or [],
        )
        self._store.store_project(project)
        return project

    def get_project(self, project_id: str) -> Optional[ResearchProject]:
        """Get project by ID."""
        return self._store.get_project(project_id)

    def get_projects(
        self, status: Optional[ProjectStatus] = None
    ) -> List[ResearchProject]:
        """Get projects."""
        if status:
            return self._store.get_projects_by_status(status)
        return self._store.get_all_projects()

    def update_project_status(
        self,
        project_id: str,
        status: ProjectStatus,
    ) -> Optional[ResearchProject]:
        """Update project status."""
        project = self._store.get_project(project_id)
        if project:
            project.status = status
            self._store.store_project(project)
        return project

    def create_experiment(
        self,
        project_id: str,
        name: str,
        description: str,
        config: Dict[str, Any] = None,
    ) -> Optional[Experiment]:
        """Create an experiment."""
        project = self._store.get_project(project_id)
        if not project:
            return None
        experiment = Experiment(
            project_id=project_id,
            name=name,
            description=description,
            config=config or {},
        )
        self._store.store_experiment(experiment)
        return experiment

    def get_experiment(self, experiment_id: str) -> Optional[Experiment]:
        """Get experiment by ID."""
        return self._store.get_experiment(experiment_id)

    def get_experiments(self, project_id: str) -> List[Experiment]:
        """Get experiments for a project."""
        return self._store.get_experiments_by_project(project_id)

    def run_experiment(
        self,
        experiment_id: str,
        results: Dict[str, Any],
    ) -> Optional[Experiment]:
        """Run an experiment."""
        experiment = self._store.get_experiment(experiment_id)
        if experiment:
            experiment.status = ExperimentStatus.RUNNING
            self._store.store_experiment(experiment)
            experiment.results = results
            experiment.status = ExperimentStatus.COMPLETED
            experiment.completed_at = datetime.now(timezone.utc)
            self._store.store_experiment(experiment)
        return experiment

    def create_scenario(
        self,
        name: str,
        description: str,
        attack_type: str,
        parameters: Dict[str, Any] = None,
    ) -> SimulationScenario:
        """Create a simulation scenario."""
        scenario = SimulationScenario(
            name=name,
            description=description,
            attack_type=attack_type,
            parameters=parameters or {},
        )
        self._store.store_scenario(scenario)
        return scenario

    def get_scenario(self, scenario_id: str) -> Optional[SimulationScenario]:
        """Get scenario by ID."""
        return self._store.get_scenario(scenario_id)

    def get_all_scenarios(self) -> List[SimulationScenario]:
        """Get all scenarios."""
        return self._store.get_all_scenarios()

    def create_profile(
        self,
        entity_type: str,
        entity_id: str,
        normal_patterns: List[Dict[str, Any]] = None,
    ) -> BehaviorProfile:
        """Create a behavior profile."""
        profile = BehaviorProfile(
            entity_type=entity_type,
            entity_id=entity_id,
            normal_patterns=normal_patterns or [],
        )
        self._store.store_profile(profile)
        return profile

    def get_profile(self, profile_id: str) -> Optional[BehaviorProfile]:
        """Get profile by ID."""
        return self._store.get_profile(profile_id)

    def get_profiles(self, entity_id: str) -> List[BehaviorProfile]:
        """Get profiles for an entity."""
        return self._store.get_profiles_by_entity(entity_id)

    def update_profile(
        self,
        profile_id: str,
        anomaly_indicators: List[str] = None,
        risk_factors: Dict[str, float] = None,
    ) -> Optional[BehaviorProfile]:
        """Update a behavior profile."""
        profile = self._store.get_profile(profile_id)
        if profile:
            if anomaly_indicators:
                profile.anomaly_indicators.extend(anomaly_indicators)
            if risk_factors:
                profile.risk_factors.update(risk_factors)
            profile.updated_at = datetime.now(timezone.utc)
            self._store.store_profile(profile)
        return profile

    def identify_threat_pattern(
        self,
        name: str,
        category: str,
        description: str,
        indicators: List[str],
        severity: str = "MEDIUM",
    ) -> ThreatPattern:
        """Identify a threat pattern."""
        pattern = ThreatPattern(
            name=name,
            category=category,
            description=description,
            indicators=indicators,
            severity=severity,
        )
        self._store.store_pattern(pattern)
        return pattern

    def get_pattern(self, pattern_id: str) -> Optional[ThreatPattern]:
        """Get threat pattern by ID."""
        return self._store.get_pattern(pattern_id)

    def get_all_patterns(self) -> List[ThreatPattern]:
        """Get all threat patterns."""
        return self._store.get_all_patterns()

    def add_finding(
        self,
        project_id: str,
        title: str,
        description: str,
        confidence: float = 0.0,
        impact: str = "MEDIUM",
    ) -> Optional[ResearchFinding]:
        """Add a research finding."""
        project = self._store.get_project(project_id)
        if not project:
            return None
        finding = ResearchFinding(
            project_id=project_id,
            title=title,
            description=description,
            confidence=confidence,
            impact=impact,
        )
        self._store.store_finding(finding)
        return finding

    def get_finding(self, finding_id: str) -> Optional[ResearchFinding]:
        """Get finding by ID."""
        return self._store.get_finding(finding_id)

    def get_findings(self, project_id: str) -> List[ResearchFinding]:
        """Get findings for a project."""
        return self._store.get_findings_by_project(project_id)

    def get_metrics(self) -> ResearchMetrics:
        """Get research metrics."""
        metrics_dict = self._store.get_metrics()
        return ResearchMetrics(**metrics_dict)

    def clear(self) -> None:
        """Clear all data."""
        reset_research_center_store()


_research_center_service: Optional[ResearchCenterService] = None


def get_research_center_service() -> ResearchCenterService:
    global _research_center_service
    if _research_center_service is None:
        _research_center_service = ResearchCenterService()
    return _research_center_service


def reset_research_center_service() -> None:
    global _research_center_service
    _research_center_service = None
    reset_research_center_store()
