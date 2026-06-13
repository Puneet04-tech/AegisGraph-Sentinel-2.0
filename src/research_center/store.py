"""
Fraud Intelligence Research Center Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from .models import (
    ResearchProject,
    Experiment,
    SimulationScenario,
    BehaviorProfile,
    ThreatPattern,
    ResearchFinding,
    ProjectStatus,
    ExperimentStatus,
)


class ResearchCenterStore:
    """Thread-safe storage for research center data."""

    def __init__(self):
        self._lock = Lock()
        self._projects: Dict[str, ResearchProject] = {}
        self._experiments: Dict[str, Experiment] = {}
        self._scenarios: Dict[str, SimulationScenario] = {}
        self._profiles: Dict[str, BehaviorProfile] = {}
        self._patterns: Dict[str, ThreatPattern] = {}
        self._findings: Dict[str, ResearchFinding] = {}

    def store_project(self, project: ResearchProject) -> ResearchProject:
        with self._lock:
            self._projects[project.project_id] = project
        return project

    def get_project(self, project_id: str) -> Optional[ResearchProject]:
        return self._projects.get(project_id)

    def get_all_projects(self) -> List[ResearchProject]:
        return list(self._projects.values())

    def get_projects_by_status(
        self, status: ProjectStatus
    ) -> List[ResearchProject]:
        return [p for p in self._projects.values() if p.status == status]

    def store_experiment(self, experiment: Experiment) -> Experiment:
        with self._lock:
            self._experiments[experiment.experiment_id] = experiment
        return experiment

    def get_experiment(self, experiment_id: str) -> Optional[Experiment]:
        return self._experiments.get(experiment_id)

    def get_experiments_by_project(
        self, project_id: str
    ) -> List[Experiment]:
        return [e for e in self._experiments.values() if e.project_id == project_id]

    def store_scenario(self, scenario: SimulationScenario) -> SimulationScenario:
        with self._lock:
            self._scenarios[scenario.scenario_id] = scenario
        return scenario

    def get_scenario(self, scenario_id: str) -> Optional[SimulationScenario]:
        return self._scenarios.get(scenario_id)

    def get_all_scenarios(self) -> List[SimulationScenario]:
        return list(self._scenarios.values())

    def store_profile(self, profile: BehaviorProfile) -> BehaviorProfile:
        with self._lock:
            self._profiles[profile.profile_id] = profile
        return profile

    def get_profile(self, profile_id: str) -> Optional[BehaviorProfile]:
        return self._profiles.get(profile_id)

    def get_profiles_by_entity(self, entity_id: str) -> List[BehaviorProfile]:
        return [p for p in self._profiles.values() if p.entity_id == entity_id]

    def store_pattern(self, pattern: ThreatPattern) -> ThreatPattern:
        with self._lock:
            self._patterns[pattern.pattern_id] = pattern
        return pattern

    def get_pattern(self, pattern_id: str) -> Optional[ThreatPattern]:
        return self._patterns.get(pattern_id)

    def get_all_patterns(self) -> List[ThreatPattern]:
        return list(self._patterns.values())

    def store_finding(self, finding: ResearchFinding) -> ResearchFinding:
        with self._lock:
            self._findings[finding.finding_id] = finding
        return finding

    def get_finding(self, finding_id: str) -> Optional[ResearchFinding]:
        return self._findings.get(finding_id)

    def get_findings_by_project(
        self, project_id: str
    ) -> List[ResearchFinding]:
        return [f for f in self._findings.values() if f.project_id == project_id]

    def get_metrics(self) -> Dict[str, Any]:
        projects = list(self._projects.values())
        experiments = list(self._experiments.values())
        return {
            "total_projects": len(projects),
            "active_projects": len([p for p in projects if p.status == ProjectStatus.ACTIVE]),
            "total_experiments": len(experiments),
            "completed_experiments": len([e for e in experiments if e.status == ExperimentStatus.COMPLETED]),
            "threat_patterns_identified": len(self._patterns),
            "simulations_run": len(self._scenarios),
        }


_research_center_store: Optional[ResearchCenterStore] = None
_store_lock = Lock()


def get_research_center_store() -> ResearchCenterStore:
    global _research_center_store
    with _store_lock:
        if _research_center_store is None:
            _research_center_store = ResearchCenterStore()
        return _research_center_store


def reset_research_center_store() -> None:
    global _research_center_store
    with _store_lock:
        _research_center_store = ResearchCenterStore()
