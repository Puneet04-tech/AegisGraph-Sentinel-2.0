"""
Security Digital Twin Store.

Storage layer for digital twin components.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AttackPath,
    AuditEvent,
    DigitalTwinAsset,
    FraudSimulation,
    ImpactAssessment,
    RiskForecast,
    SimulationScenario,
    SimulationStatus,
    SimulationType,
    ThreatSimulation,
)


class DigitalTwinStore:
    """Store for security digital twin."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._assets: Dict[str, DigitalTwinAsset] = {}
        self._scenarios: Dict[str, SimulationScenario] = {}
        self._threat_simulations: Dict[str, ThreatSimulation] = {}
        self._fraud_simulations: Dict[str, FraudSimulation] = {}
        self._attack_paths: Dict[str, AttackPath] = {}
        self._forecasts: Dict[str, RiskForecast] = {}
        self._assessments: Dict[str, ImpactAssessment] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def add_asset(self, asset: DigitalTwinAsset) -> None:
        """Add an asset."""
        with self._lock:
            self._assets[asset.asset_id] = asset

    def get_asset(self, asset_id: str) -> Optional[DigitalTwinAsset]:
        """Get an asset."""
        return self._assets.get(asset_id)

    def get_assets_by_type(self, asset_type: str) -> List[DigitalTwinAsset]:
        """Get assets by type."""
        from .models import AssetType
        type_enum = AssetType(asset_type)
        return [a for a in self._assets.values() if a.asset_type == type_enum]

    def add_scenario(self, scenario: SimulationScenario) -> None:
        """Add a scenario."""
        with self._lock:
            self._scenarios[scenario.scenario_id] = scenario

    def get_scenario(self, scenario_id: str) -> Optional[SimulationScenario]:
        """Get a scenario."""
        return self._scenarios.get(scenario_id)

    def get_scenarios_by_type(
        self,
        sim_type: SimulationType,
    ) -> List[SimulationScenario]:
        """Get scenarios by type."""
        return [s for s in self._scenarios.values() if s.simulation_type == sim_type]

    def add_threat_simulation(self, simulation: ThreatSimulation) -> None:
        """Add a threat simulation."""
        with self._lock:
            self._threat_simulations[simulation.simulation_id] = simulation

    def get_threat_simulation(
        self,
        simulation_id: str,
    ) -> Optional[ThreatSimulation]:
        """Get a threat simulation."""
        return self._threat_simulations.get(simulation_id)

    def add_fraud_simulation(self, simulation: FraudSimulation) -> None:
        """Add a fraud simulation."""
        with self._lock:
            self._fraud_simulations[simulation.simulation_id] = simulation

    def get_fraud_simulation(
        self,
        simulation_id: str,
    ) -> Optional[FraudSimulation]:
        """Get a fraud simulation."""
        return self._fraud_simulations.get(simulation_id)

    def add_attack_path(self, path: AttackPath) -> None:
        """Add an attack path."""
        with self._lock:
            self._attack_paths[path.path_id] = path

    def get_attack_path(self, path_id: str) -> Optional[AttackPath]:
        """Get an attack path."""
        return self._attack_paths.get(path_id)

    def store_forecast(self, forecast: RiskForecast) -> None:
        """Store a forecast."""
        with self._lock:
            self._forecasts[forecast.forecast_id] = forecast

    def get_forecast(self, forecast_id: str) -> Optional[RiskForecast]:
        """Get a forecast."""
        return self._forecasts.get(forecast_id)

    def add_assessment(self, assessment: ImpactAssessment) -> None:
        """Add an assessment."""
        with self._lock:
            self._assessments[assessment.assessment_id] = assessment

    def get_assessment(self, assessment_id: str) -> Optional[ImpactAssessment]:
        """Get an assessment."""
        return self._assessments.get(assessment_id)

    def log_audit(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{len(self._audit_log) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
        )
        with self._lock:
            self._audit_log.append(event)

    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get audit log."""
        return self._audit_log[-limit:]

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get dashboard metrics."""
        return {
            "total_assets": len(self._assets),
            "total_scenarios": len(self._scenarios),
            "threat_simulations": len(self._threat_simulations),
            "fraud_simulations": len(self._fraud_simulations),
            "attack_paths": len(self._attack_paths),
            "forecasts": len(self._forecasts),
            "assessments": len(self._assessments),
        }

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._assets.clear()
            self._scenarios.clear()
            self._threat_simulations.clear()
            self._fraud_simulations.clear()
            self._attack_paths.clear()
            self._forecasts.clear()
            self._assessments.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[DigitalTwinStore] = None
_store_lock = threading.Lock()


def get_twin_store() -> DigitalTwinStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = DigitalTwinStore()
    return _store


def reset_twin_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None