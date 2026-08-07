"""
Health Monitor Module.

System health monitoring and component tracking.
"""

import threading
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    ComponentHealth,
    ComponentStatus,
)
from .probes import Probe, ProbeResult
from .store import ObservabilityStore, get_observability_store

logger = logging.getLogger(__name__)


class HealthMonitor:
    """Health Monitor for system component tracking.
    
    Provides:
        - Component health tracking
        - Health score calculation
        - Dependency monitoring
        - Health reporting
    """
    
    #: Consecutive failed probes before a component is reported unhealthy, so
    #: one transient blip does not flap the status.
    DEFAULT_FAILURE_THRESHOLD = 2

    def __init__(
        self,
        store: Optional[ObservabilityStore] = None,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    ):
        """Initialize the health monitor."""
        self._store = store or get_observability_store()
        self._module_id = "health_monitor"
        self._failure_threshold = max(1, int(failure_threshold))
        self._probes: Dict[str, Probe] = {}
        self._consecutive_failures: Dict[str, int] = {}
        self._probe_lock = Lock()

    def set_probe(self, component_id: str, probe: Optional[Probe]) -> None:
        """Attach (or clear) the probe used to check a component."""
        with self._probe_lock:
            if probe is None:
                self._probes.pop(component_id, None)
            else:
                self._probes[component_id] = probe

    def get_probe(self, component_id: str) -> Optional[Probe]:
        with self._probe_lock:
            return self._probes.get(component_id)
    
    def register_component(
        self,
        component_name: str,
        component_type: str,
        metadata: Dict[str, Any] = None,
        probe: Optional[Probe] = None,
    ) -> ComponentHealth:
        """Register a new component.

        A component registered without a probe reports UNKNOWN rather than a
        fabricated healthy status: not being able to check something is not
        the same as it being fine.
        """
        logger.info(f"Registering component: {component_name}")
        
        health = ComponentHealth(
            component_name=component_name,
            component_type=component_type,
            status=ComponentStatus.UNKNOWN,
            health_score=0.0,
            metadata=metadata or {},
        )
        
        self._store.store_health(health)
        if probe is not None:
            # Keyed on component_id only, matching how the store keys health
            # records, so there is one canonical identity to set and clear.
            self.set_probe(health.component_id, probe)
        return health

    def check_health(self, component_id: str) -> Dict[str, Any]:
        """Perform health check on component."""
        health = self._store.get_health(component_id)
        if not health:
            return {"error": "Component not found"}
        
        logger.info(f"Checking health of {health.component_name}")

        probe = self.get_probe(component_id)
        if probe is None:
            # Nothing to check with. Report that honestly instead of asserting
            # health on no evidence.
            health.status = ComponentStatus.UNKNOWN
            health.last_check = datetime.now(timezone.utc)
            self._store.store_health(health)
            return {
                "component_id": component_id,
                "component_name": health.component_name,
                "status": health.status.value,
                "health_score": health.health_score,
                "response_time_ms": health.response_time_ms,
                "last_check": health.last_check.isoformat(),
                "error": "no probe configured",
            }

        result = self._run_probe(probe)

        with self._probe_lock:
            if result.healthy:
                self._consecutive_failures[component_id] = 0
                failures = 0
            else:
                failures = self._consecutive_failures.get(component_id, 0) + 1
                self._consecutive_failures[component_id] = failures

        if result.healthy:
            health.status = ComponentStatus.HEALTHY
            health.health_score = (
                min(100, health.health_score + 5) if health.health_score > 0 else 100
            )
        elif failures >= self._failure_threshold:
            health.status = ComponentStatus.UNHEALTHY
            health.health_score = max(0, health.health_score - 10)
        else:
            # Below the threshold a failure is a blip, not an outage.
            health.status = ComponentStatus.DEGRADED
            health.health_score = max(0, health.health_score - 10)

        health.last_check = datetime.now(timezone.utc)
        # Measured, not invented.
        health.response_time_ms = round(result.latency_ms, 3)
        health.error_count = failures

        self._store.store_health(health)

        response = {
            "component_id": component_id,
            "component_name": health.component_name,
            "status": health.status.value,
            "health_score": health.health_score,
            "response_time_ms": health.response_time_ms,
            "last_check": health.last_check.isoformat(),
            "consecutive_failures": failures,
        }
        if result.error:
            response["error"] = result.error
        return response

    @staticmethod
    def _run_probe(probe: Probe) -> ProbeResult:
        """Invoke a probe, containing any failure it does not contain itself."""
        try:
            result = probe()
        except Exception as exc:
            return ProbeResult(healthy=False, latency_ms=0.0, error=str(exc))
        if not isinstance(result, ProbeResult):
            return ProbeResult(healthy=bool(result), latency_ms=0.0)
        return result

    def update_health(
        self,
        component_id: str,
        status: ComponentStatus,
        health_score: float,
        metadata: Dict[str, Any] = None,
    ) -> ComponentHealth:
        """Update component health."""
        health = self._store.get_health(component_id)
        if not health:
            raise ValueError(f"Component {component_id} not found")
        
        health.status = status
        health.health_score = health_score
        health.last_check = datetime.now(timezone.utc)
        
        if metadata:
            health.metadata.update(metadata)
        
        self._store.store_health(health)
        return health
    
    def get_component_health(self, component_id: str) -> Optional[ComponentHealth]:
        """Get component health."""
        return self._store.get_health(component_id)
    
    def get_all_components(self) -> List[ComponentHealth]:
        """Get all component health."""
        return self._store.get_all_health()
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary."""
        return self._store.get_health_summary()
    
    def calculate_overall_health(self) -> float:
        """Calculate overall platform health score."""
        healths = self._store.get_all_health()
        
        if not healths:
            return 0.0
        
        # Weighted average based on component importance
        weights = {
            "api": 0.3,
            "database": 0.3,
            "cache": 0.15,
            "queue": 0.15,
            "worker": 0.1,
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for health in healths:
            weight = weights.get(health.component_type, 0.1)
            total_score += health.health_score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def check_dependencies(self, component_id: str) -> List[Dict[str, Any]]:
        """Check health of component dependencies.

        Reports each dependency's own last recorded check rather than the
        `random.uniform(90, 100)` this previously invented, and reports
        UNKNOWN for a dependency that has never been checked.
        """
        health = self._store.get_health(component_id)
        if not health:
            return []

        declared = (health.metadata or {}).get("dependencies") or []
        dependencies = []

        for dependency in declared:
            dep_id = (
                dependency if isinstance(dependency, str) else dependency.get("id")
            )
            dep_type = (
                "unknown"
                if isinstance(dependency, str)
                else dependency.get("type", "unknown")
            )
            if not dep_id:
                continue

            dep_health = self._store.get_health(dep_id)
            if dep_health is None:
                dependencies.append(
                    {
                        "id": dep_id,
                        "type": dep_type,
                        "status": ComponentStatus.UNKNOWN.value,
                        "health_score": 0.0,
                        "error": "dependency not registered",
                    }
                )
                continue

            dependencies.append(
                {
                    "id": dep_id,
                    "type": dep_health.component_type or dep_type,
                    "status": dep_health.status.value,
                    "health_score": dep_health.health_score,
                    "last_check": (
                        dep_health.last_check.isoformat()
                        if getattr(dep_health, "last_check", None)
                        else None
                    ),
                }
            )

        return dependencies


# Global singleton
_health_monitor: Optional[HealthMonitor] = None
_health_monitor_lock = Lock()


def get_health_monitor(store: Optional[ObservabilityStore] = None) -> HealthMonitor:
    """Get or create the singleton HealthMonitor instance."""
    global _health_monitor
    
    with _health_monitor_lock:
        if _health_monitor is None:
            _health_monitor = HealthMonitor(store=store)
        return _health_monitor