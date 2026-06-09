"""
Health Monitor Module.

System health monitoring and component tracking.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    ComponentHealth,
    ComponentStatus,
)
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
    
    def __init__(self, store: Optional[ObservabilityStore] = None):
        """Initialize the health monitor."""
        self._store = store or get_observability_store()
        self._module_id = "health_monitor"
    
    def register_component(
        self,
        component_name: str,
        component_type: str,
        metadata: Dict[str, Any] = None,
    ) -> ComponentHealth:
        """Register a new component."""
        logger.info(f"Registering component: {component_name}")
        
        health = ComponentHealth(
            component_name=component_name,
            component_type=component_type,
            status=ComponentStatus.UNKNOWN,
            health_score=0.0,
            metadata=metadata or {},
        )
        
        self._store.store_health(health)
        return health
    
    def check_health(self, component_id: str) -> Dict[str, Any]:
        """Perform health check on component."""
        health = self._store.get_health(component_id)
        if not health:
            return {"error": "Component not found"}
        
        logger.info(f"Checking health of {health.component_name}")
        
        # Simulate health check
        is_healthy = random.random() > 0.05  # 95% healthy
        response_time = random.uniform(5, 200)
        
        if is_healthy:
            health.status = ComponentStatus.HEALTHY
            health.health_score = min(100, health.health_score + 5) if health.health_score > 0 else 100
        else:
            health.status = ComponentStatus.DEGRADED
            health.health_score = max(0, health.health_score - 10)
        
        health.last_check = datetime.now(timezone.utc)
        health.response_time_ms = response_time
        health.error_count = 0 if is_healthy else random.randint(1, 5)
        
        self._store.store_health(health)
        
        return {
            "component_id": component_id,
            "component_name": health.component_name,
            "status": health.status.value,
            "health_score": health.health_score,
            "response_time_ms": health.response_time_ms,
            "last_check": health.last_check.isoformat(),
        }
    
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
        """Check health of component dependencies."""
        health = self._store.get_health(component_id)
        if not health:
            return []
        
        # Simulate dependency check
        dependencies = []
        for dep_type in ["database", "cache", "queue"]:
            dep_health = ComponentHealth(
                component_name=f"{health.component_name}_{dep_type}",
                component_type=dep_type,
                status=ComponentStatus.HEALTHY,
                health_score=random.uniform(90, 100),
            )
            dependencies.append({
                "type": dep_type,
                "status": dep_health.status.value,
                "health_score": dep_health.health_score,
            })
        
        return dependencies


# Global singleton
_health_monitor: Optional[HealthMonitor] = None


def get_health_monitor(store: Optional[ObservabilityStore] = None) -> HealthMonitor:
    """Get or create the singleton HealthMonitor instance."""
    global _health_monitor
    
    if _health_monitor is None:
        _health_monitor = HealthMonitor(store=store)
    return _health_monitor