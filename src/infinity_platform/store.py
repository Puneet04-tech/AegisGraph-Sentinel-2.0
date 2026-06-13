"""
Infinity Platform Store.

Storage layer for unified infinity platform.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AuditEvent,
    Component,
    ComponentType,
    CrossDomainCorrelation,
    IntegrationStatus,
    InfinityDashboard,
    RiskLevel,
    UnifiedIntelligence,
)


class InfinityStore:
    """Store for infinity platform."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._components: Dict[str, Component] = {}
        self._intelligence: Dict[str, UnifiedIntelligence] = {}
        self._correlations: Dict[str, CrossDomainCorrelation] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def add_component(self, component: Component) -> None:
        """Add a component."""
        with self._lock:
            self._components[component.component_id] = component

    def get_component(self, component_id: str) -> Optional[Component]:
        """Get a component."""
        return self._components.get(component_id)

    def get_component_by_type(
        self,
        component_type: ComponentType,
    ) -> Optional[Component]:
        """Get component by type."""
        for comp in self._components.values():
            if comp.component_type == component_type:
                return comp
        return None

    def update_component_status(
        self,
        component_id: str,
        status: IntegrationStatus,
    ) -> bool:
        """Update component status."""
        component = self._components.get(component_id)
        if not component:
            return False
        component.status = status
        component.last_sync = datetime.now(timezone.utc)
        return True

    def add_intelligence(self, intel: UnifiedIntelligence) -> None:
        """Add unified intelligence."""
        with self._lock:
            self._intelligence[intel.intel_id] = intel

    def get_intelligence(self, intel_id: str) -> Optional[UnifiedIntelligence]:
        """Get intelligence."""
        return self._intelligence.get(intel_id)

    def search_intelligence(
        self,
        query: str,
    ) -> List[UnifiedIntelligence]:
        """Search intelligence."""
        query_lower = query.lower()
        return [
            i for i in self._intelligence.values()
            if query_lower in i.title.lower() or
            query_lower in i.description.lower()
        ]

    def add_correlation(self, correlation: CrossDomainCorrelation) -> None:
        """Add correlation."""
        with self._lock:
            self._correlations[correlation.correlation_id] = correlation

    def get_correlation(
        self,
        correlation_id: str,
    ) -> Optional[CrossDomainCorrelation]:
        """Get correlation."""
        return self._correlations.get(correlation_id)

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

    def get_dashboard(self) -> InfinityDashboard:
        """Get dashboard."""
        components = list(self._components.values())
        healthy = len([c for c in components if c.status == IntegrationStatus.ACTIVE])
        
        return InfinityDashboard(
            total_intelligence=len(self._intelligence),
            active_threats=len([
                i for i in self._intelligence.values()
                if i.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]
            ]),
            components_healthy=healthy,
            components_total=len(components),
            calculated_at=datetime.now(timezone.utc),
        )

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._components.clear()
            self._intelligence.clear()
            self._correlations.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[InfinityStore] = None
_store_lock = threading.Lock()


def get_infinity_store() -> InfinityStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = InfinityStore()
    return _store


def reset_infinity_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None