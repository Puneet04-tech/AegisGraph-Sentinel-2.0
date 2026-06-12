"""
AegisGraph Sentinel Infinity Engine.

Unified engine for the infinity platform.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Component,
    ComponentType,
    CrossDomainCorrelation,
    IntegrationStatus,
    RiskLevel,
    UnifiedIntelligence,
)
from .store import InfinityStore, get_infinity_store


class InfinityEngine:
    """Main infinity platform engine."""

    def __init__(self, store: Optional[InfinityStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_infinity_store()

    def register_component(
        self,
        component_type: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Component:
        """Register a platform component."""
        component_id = f"comp-{uuid.uuid4().hex[:12]}"
        
        component = Component(
            component_id=component_id,
            component_type=ComponentType(component_type),
            name=name,
            metadata=metadata or {},
        )
        
        self.store.add_component(component)
        
        self.store.log_audit(
            user_id="system",
            action="component_registered",
            resource_type="component",
            resource_id=component_id,
            details={"type": component_type, "name": name},
        )
        
        return component

    def get_component_status(self, component_id: str) -> Optional[Dict[str, Any]]:
        """Get component status."""
        component = self.store.get_component(component_id)
        if not component:
            return None
        
        return {
            "component_id": component.component_id,
            "name": component.name,
            "status": component.status.value,
            "health_score": component.health_score,
            "last_sync": component.last_sync.isoformat() if component.last_sync else None,
        }

    def add_unified_intelligence(
        self,
        sources: List[str],
        intelligence_type: str,
        title: str,
        description: str,
        severity: str,
        confidence: float = 0.5,
        indicators: Optional[List[Dict[str, Any]]] = None,
    ) -> UnifiedIntelligence:
        """Add unified intelligence."""
        intel_id = f"intel-{uuid.uuid4().hex[:12]}"
        
        intel = UnifiedIntelligence(
            intel_id=intel_id,
            sources=sources,
            intelligence_type=intelligence_type,
            title=title,
            description=description,
            severity=RiskLevel(severity),
            confidence=confidence,
            indicators=indicators or [],
        )
        
        self.store.add_intelligence(intel)
        
        self.store.log_audit(
            user_id="system",
            action="intelligence_added",
            resource_type="unified_intelligence",
            resource_id=intel_id,
            details={"type": intelligence_type, "sources": sources},
        )
        
        return intel

    def correlate_intelligence(
        self,
        intelligence_ids: List[str],
        correlation_type: str,
        description: str,
    ) -> CrossDomainCorrelation:
        """Correlate intelligence across domains."""
        correlation_id = f"corr-{uuid.uuid4().hex[:12]}"
        
        correlation = CrossDomainCorrelation(
            correlation_id=correlation_id,
            correlation_type=correlation_type,
            description=description,
            related_intelligence=intelligence_ids,
            confidence=0.7,
        )
        
        self.store.add_correlation(correlation)
        
        for intel_id in intelligence_ids:
            intel = self.store.get_intelligence(intel_id)
            if intel:
                intel.correlated = True
        
        self.store.log_audit(
            user_id="system",
            action="intelligence_correlated",
            resource_type="correlation",
            resource_id=correlation_id,
        )
        
        return correlation

    def search_unified_intelligence(
        self,
        query: str,
    ) -> List[Dict[str, Any]]:
        """Search unified intelligence."""
        results = self.store.search_intelligence(query)
        
        return [
            {
                "intel_id": i.intel_id,
                "title": i.title,
                "description": i.description,
                "severity": i.severity.value,
                "confidence": i.confidence,
                "sources": i.sources,
                "correlated": i.correlated,
                "created_at": i.created_at.isoformat(),
            }
            for i in results
        ]

    def get_executive_dashboard(self) -> Dict[str, Any]:
        """Get executive command center dashboard."""
        dashboard = self.store.get_dashboard()
        components = list(self.store._components.values())
        
        component_status = {}
        for comp_type in ComponentType:
            comp = self.store.get_component_by_type(comp_type)
            if comp:
                component_status[comp_type.value] = {
                    "name": comp.name,
                    "status": comp.status.value,
                    "health_score": comp.health_score,
                }
        
        return {
            "platform_health": {
                "total_components": dashboard.components_total,
                "healthy_components": dashboard.components_healthy,
                "health_percentage": (
                    dashboard.components_healthy / dashboard.components_total * 100
                    if dashboard.components_total > 0 else 0
                ),
            },
            "threat_summary": {
                "total_intelligence": dashboard.total_intelligence,
                "active_threats": dashboard.active_threats,
                "unified_threats": dashboard.unified_threats,
            },
            "components": component_status,
            "calculated_at": dashboard.calculated_at.isoformat(),
        }

    def sync_component(self, component_id: str) -> bool:
        """Sync a component."""
        success = self.store.update_component_status(
            component_id,
            IntegrationStatus.ACTIVE,
        )
        
        if success:
            self.store.log_audit(
                user_id="system",
                action="component_synced",
                resource_type="component",
                resource_id=component_id,
            )
        
        return success

    def get_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "resource_type": e.resource_type,
            }
            for e in events
        ]


# Singleton instance
_engine: Optional[InfinityEngine] = None


def get_infinity_engine() -> InfinityEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = InfinityEngine()
    return _engine


def reset_infinity_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None