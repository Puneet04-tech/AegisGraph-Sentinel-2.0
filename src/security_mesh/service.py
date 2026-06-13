"""
Security Intelligence Mesh Service.

Main service for the security intelligence mesh.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AuditEvent,
    Intelligence,
    IntelligenceType,
    MeshNode,
    NodeType,
)
from .store import (
    SecurityMeshStore,
    get_mesh_store,
    reset_mesh_store,
)
from .controller import (
    MeshController,
    get_mesh_controller,
    reset_mesh_controller,
)
from .router import (
    IntelligenceRouter,
    get_intelligence_router,
    reset_intelligence_router,
)
from .decision_engine import (
    DecisionEngine,
    get_decision_engine,
    reset_decision_engine,
)
from .federation import (
    FederationEngine,
    get_federation_engine,
    reset_federation_engine,
)
from .orchestrator import (
    SecurityOrchestrator,
    get_security_orchestrator,
    reset_security_orchestrator,
)


class SecurityMeshService:
    """Main service for security intelligence mesh."""

    def __init__(self, store: Optional[SecurityMeshStore] = None) -> None:
        """Initialize the service."""
        self.store = store or get_mesh_store()
        self.controller = get_mesh_controller()
        self.router = get_intelligence_router()
        self.decision = get_decision_engine()
        self.federation = get_federation_engine()
        self.orchestrator = get_security_orchestrator()

    async def register(
        self,
        node_type: str,
        name: str,
        endpoint: str,
        capabilities: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register a node in the mesh."""
        node = self.controller.register_node(
            node_type=node_type,
            name=name,
            endpoint=endpoint,
            capabilities=capabilities,
        )
        
        return {
            "node_id": node.node_id,
            "status": "registered",
        }

    async def share(
        self,
        source_node: str,
        intelligence_type: str,
        title: str,
        description: str,
        indicators: Optional[List[Dict[str, Any]]] = None,
        confidence: float = 0.8,
    ) -> Dict[str, Any]:
        """Share intelligence across the mesh."""
        intel = self.router.share_intelligence(
            source_node=source_node,
            intelligence_type=intelligence_type,
            title=title,
            description=description,
            indicators=indicators,
            confidence=confidence,
        )
        
        decisions = self.decision.evaluate_intelligence(intel)
        
        return {
            "intel_id": intel.intel_id,
            "status": "shared",
            "decisions": decisions,
        }

    async def get_intelligence(
        self,
        query: Optional[str] = None,
        intelligence_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get intelligence from the mesh."""
        if query:
            return self.router.search_intelligence(query, intelligence_type)
        elif intelligence_type:
            results = self.store.get_intelligence_by_type(
                IntelligenceType(intelligence_type)
            )
            return [self.router._intel_to_dict(i) for i in results]
        else:
            return self.router.get_cross_domain_intelligence()

    async def get_federation(self) -> Dict[str, Any]:
        """Get federation insights."""
        return self.federation.get_cross_domain_insights()

    async def orchestrate(
        self,
        source_node: str,
        action_type: str,
        parameters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Orchestrate an action across nodes."""
        if action_type == "investigation":
            return await self.orchestrator.coordinate_investigation(
                source_node=source_node,
                investigation_type=parameters.get("type", "general"),
                parameters=parameters,
            )
        
        return await self.orchestrator.orchestrate_response(
            source_intel=Intelligence(
                intel_id=parameters.get("intel_id", ""),
                source_node=source_node,
                intelligence_type=IntelligenceType.THREAT,
                title=parameters.get("title", ""),
                description=parameters.get("description", ""),
            ),
            target_node_types=parameters.get("target_types"),
        )

    async def get_dashboard(self) -> Dict[str, Any]:
        """Get mesh dashboard."""
        metrics = self.store.get_mesh_metrics()
        orchestration = self.orchestrator.get_orchestration_status()
        
        return {
            "total_nodes": metrics.total_nodes,
            "active_nodes": metrics.active_nodes,
            "total_intelligence": metrics.total_intelligence,
            "intelligence_shared": metrics.intelligence_shared,
            "cross_domain_correlations": metrics.cross_domain_correlations,
            "automated_responses": metrics.automated_responses,
            "orchestration_status": orchestration,
            "calculated_at": metrics.calculated_at.isoformat(),
        }

    async def get_health(self) -> Dict[str, Any]:
        """Get mesh health status."""
        nodes = self.store.get_active_nodes()
        
        healthy = len(nodes)
        total = len(self.store._nodes)
        
        return {
            "status": "healthy" if healthy == total else "degraded",
            "total_nodes": total,
            "active_nodes": healthy,
            "inactive_nodes": total - healthy,
        }

    async def get_audit(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "user_id": e.user_id,
                "action": e.action,
                "node_id": e.node_id,
                "success": e.success,
            }
            for e in events
        ]


# Singleton instance
_service: Optional[SecurityMeshService] = None


def get_security_mesh_service() -> SecurityMeshService:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = SecurityMeshService()
    return _service


def reset_security_mesh_service() -> None:
    """Reset the global service."""
    global _service
    _service = None
    reset_mesh_store()
    reset_mesh_controller()
    reset_intelligence_router()
    reset_decision_engine()
    reset_federation_engine()
    reset_security_orchestrator()