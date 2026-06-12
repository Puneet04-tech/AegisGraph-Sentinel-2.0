"""
Security Orchestrator.

Orchestrates cross-node operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Intelligence,
    IntelligenceType,
    MeshNode,
    NodeType,
    OrchestrationTask,
)
from .store import SecurityMeshStore, get_mesh_store


class SecurityOrchestrator:
    """Orchestrator for security mesh operations."""

    def __init__(self, store: Optional[SecurityMeshStore] = None) -> None:
        """Initialize the orchestrator."""
        self.store = store or get_mesh_store()

    async def orchestrate_response(
        self,
        source_intel: Intelligence,
        target_node_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Orchestrate a response across nodes."""
        if target_node_types is None:
            target_node_types = self._infer_target_types(source_intel)
        
        task_id = f"orch-{uuid.uuid4().hex[:12]}"
        
        task = OrchestrationTask(
            task_id=task_id,
            task_type="cross_domain_response",
            source_node=source_intel.source_node,
            target_nodes=[
                n.node_id for n in self.store.get_active_nodes()
                if n.node_type.value in target_node_types
            ],
            parameters={
                "intel_id": source_intel.intel_id,
                "intel_title": source_intel.title,
                "intel_type": source_intel.intelligence_type.value,
            },
        )
        
        self.store.create_task(task)
        
        self.store.log_audit(
            user_id=source_intel.source_node,
            action="orchestration_started",
            node_id=source_intel.source_node,
            details={"task_id": task_id, "intel_id": source_intel.intel_id},
        )
        
        return {
            "task_id": task_id,
            "status": "initiated",
            "target_nodes": task.target_nodes,
        }

    def _infer_target_types(self, intel: Intelligence) -> List[str]:
        """Infer target node types from intelligence."""
        types = set()
        
        for tag in intel.tags:
            tag_lower = tag.lower()
            if "fraud" in tag_lower:
                types.add("fraud")
            if "aml" in tag_lower:
                types.add("aml")
            if "cyber" in tag_lower:
                types.add("cyber")
            if "compliance" in tag_lower:
                types.add("compliance")
        
        if not types:
            types.add("threat_intel")
        
        return list(types)

    async def coordinate_investigation(
        self,
        source_node: str,
        investigation_type: str,
        parameters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Coordinate an investigation across nodes."""
        task_id = f"invest-{uuid.uuid4().hex[:12]}"
        
        task = OrchestrationTask(
            task_id=task_id,
            task_type=f"investigation_{investigation_type}",
            source_node=source_node,
            target_nodes=[
                n.node_id for n in self.store.get_active_nodes()
            ],
            parameters=parameters,
        )
        
        self.store.create_task(task)
        
        return {
            "task_id": task_id,
            "status": "coordinated",
            "participating_nodes": len(task.target_nodes),
        }

    def execute_automated_action(
        self,
        action_type: str,
        target_node: str,
        parameters: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute an automated action on a node."""
        node = self.store.get_node(target_node)
        if not node:
            return {"success": False, "error": "Node not found"}
        
        if node.status.value != "active":
            return {"success": False, "error": "Node not active"}
        
        self.store.log_audit(
            user_id="system",
            action=f"automated_action_{action_type}",
            node_id=target_node,
            details=parameters,
        )
        
        return {
            "success": True,
            "action": action_type,
            "target_node": target_node,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_orchestration_status(self) -> Dict[str, Any]:
        """Get orchestration status."""
        tasks = list(self.store._tasks.values())
        
        return {
            "total_tasks": len(tasks),
            "pending": len([t for t in tasks if t.status == "pending"]),
            "in_progress": len([t for t in tasks if t.status == "in_progress"]),
            "completed": len([t for t in tasks if t.status == "completed"]),
            "failed": len([t for t in tasks if t.status == "failed"]),
        }


# Singleton instance
_orchestrator: Optional[SecurityOrchestrator] = None


def get_security_orchestrator() -> SecurityOrchestrator:
    """Get the global orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = SecurityOrchestrator()
    return _orchestrator


def reset_security_orchestrator() -> None:
    """Reset the global orchestrator."""
    global _orchestrator
    _orchestrator = None