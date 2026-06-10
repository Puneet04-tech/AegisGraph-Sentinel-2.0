"""
Mesh Controller.

Central controller for the security intelligence mesh.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    MeshNode,
    NodeStatus,
    NodeType,
)
from .store import SecurityMeshStore, get_mesh_store


class MeshController:
    """Controller for mesh node management."""

    def __init__(self, store: Optional[SecurityMeshStore] = None) -> None:
        """Initialize the controller."""
        self.store = store or get_mesh_store()

    def register_node(
        self,
        node_type: str,
        name: str,
        endpoint: str,
        capabilities: Optional[List[str]] = None,
    ) -> MeshNode:
        """Register a new node in the mesh."""
        node_id = f"node-{uuid.uuid4().hex[:12]}"
        
        node = MeshNode(
            node_id=node_id,
            node_type=NodeType(node_type),
            name=name,
            endpoint=endpoint,
            capabilities=capabilities or [],
        )
        
        self.store.register_node(node)
        
        self.store.log_audit(
            user_id="system",
            action="node_registered",
            node_id=node_id,
            details={"node_type": node_type, "name": name},
        )
        
        return node

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get node details."""
        node = self.store.get_node(node_id)
        if not node:
            return None
        
        return self._node_to_dict(node)

    def _node_to_dict(self, node: MeshNode) -> Dict[str, Any]:
        """Convert node to dictionary."""
        return {
            "node_id": node.node_id,
            "node_type": node.node_type.value,
            "name": node.name,
            "endpoint": node.endpoint,
            "capabilities": node.capabilities,
            "status": node.status.value,
            "trust_score": node.trust_score,
            "shared_intelligence_count": node.shared_intelligence_count,
            "received_intelligence_count": node.received_intelligence_count,
            "registered_at": node.registered_at.isoformat(),
            "last_heartbeat": node.last_heartbeat.isoformat(),
        }

    def heartbeat(self, node_id: str) -> bool:
        """Process node heartbeat."""
        success = self.store.update_node_heartbeat(node_id)
        
        if success:
            self.store.log_audit(
                user_id="system",
                action="node_heartbeat",
                node_id=node_id,
            )
        
        return success

    def get_all_nodes(
        self,
        node_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get all nodes with optional filtering."""
        nodes = list(self.store._nodes.values())
        
        if node_type:
            type_enum = NodeType(node_type)
            nodes = [n for n in nodes if n.node_type == type_enum]
        
        if status:
            status_enum = NodeStatus(status)
            nodes = [n for n in nodes if n.status == status_enum]
        
        return [self._node_to_dict(n) for n in nodes]

    def get_active_nodes(self) -> List[Dict[str, Any]]:
        """Get active nodes."""
        nodes = self.store.get_active_nodes()
        return [self._node_to_dict(n) for n in nodes]

    def suspend_node(self, node_id: str) -> bool:
        """Suspend a node."""
        node = self.store.get_node(node_id)
        if not node:
            return False
        
        node.status = NodeStatus.SUSPENDED
        self.store.log_audit(
            user_id="system",
            action="node_suspended",
            node_id=node_id,
        )
        return True

    def reactivate_node(self, node_id: str) -> bool:
        """Reactivate a node."""
        node = self.store.get_node(node_id)
        if not node:
            return False
        
        node.status = NodeStatus.ACTIVE
        self.store.log_audit(
            user_id="system",
            action="node_reactivated",
            node_id=node_id,
        )
        return True


# Singleton instance
_controller: Optional[MeshController] = None


def get_mesh_controller() -> MeshController:
    """Get the global controller instance."""
    global _controller
    if _controller is None:
        _controller = MeshController()
    return _controller


def reset_mesh_controller() -> None:
    """Reset the global controller."""
    global _controller
    _controller = None