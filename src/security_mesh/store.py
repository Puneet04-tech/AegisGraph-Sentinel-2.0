"""
Security Mesh Store.

Storage layer for mesh components.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AuditEvent,
    Intelligence,
    IntelligenceRequest,
    IntelligenceType,
    KnowledgeGraphEntry,
    MeshMetrics,
    MeshNode,
    NodeStatus,
    NodeType,
    OrchestrationTask,
    ShareLevel,
)


class SecurityMeshStore:
    """Store for security mesh."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._nodes: Dict[str, MeshNode] = {}
        self._intelligence: Dict[str, Intelligence] = {}
        self._requests: Dict[str, IntelligenceRequest] = {}
        self._tasks: Dict[str, OrchestrationTask] = {}
        self._knowledge_graph: Dict[str, KnowledgeGraphEntry] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def register_node(self, node: MeshNode) -> None:
        """Register a mesh node."""
        with self._lock:
            self._nodes[node.node_id] = node

    def get_node(self, node_id: str) -> Optional[MeshNode]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def get_nodes_by_type(self, node_type: NodeType) -> List[MeshNode]:
        """Get nodes by type."""
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def get_active_nodes(self) -> List[MeshNode]:
        """Get active nodes."""
        return [n for n in self._nodes.values() if n.status == NodeStatus.ACTIVE]

    def update_node_heartbeat(self, node_id: str) -> bool:
        """Update node heartbeat."""
        node = self._nodes.get(node_id)
        if not node:
            return False
        node.last_heartbeat = datetime.now(timezone.utc)
        return True

    def store_intelligence(self, intel: Intelligence) -> None:
        """Store intelligence."""
        with self._lock:
            self._intelligence[intel.intel_id] = intel
        
        node = self._nodes.get(intel.source_node)
        if node:
            node.shared_intelligence_count += 1

    def get_intelligence(
        self,
        intel_id: str,
    ) -> Optional[Intelligence]:
        """Get intelligence by ID."""
        return self._intelligence.get(intel_id)

    def get_intelligence_by_type(
        self,
        intel_type: IntelligenceType,
    ) -> List[Intelligence]:
        """Get intelligence by type."""
        return [
            i for i in self._intelligence.values()
            if i.intelligence_type == intel_type
        ]

    def get_intelligence_for_node(
        self,
        node_type: NodeType,
        share_level: ShareLevel = ShareLevel.PARTIAL,
    ) -> List[Intelligence]:
        """Get intelligence suitable for a node."""
        results = []
        for intel in self._intelligence.values():
            if intel.share_level in [ShareLevel.FULL, share_level]:
                source_node = self._nodes.get(intel.source_node)
                if source_node and source_node.node_type != node_type:
                    results.append(intel)
        return results

    def search_intelligence(
        self,
        query: str,
        intel_type: Optional[IntelligenceType] = None,
    ) -> List[Intelligence]:
        """Search intelligence."""
        results = []
        query_lower = query.lower()
        
        for intel in self._intelligence.values():
            if intel_type and intel.intelligence_type != intel_type:
                continue
            
            if query_lower in intel.title.lower():
                results.append(intel)
            elif query_lower in intel.description.lower():
                results.append(intel)
            elif any(query_lower in tag.lower() for tag in intel.tags):
                results.append(intel)
        
        return results

    def add_request(self, request: IntelligenceRequest) -> None:
        """Add an intelligence request."""
        with self._lock:
            self._requests[request.request_id] = request

    def get_request(self, request_id: str) -> Optional[IntelligenceRequest]:
        """Get a request by ID."""
        return self._requests.get(request_id)

    def create_task(self, task: OrchestrationTask) -> None:
        """Create an orchestration task."""
        with self._lock:
            self._tasks[task.task_id] = task

    def get_task(self, task_id: str) -> Optional[OrchestrationTask]:
        """Get a task by ID."""
        return self._tasks.get(task_id)

    def update_task_result(self, task_id: str, result: Dict[str, Any]) -> bool:
        """Update task result."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.result = result
        task.status = "completed"
        task.completed_at = datetime.now(timezone.utc)
        return True

    def add_knowledge_entry(self, entry: KnowledgeGraphEntry) -> None:
        """Add a knowledge graph entry."""
        with self._lock:
            self._knowledge_graph[entry.entry_id] = entry

    def get_knowledge_entry(self, entry_id: str) -> Optional[KnowledgeGraphEntry]:
        """Get a knowledge graph entry."""
        return self._knowledge_graph.get(entry_id)

    def get_knowledge_by_entity(self, entity_id: str) -> List[KnowledgeGraphEntry]:
        """Get knowledge entries by entity ID."""
        return [
            e for e in self._knowledge_graph.values()
            if e.entity_id == entity_id
        ]

    def log_audit(
        self,
        user_id: str,
        action: str,
        node_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{len(self._audit_log) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            node_id=node_id,
            details=details or {},
            success=success,
        )
        with self._lock:
            self._audit_log.append(event)

    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get audit log."""
        return self._audit_log[-limit:]

    def get_mesh_metrics(self) -> MeshMetrics:
        """Get mesh metrics."""
        nodes = list(self._nodes.values())
        active = [n for n in nodes if n.status == NodeStatus.ACTIVE]
        
        return MeshMetrics(
            total_nodes=len(nodes),
            active_nodes=len(active),
            total_intelligence=len(self._intelligence),
            intelligence_shared=sum(n.shared_intelligence_count for n in nodes),
            cross_domain_correlations=0,
            automated_responses=len([t for t in self._tasks.values() if t.status == "completed"]),
            calculated_at=datetime.now(timezone.utc),
        )

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._nodes.clear()
            self._intelligence.clear()
            self._requests.clear()
            self._tasks.clear()
            self._knowledge_graph.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[SecurityMeshStore] = None
_store_lock = threading.Lock()


def get_mesh_store() -> SecurityMeshStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = SecurityMeshStore()
    return _store


def reset_mesh_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None