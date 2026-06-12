"""
Autonomous Decision Engine.

Makes autonomous decisions for mesh coordination.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Intelligence,
    IntelligenceType,
    OrchestrationTask,
)
from .store import SecurityMeshStore, get_mesh_store


class DecisionEngine:
    """Engine for autonomous decision making."""

    def __init__(self, store: Optional[SecurityMeshStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_mesh_store()
        self._decision_rules: Dict[str, Dict[str, Any]] = {}

    def add_decision_rule(
        self,
        rule_id: str,
        condition: Dict[str, Any],
        action: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a decision rule."""
        self._decision_rules[rule_id] = {
            "rule_id": rule_id,
            "condition": condition,
            "action": action,
            "parameters": parameters or {},
        }

    def evaluate_intelligence(
        self,
        intel: Intelligence,
    ) -> List[Dict[str, Any]]:
        """Evaluate intelligence and determine actions."""
        decisions = []
        
        if intel.intelligence_type == IntelligenceType.THREAT:
            if intel.confidence >= 0.8:
                decisions.append({
                    "action": "broadcast_alert",
                    "priority": "high",
                    "targets": self._get_all_node_types(),
                })
            else:
                decisions.append({
                    "action": "investigate_further",
                    "priority": "medium",
                })
        
        if intel.intelligence_type == IntelligenceType.INDICATOR:
            decisions.append({
                "action": "correlate_indicators",
                "priority": "low",
            })
        
        if intel.intelligence_type == IntelligenceType.CAMPAIGN:
            decisions.append({
                "action": "coordinate_response",
                "priority": "high",
                "targets": self._get_relevant_nodes(intel.tags),
            })
        
        if intel.intelligence_type == IntelligenceType.PATTERN:
            decisions.append({
                "action": "update_detection_rules",
                "priority": "medium",
            })
        
        return decisions

    def _get_all_node_types(self) -> List[str]:
        """Get all node types."""
        return ["fraud", "aml", "cyber", "compliance", "threat_intel"]

    def _get_relevant_nodes(self, tags: List[str]) -> List[str]:
        """Get relevant nodes based on tags."""
        relevant = []
        for tag in tags:
            if "fraud" in tag.lower():
                relevant.append("fraud")
            elif "aml" in tag.lower():
                relevant.append("aml")
            elif "cyber" in tag.lower():
                relevant.append("cyber")
        return relevant if relevant else self._get_all_node_types()

    def create_task(
        self,
        task_type: str,
        source_node: str,
        target_nodes: Optional[List[str]] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> OrchestrationTask:
        """Create an orchestration task."""
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        
        task = OrchestrationTask(
            task_id=task_id,
            task_type=task_type,
            source_node=source_node,
            target_nodes=target_nodes or [],
            parameters=parameters or {},
        )
        
        self.store.create_task(task)
        
        self.store.log_audit(
            user_id=source_node,
            action="task_created",
            node_id=source_node,
            details={"task_id": task_id, "task_type": task_type},
        )
        
        return task

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task details."""
        task = self.store.get_task(task_id)
        if not task:
            return None
        
        return {
            "task_id": task.task_id,
            "task_type": task.task_type,
            "source_node": task.source_node,
            "target_nodes": task.target_nodes,
            "status": task.status,
            "result": task.result,
            "created_at": task.created_at.isoformat(),
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
        }

    def complete_task(
        self,
        task_id: str,
        result: Dict[str, Any],
    ) -> bool:
        """Mark task as completed."""
        success = self.store.update_task_result(task_id, result)
        
        if success:
            self.store.log_audit(
                user_id="system",
                action="task_completed",
                details={"task_id": task_id},
            )
        
        return success

    def get_pending_tasks(self) -> List[Dict[str, Any]]:
        """Get pending tasks."""
        tasks = [
            t for t in self.store._tasks.values()
            if t.status == "pending"
        ]
        
        return [
            {
                "task_id": t.task_id,
                "task_type": t.task_type,
                "source_node": t.source_node,
                "priority": t.parameters.get("priority", 1),
            }
            for t in tasks
        ]


# Singleton instance
_engine: Optional[DecisionEngine] = None


def get_decision_engine() -> DecisionEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = DecisionEngine()
    return _engine


def reset_decision_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None