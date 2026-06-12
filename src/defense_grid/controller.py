"""
Defense Grid Controller for Autonomous Enterprise Defense Grid.

Orchestrates autonomous defense operations across the grid.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
import threading
import hashlib


@dataclass
class DefenseCommand:
    """Defense command to be executed."""
    command_id: str
    command_type: str
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: str = "MEDIUM"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "PENDING"


class DefenseGridController:
    """Central controller for autonomous defense grid.
    
    Coordinates threat prevention, containment, mitigation,
    and recovery operations across all grid nodes.
    """

    def __init__(self, store: Any):
        """Initialize the defense grid controller.
        
        Args:
            store: Defense store instance
        """
        self.store = store
        self._command_queue: List[DefenseCommand] = []
        self._execution_handlers: Dict[str, Callable] = {}
        self._lock = threading.Lock()
        self._active_responses: Dict[str, Dict[str, Any]] = {}
        self._subscribers: List[Callable[[Dict], None]] = []

    def register_handler(self, command_type: str, handler: Callable) -> None:
        """Register a command execution handler.
        
        Args:
            command_type: Type of command
            handler: Handler function
        """
        with self._lock:
            self._execution_handlers[command_type] = handler

    def subscribe(self, callback: Callable[[Dict], None]) -> None:
        """Subscribe to defense grid events.
        
        Args:
            callback: Function to call on events
        """
        with self._lock:
            self._subscribers.append(callback)

    def _notify_subscribers(self, event: Dict[str, Any]) -> None:
        """Notify all subscribers of an event."""
        for callback in self._subscribers:
            try:
                callback(event)
            except Exception:
                pass

    def process_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a detected threat.
        
        Args:
            threat_data: Threat data including type, severity, entities
            
        Returns:
            Processing result
        """
        threat_id = threat_data.get("threat_id", str(uuid.uuid4()))
        threat_type = threat_data.get("type", "")
        severity = threat_data.get("severity", "MEDIUM")
        affected_entities = threat_data.get("affected_entities", [])
        
        start_time = datetime.now(timezone.utc)
        
        # Log defense event
        event = {
            "event_id": str(hashlib.md5(f"{threat_id}{start_time}".encode()).hexdigest()[:16]),
            "event_type": "THREAT_DETECTED",
            "severity": severity,
            "source": threat_data.get("source", "UNKNOWN"),
            "description": f"Threat detected: {threat_type}",
            "affected_entities": [{"entity_id": e, "type": "unknown"} for e in affected_entities],
            "related_threat_id": threat_id,
            "timestamp": start_time,
        }
        self.store.add_defense_event(event)
        
        response = {
            "threat_id": threat_id,
            "threat_type": threat_type,
            "severity": severity,
            "affected_entities": affected_entities,
            "response_id": str(uuid.uuid4()),
            "detection_time": start_time,
        }
        
        # Determine response based on severity
        if severity in ("CRITICAL", "HIGH"):
            # Immediate containment
            response["actions"] = self._execute_critical_response(threat_data)
        elif severity == "MEDIUM":
            # Standard response
            response["actions"] = self._execute_standard_response(threat_data)
        else:
            # Monitor and log
            response["actions"] = [{"type": "MONITOR", "status": "TRIGGERED"}]
        
        response["response_start_time"] = datetime.now(timezone.utc)
        
        # Store response
        self.store.add_threat_response(response)
        
        response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        response["response_time_ms"] = response_time
        
        # Update event with actions
        event["actions_taken"] = [a.get("type") for a in response.get("actions", [])]
        event["response_time_ms"] = response_time
        
        self._notify_subscribers({
            "type": "THREAT_RESPONSE",
            "threat_id": threat_id,
            "response": response,
        })
        
        return response

    def _execute_critical_response(self, threat_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute critical severity response."""
        actions = []
        
        # Immediate containment
        for entity in threat_data.get("affected_entities", []):
            containment = self._initiate_containment(
                entity_id=entity,
                containment_type="NETWORK_ISOLATE",
                reason="Critical threat containment",
            )
            actions.append(containment)
        
        # Execute prevention policies
        policies = self.store.list_policies(enabled=True, policy_type="PREVENTION")
        for policy in policies[:3]:  # Top 3 policies
            result = self._execute_policy(policy)
            actions.append(result)
        
        return actions

    def _execute_standard_response(self, threat_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute standard severity response."""
        actions = []
        
        # Apply detection policies
        policies = self.store.list_policies(enabled=True, policy_type="DETECTION")
        for policy in policies[:2]:
            result = self._execute_policy(policy)
            actions.append(result)
        
        return actions

    def _initiate_containment(
        self,
        entity_id: str,
        containment_type: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Initiate containment action."""
        action = {
            "action_id": str(uuid.uuid4()),
            "containment_type": containment_type,
            "target_entity": entity_id,
            "target_entity_type": "ENTITY",
            "duration_seconds": 3600,
            "auto_extend": True,
            "status": "IN_PROGRESS",
            "initiated_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "initiated_by": "DEFENSE_GRID_CONTROLLER",
            "reason": reason,
        }
        
        self.store.add_containment_action(action)
        
        self._notify_subscribers({
            "type": "CONTAINMENT_INITIATED",
            "action": action,
        })
        
        return action

    def _execute_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a defense policy."""
        policy_id = policy.get("policy_id")
        
        # Check cooldown
        last_triggered = policy.get("last_triggered")
        cooldown = policy.get("cooldown_seconds", 300)
        
        if last_triggered:
            if isinstance(last_triggered, str):
                last_triggered = datetime.fromisoformat(last_triggered)
            elapsed = (datetime.now(timezone.utc) - last_triggered).total_seconds()
            if elapsed < cooldown:
                return {
                    "type": "POLICY_SKIP",
                    "policy_id": policy_id,
                    "reason": "Cooldown active",
                }
        
        # Execute actions
        actions = policy.get("actions", [])
        results = []
        
        for action in actions:
            action_type = action.get("type")
            if action_type in self._execution_handlers:
                result = self._execution_handlers[action_type](action)
                results.append(result)
        
        # Update policy stats
        policy["trigger_count"] = policy.get("trigger_count", 0) + 1
        policy["last_triggered"] = datetime.now(timezone.utc)
        
        return {
            "type": "POLICY_EXECUTED",
            "policy_id": policy_id,
            "actions_executed": len(results),
            "results": results,
        }

    def queue_command(self, command: DefenseCommand) -> str:
        """Queue a command for execution.
        
        Args:
            command: Defense command
            
        Returns:
            Command ID
        """
        with self._lock:
            self._command_queue.append(command)
            return command.command_id

    def execute_command(self, command_id: str) -> Dict[str, Any]:
        """Execute a queued command.
        
        Args:
            command_id: Command ID
            
        Returns:
            Execution result
        """
        command = None
        with self._lock:
            for cmd in self._command_queue:
                if cmd.command_id == command_id:
                    command = cmd
                    break
        
        if not command:
            return {"error": "Command not found"}
        
        if command.command_type not in self._execution_handlers:
            return {"error": f"No handler for command type: {command.command_type}"}
        
        handler = self._execution_handlers[command.command_type]
        result = handler(command)
        
        command.status = "COMPLETED"
        
        return {
            "command_id": command_id,
            "status": "COMPLETED",
            "result": result,
        }

    def release_containment(self, action_id: str) -> Dict[str, Any]:
        """Release a containment action.
        
        Args:
            action_id: Containment action ID
            
        Returns:
            Release result
        """
        action = self.store.get_containment_action(action_id)
        if not action:
            return {"error": "Containment action not found"}
        
        if action.get("status") == "COMPLETED":
            return {"error": "Containment already released"}
        
        action["status"] = "COMPLETED"
        action["released_at"] = datetime.now(timezone.utc)
        
        self._notify_subscribers({
            "type": "CONTAINMENT_RELEASED",
            "action": action,
        })
        
        return {
            "action_id": action_id,
            "status": "RELEASED",
            "released_at": action["released_at"].isoformat(),
        }

    def initiate_recovery(self, entity_id: str, entity_type: str) -> Dict[str, Any]:
        """Initiate recovery for an entity.
        
        Args:
            entity_id: Entity to recover
            entity_type: Type of entity
            
        Returns:
            Recovery plan
        """
        plan = {
            "plan_id": str(uuid.uuid4()),
            "name": f"Recovery Plan for {entity_id}",
            "description": f"Automated recovery for {entity_type}",
            "target_entity": entity_id,
            "target_entity_type": entity_type,
            "phases": [
                {"phase": 1, "name": "Assessment", "actions": ["assess_damage"]},
                {"phase": 2, "name": "Cleanup", "actions": ["remove_threat", "patch_vulnerabilities"]},
                {"phase": 3, "name": "Restoration", "actions": ["restore_services", "verify_connectivity"]},
                {"phase": 4, "name": "Validation", "actions": ["test_functionality", "confirm_security"]},
            ],
            "status": "IN_PROGRESS",
            "created_at": datetime.now(timezone.utc),
            "started_at": datetime.now(timezone.utc),
            "current_phase": 0,
        }
        
        self.store.add_recovery_plan(plan)
        
        self._notify_subscribers({
            "type": "RECOVERY_INITIATED",
            "plan": plan,
        })
        
        return plan

    def get_grid_status(self) -> Dict[str, Any]:
        """Get overall defense grid status."""
        stats = self.store.get_defense_stats()
        
        # Get node health
        nodes = self.store.list_grid_nodes()
        avg_health = sum(n.get("health_score", 0) for n in nodes) / len(nodes) if nodes else 0
        
        # Get active responses
        active_containments = self.store.list_containment_actions(active_only=True)
        
        # Get recent events
        recent_events = self.store.list_defense_events(limit=10)
        
        return {
            "grid_status": "OPERATIONAL" if avg_health > 80 else "DEGRADED",
            "total_nodes": stats["total_grid_nodes"],
            "active_nodes": stats["active_nodes"],
            "average_health": avg_health,
            "active_containments": len(active_containments),
            "pending_events": stats["unresolved_events"],
            "recent_events": recent_events,
            "nodes_by_status": stats["nodes_by_status"],
        }


def get_defense_controller() -> DefenseGridController:
    """Get the global defense controller instance."""
    from .store import get_defense_store
    store = get_defense_store()
    return DefenseGridController(store)


import uuid