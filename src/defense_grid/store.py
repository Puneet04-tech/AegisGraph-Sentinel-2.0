"""
Storage layer for Autonomous Enterprise Defense Grid.

Provides persistent storage for defense policies, actions, and events.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import threading
import uuid


@dataclass
class DefenseStore:
    """Central storage for defense grid data.
    
    Thread-safe in-memory storage with persistence capabilities.
    """
    policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    mitigation_actions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    containment_actions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    recovery_plans: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    defense_events: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    threat_responses: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    grid_nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_policy(self, policy: Dict[str, Any]) -> str:
        """Add a new defense policy."""
        with self._lock:
            policy_id = policy.get("policy_id", str(uuid.uuid4()))
            policy["policy_id"] = policy_id
            self.policies[policy_id] = policy
            return policy_id

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get a policy by ID."""
        return self.policies.get(policy_id)

    def list_policies(
        self,
        enabled: Optional[bool] = None,
        policy_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List policies with optional filtering."""
        results = list(self.policies.values())
        if enabled is not None:
            results = [p for p in results if p.get("enabled") == enabled]
        if policy_type:
            results = [p for p in results if p.get("type") == policy_type]
        return results

    def add_mitigation_action(self, action: Dict[str, Any]) -> str:
        """Add a mitigation action."""
        with self._lock:
            action_id = action.get("action_id", str(uuid.uuid4()))
            action["action_id"] = action_id
            self.mitigation_actions[action_id] = action
            return action_id

    def get_mitigation_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Get a mitigation action by ID."""
        return self.mitigation_actions.get(action_id)

    def list_mitigation_actions(
        self,
        status: Optional[str] = None,
        target_entity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List mitigation actions with optional filtering."""
        results = list(self.mitigation_actions.values())
        if status:
            results = [a for a in results if a.get("status") == status]
        if target_entity:
            results = [a for a in results if a.get("target_entity") == target_entity]
        return sorted(results, key=lambda x: x.get("initiated_at", ""), reverse=True)

    def add_containment_action(self, action: Dict[str, Any]) -> str:
        """Add a containment action."""
        with self._lock:
            action_id = action.get("action_id", str(uuid.uuid4()))
            action["action_id"] = action_id
            self.containment_actions[action_id] = action
            return action_id

    def get_containment_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Get a containment action by ID."""
        return self.containment_actions.get(action_id)

    def list_containment_actions(
        self,
        status: Optional[str] = None,
        active_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """List containment actions with optional filtering."""
        results = list(self.containment_actions.values())
        if status:
            results = [a for a in results if a.get("status") == status]
        if active_only:
            results = [a for a in results if a.get("status") in ("PENDING", "IN_PROGRESS")]
        return sorted(results, key=lambda x: x.get("initiated_at", ""), reverse=True)

    def add_recovery_plan(self, plan: Dict[str, Any]) -> str:
        """Add a recovery plan."""
        with self._lock:
            plan_id = plan.get("plan_id", str(uuid.uuid4()))
            plan["plan_id"] = plan_id
            self.recovery_plans[plan_id] = plan
            return plan_id

    def get_recovery_plan(self, plan_id: str) -> Optional[Dict[str, Any]]:
        """Get a recovery plan by ID."""
        return self.recovery_plans.get(plan_id)

    def add_defense_event(self, event: Dict[str, Any]) -> str:
        """Add a defense event."""
        with self._lock:
            event_id = event.get("event_id", str(uuid.uuid4()))
            event["event_id"] = event_id
            self.defense_events[event_id] = event
            return event_id

    def get_defense_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get a defense event by ID."""
        return self.defense_events.get(event_id)

    def list_defense_events(
        self,
        severity: Optional[str] = None,
        resolved: Optional[bool] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List defense events with optional filtering."""
        results = list(self.defense_events.values())
        if severity:
            results = [e for e in results if e.get("severity") == severity]
        if resolved is not None:
            results = [e for e in results if e.get("resolved") == resolved]
        return sorted(results, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    def add_threat_response(self, response: Dict[str, Any]) -> str:
        """Add a threat response."""
        with self._lock:
            response_id = response.get("response_id", str(uuid.uuid4()))
            response["response_id"] = response_id
            self.threat_responses[response_id] = response
            return response_id

    def get_threat_response(self, response_id: str) -> Optional[Dict[str, Any]]:
        """Get a threat response by ID."""
        return self.threat_responses.get(response_id)

    def add_grid_node(self, node: Dict[str, Any]) -> str:
        """Add a grid node."""
        with self._lock:
            node_id = node.get("node_id", str(uuid.uuid4()))
            node["node_id"] = node_id
            self.grid_nodes[node_id] = node
            return node_id

    def get_grid_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get a grid node by ID."""
        return self.grid_nodes.get(node_id)

    def list_grid_nodes(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List grid nodes with optional filtering."""
        results = list(self.grid_nodes.values())
        if status:
            results = [n for n in results if n.get("status") == status]
        return results

    def get_defense_stats(self) -> Dict[str, Any]:
        """Get defense grid statistics."""
        # Policy stats
        enabled_policies = len([p for p in self.policies.values() if p.get("enabled")])
        
        # Action stats
        mitigation_by_status = {}
        for action in self.mitigation_actions.values():
            status = action.get("status", "UNKNOWN")
            mitigation_by_status[status] = mitigation_by_status.get(status, 0) + 1
        
        containment_active = len([
            a for a in self.containment_actions.values()
            if a.get("status") in ("PENDING", "IN_PROGRESS")
        ])
        
        # Event stats
        events_by_severity = {}
        for event in self.defense_events.values():
            severity = event.get("severity", "MEDIUM")
            events_by_severity[severity] = events_by_severity.get(severity, 0) + 1
        
        # Node stats
        nodes_by_status = {}
        for node in self.grid_nodes.values():
            status = node.get("status", "UNKNOWN")
            nodes_by_status[status] = nodes_by_status.get(status, 0) + 1
        
        return {
            "total_policies": len(self.policies),
            "enabled_policies": enabled_policies,
            "total_mitigation_actions": len(self.mitigation_actions),
            "mitigation_by_status": mitigation_by_status,
            "active_containments": containment_active,
            "total_containment_actions": len(self.containment_actions),
            "total_defense_events": len(self.defense_events),
            "events_by_severity": events_by_severity,
            "unresolved_events": len([e for e in self.defense_events.values() if not e.get("resolved")]),
            "total_grid_nodes": len(self.grid_nodes),
            "nodes_by_status": nodes_by_status,
            "active_nodes": len([n for n in self.grid_nodes.values() if n.get("status") == "ACTIVE"]),
            "total_threat_responses": len(self.threat_responses),
        }


# Singleton instance
_store: Optional[DefenseStore] = None


def get_defense_store() -> DefenseStore:
    """Get the global defense store instance."""
    global _store
    if _store is None:
        _store = DefenseStore()
    return _store