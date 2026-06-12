"""
Data models for Autonomous Enterprise Defense Grid.

Core models:
    DefensePolicy: Defense policy configuration
    MitigationAction: Mitigation action definition
    ContainmentAction: Containment action definition
    RecoveryPlan: Recovery plan for compromised systems
    DefenseEvent: Defense event log
    ThreatResponse: Threat response record
    GridNode: Defense grid node configuration
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
import uuid


class ActionStatus(str, Enum):
    """Status of an action."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ActionPriority(str, Enum):
    """Priority levels for actions."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class NodeStatus(str, Enum):
    """Defense grid node status."""
    ACTIVE = "ACTIVE"
    STANDBY = "STANDBY"
    ISOLATED = "ISOLATED"
    OFFLINE = "OFFLINE"
    COMPROMISED = "COMPROMISED"


class PolicyType(str, Enum):
    """Defense policy types."""
    PREVENTION = "PREVENTION"
    DETECTION = "DETECTION"
    CONTAINMENT = "CONTAINMENT"
    RECOVERY = "RECOVERY"
    MONITORING = "MONITORING"


@dataclass
class DefensePolicy:
    """Defense policy configuration.
    
    Attributes:
        policy_id: Unique identifier
        name: Policy name
        type: Policy type
        description: Policy description
        priority: Policy priority
        enabled: Whether policy is enabled
        conditions: Trigger conditions
        actions: Actions to execute
        cooldown_seconds: Minimum time between triggers
        last_triggered: Last trigger timestamp
    """
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    type: PolicyType = PolicyType.DETECTION
    description: str = ""
    priority: ActionPriority = ActionPriority.MEDIUM
    enabled: bool = True
    conditions: Dict[str, Any] = field(default_factory=dict)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    cooldown_seconds: int = 300
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "type": self.type.value,
            "description": self.description,
            "priority": self.priority.value,
            "enabled": self.enabled,
            "conditions": self.conditions,
            "actions": self.actions,
            "cooldown_seconds": self.cooldown_seconds,
            "last_triggered": self.last_triggered.isoformat() if self.last_triggered else None,
            "trigger_count": self.trigger_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "metadata": self.metadata,
        }


@dataclass
class MitigationAction:
    """Mitigation action definition.
    
    Attributes:
        action_id: Unique identifier
        name: Action name
        action_type: Type of mitigation
        description: Action description
        target_entity: Entity to act on
        execution_time_seconds: Estimated execution time
        rollback_available: Whether rollback is possible
        prerequisites: Prerequisites for execution
        estimated_impact: Estimated impact on operations
    """
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    action_type: str = ""
    description: str = ""
    target_entity: str = ""
    target_entity_type: str = ""
    execution_time_seconds: int = 30
    rollback_available: bool = True
    rollback_action_id: Optional[str] = None
    prerequisites: List[str] = field(default_factory=list)
    estimated_impact: str = "MINIMAL"
    required_permissions: List[str] = field(default_factory=list)
    status: ActionStatus = ActionStatus.PENDING
    initiated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    initiated_by: str = "SYSTEM"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_id": self.action_id,
            "name": self.name,
            "action_type": self.action_type,
            "description": self.description,
            "target_entity": self.target_entity,
            "target_entity_type": self.target_entity_type,
            "execution_time_seconds": self.execution_time_seconds,
            "rollback_available": self.rollback_available,
            "rollback_action_id": self.rollback_action_id,
            "prerequisites": self.prerequisites,
            "estimated_impact": self.estimated_impact,
            "required_permissions": self.required_permissions,
            "status": self.status.value,
            "initiated_at": self.initiated_at.isoformat() if self.initiated_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "initiated_by": self.initiated_by,
            "result": self.result,
            "error": self.error,
            "metadata": self.metadata,
        }


@dataclass
class ContainmentAction:
    """Containment action definition.
    
    Attributes:
        action_id: Unique identifier
        containment_type: Type of containment
        target_entity: Entity to contain
        duration_seconds: Containment duration
        auto_extend: Whether to auto-extend if needed
        isolation_scope: What to isolate
        status: Containment status
    """
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    containment_type: str = ""
    target_entity: str = ""
    target_entity_type: str = ""
    duration_seconds: int = 3600
    auto_extend: bool = True
    max_extensions: int = 3
    extension_count: int = 0
    isolation_scope: List[str] = field(default_factory=list)
    status: ActionStatus = ActionStatus.PENDING
    initiated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    released_at: Optional[datetime] = None
    initiated_by: str = "SYSTEM"
    reason: str = ""
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_id": self.action_id,
            "containment_type": self.containment_type,
            "target_entity": self.target_entity,
            "target_entity_type": self.target_entity_type,
            "duration_seconds": self.duration_seconds,
            "auto_extend": self.auto_extend,
            "max_extensions": self.max_extensions,
            "extension_count": self.extension_count,
            "isolation_scope": self.isolation_scope,
            "status": self.status.value,
            "initiated_at": self.initiated_at.isoformat() if self.initiated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "released_at": self.released_at.isoformat() if self.released_at else None,
            "initiated_by": self.initiated_by,
            "reason": self.reason,
            "result": self.result,
            "error": self.error,
            "metadata": self.metadata,
        }


@dataclass
class RecoveryPlan:
    """Recovery plan for compromised systems.
    
    Attributes:
        plan_id: Unique identifier
        name: Plan name
        target_entity: Entity to recover
        phases: Recovery phases
        estimated_duration: Estimated completion time
        prerequisites: Prerequisites for recovery
    """
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    target_entity: str = ""
    target_entity_type: str = ""
    phases: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "PENDING"
    estimated_duration_seconds: int = 0
    actual_duration_seconds: int = 0
    prerequisites: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_phase: int = 0
    completed_phases: List[str] = field(default_factory=list)
    failed_phases: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plan_id": self.plan_id,
            "name": self.name,
            "description": self.description,
            "target_entity": self.target_entity,
            "target_entity_type": self.target_entity_type,
            "phases": self.phases,
            "status": self.status,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "actual_duration_seconds": self.actual_duration_seconds,
            "prerequisites": self.prerequisites,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "current_phase": self.current_phase,
            "completed_phases": self.completed_phases,
            "failed_phases": self.failed_phases,
            "metadata": self.metadata,
        }


@dataclass
class DefenseEvent:
    """Defense event log entry.
    
    Attributes:
        event_id: Unique identifier
        event_type: Type of event
        severity: Event severity
        source: Event source
        description: Event description
        affected_entities: Affected entities
        actions_taken: Actions taken
        timestamp: Event timestamp
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    source: str = ""
    source_ip: Optional[str] = None
    description: str = ""
    affected_entities: List[Dict[str, Any]] = field(default_factory=list)
    related_threat_id: Optional[str] = None
    related_campaign_id: Optional[str] = None
    actions_taken: List[str] = field(default_factory=list)
    action_ids: List[str] = field(default_factory=list)
    response_time_ms: float = 0.0
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "source": self.source,
            "source_ip": self.source_ip,
            "description": self.description,
            "affected_entities": self.affected_entities,
            "related_threat_id": self.related_threat_id,
            "related_campaign_id": self.related_campaign_id,
            "actions_taken": self.actions_taken,
            "action_ids": self.action_ids,
            "response_time_ms": self.response_time_ms,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ThreatResponse:
    """Threat response record.
    
    Attributes:
        response_id: Unique identifier
        threat_id: Related threat ID
        threat_type: Type of threat
        severity: Threat severity
        actions: Response actions taken
        outcome: Response outcome
        lessons_learned: Lessons from response
    """
    response_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_id: str = ""
    threat_type: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    detection_time: Optional[datetime] = None
    response_start_time: Optional[datetime] = None
    response_end_time: Optional[datetime] = None
    detection_method: str = ""
    affected_entities: List[str] = field(default_factory=list)
    actions_taken: List[Dict[str, Any]] = field(default_factory=list)
    containment_required: bool = False
    mitigation_required: bool = False
    recovery_required: bool = False
    outcome: str = "SUCCESS"
    threat_neutralized: bool = False
    false_positive: bool = False
    lessons_learned: List[str] = field(default_factory=list)
    response_effectiveness: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "response_id": self.response_id,
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "severity": self.severity.value,
            "detection_time": self.detection_time.isoformat() if self.detection_time else None,
            "response_start_time": self.response_start_time.isoformat() if self.response_start_time else None,
            "response_end_time": self.response_end_time.isoformat() if self.response_end_time else None,
            "detection_method": self.detection_method,
            "affected_entities": self.affected_entities,
            "actions_taken": self.actions_taken,
            "containment_required": self.containment_required,
            "mitigation_required": self.mitigation_required,
            "recovery_required": self.recovery_required,
            "outcome": self.outcome,
            "threat_neutralized": self.threat_neutralized,
            "false_positive": self.false_positive,
            "lessons_learned": self.lessons_learned,
            "response_effectiveness": self.response_effectiveness,
            "metadata": self.metadata,
        }


@dataclass
class GridNode:
    """Defense grid node configuration.
    
    Attributes:
        node_id: Unique identifier
        name: Node name
        type: Node type
        capabilities: Node capabilities
        status: Node status
        health: Node health score
    """
    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    node_type: str = ""
    capabilities: List[str] = field(default_factory=list)
    status: NodeStatus = NodeStatus.ACTIVE
    health_score: float = 100.0
    last_heartbeat: Optional[datetime] = None
    region: Optional[str] = None
    datacenter: Optional[str] = None
    ip_address: Optional[str] = None
    active_policies: List[str] = field(default_factory=list)
    processed_events: int = 0
    avg_response_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "node_id": self.node_id,
            "name": self.name,
            "node_type": self.node_type,
            "capabilities": self.capabilities,
            "status": self.status.value,
            "health_score": self.health_score,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "region": self.region,
            "datacenter": self.datacenter,
            "ip_address": self.ip_address,
            "active_policies": self.active_policies,
            "processed_events": self.processed_events,
            "avg_response_time_ms": self.avg_response_time_ms,
            "metadata": self.metadata,
        }