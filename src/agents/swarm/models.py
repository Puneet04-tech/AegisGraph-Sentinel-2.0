"""
Swarm Data Models
AegisGraph Sentinel - Multi-agent adversarial simulation & threat hunting swarm.

Defines the core domain objects shared by the swarm coordinator, the
specialized agents (attack simulator, threat hunter, red team, feedback
loop) and the threat intelligence store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SwarmAgentType(str, Enum):
    """Specialized agent roles inside the swarm."""

    ATTACK_SIMULATOR = "attack_simulator"
    THREAT_HUNTER = "threat_hunter"
    PATTERN_HUNTER = "pattern_hunter"
    ANOMALY_EXPLORER = "anomaly_explorer"
    LATERAL_MOVEMENT_MAPPER = "lateral_movement_mapper"
    RED_TEAM = "red_team"


class SwarmAgentStatus(str, Enum):
    """Lifecycle status of a swarm agent."""

    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


class SwarmTaskPriority(str, Enum):
    """Priority of a task submitted to the swarm."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SimulationPolicyMode(str, Enum):
    """How aggressive the adversarial simulation should be."""

    LIGHT = "light"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


@dataclass
class AgentDescriptor:
    """Descriptor for a registered swarm agent."""

    agent_id: str
    agent_type: SwarmAgentType
    status: SwarmAgentStatus = SwarmAgentStatus.IDLE
    capabilities: List[str] = field(default_factory=list)
    tasks_processed: int = 0
    failures: int = 0
    current_task: Optional[str] = None
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    load: float = 0.0


@dataclass
class SwarmTask:
    """A unit of work dispatched to a swarm agent."""

    task_id: str
    task_type: str
    priority: SwarmTaskPriority = SwarmTaskPriority.MEDIUM
    input_data: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: SwarmAgentStatus = SwarmAgentStatus.IDLE
    agent_id: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class SimulationFinding:
    """A single finding produced by a swarm agent."""

    finding_id: str
    agent_type: SwarmAgentType
    severity: str  # low | medium | high | critical
    title: str
    description: str
    entity_ids: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    validated: bool = False
    precision: Optional[float] = None


@dataclass
class ThreatDiscovery:
    """A fraud ring or suspicious cluster discovered by the threat hunter."""

    discovery_id: str
    member_entities: List[str] = field(default_factory=list)
    score: float = 0.0
    discovery_type: str = "fraud_ring"
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    precision: Optional[float] = None


@dataclass
class AttackPattern:
    """A signature describing a simulated or observed attack technique."""

    pattern_id: str
    name: str
    technique: str
    tactics: List[str] = field(default_factory=list)
    entity_type: str = "account"
    temporal_context: str = "short_burst"
    indicators: List[str] = field(default_factory=list)
    detections: Dict[str, Any] = field(default_factory=dict)
    ttp_reference: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class EvasionReport:
    """Result of a red team evasion benchmark."""

    technique: str
    samples: int = 0
    detected: int = 0
    evasion_rate: float = 0.0
    blind_spot: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SwarmReport:
    """Aggregate report of a full simulation cycle."""

    report_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    agent_count: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    discoveries: List[ThreatDiscovery] = field(default_factory=list)
    findings: List[SimulationFinding] = field(default_factory=list)
    attack_patterns_generated: int = 0
    evasion_techniques_tested: int = 0
    blind_spots_found: int = 0
    retraining_triggered: bool = False
    coverage: Dict[str, Any] = field(default_factory=dict)
