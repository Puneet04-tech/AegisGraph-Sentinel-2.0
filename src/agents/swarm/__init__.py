"""
Adversarial Simulation & Threat Hunting Swarm
AegisGraph Sentinel - Multi-agent proactive fraud detection.

Provides a swarm of specialized agents (attack simulator, threat hunter, red
team, feedback loop) coordinated by a work-stealing coordinator, backed by a
shared threat intelligence store and TTP knowledge graph.
"""

from __future__ import annotations

from .models import (
    AgentDescriptor,
    AttackPattern,
    EvasionReport,
    SimulationFinding,
    SwarmAgentStatus,
    SwarmAgentType,
    SwarmReport,
    SwarmTask,
    SwarmTaskPriority,
    ThreatDiscovery,
)
from .store import ThreatIntelligenceStore, get_threat_intelligence_store
from .coordinator import SwarmCoordinator, WorkStealingCoordinator
from .attack_simulator import AttackSimulator, FRAUD_SIGNATURES
from .threat_hunter import ThreatHunter
from .red_team import RedTeamAgent, EVASION_TECHNIQUES
from .feedback_loop import FeedbackLoop
from .threat_intelligence_graph import ThreatIntelligenceGraph
from .dashboard import SwarmDashboard
from .policies import (
    PolicyRole,
    SimulationPolicy,
    SimulationPolicyEngine,
    PermissionDeniedError,
)

__all__ = [
    "AgentDescriptor",
    "AttackPattern",
    "EvasionReport",
    "SimulationFinding",
    "SwarmAgentStatus",
    "SwarmAgentType",
    "SwarmReport",
    "SwarmTask",
    "SwarmTaskPriority",
    "ThreatDiscovery",
    "ThreatIntelligenceStore",
    "get_threat_intelligence_store",
    "SwarmCoordinator",
    "WorkStealingCoordinator",
    "AttackSimulator",
    "FRAUD_SIGNATURES",
    "ThreatHunter",
    "RedTeamAgent",
    "EVASION_TECHNIQUES",
    "FeedbackLoop",
    "ThreatIntelligenceGraph",
    "SwarmDashboard",
    "PolicyRole",
    "SimulationPolicy",
    "SimulationPolicyEngine",
    "PermissionDeniedError",
]
