"""
Autonomous Enterprise Defense Grid Module for AegisGraph Sentinel 2.0

Production-grade autonomous defense grid capable of:
- Real-time threat detection and prevention
- Automatic containment of compromised entities
- Intelligent mitigation of security threats
- Autonomous recovery and self-healing
- Distributed defense across grid nodes
- Policy-driven security operations

Exports:
    Models:
        DefensePolicy, MitigationAction, ContainmentAction, RecoveryPlan
        DefenseEvent, ThreatResponse, GridNode
        ActionStatus, ActionPriority, ThreatSeverity, NodeStatus
    
    Stores:
        DefenseStore - Central storage for defense data
    
    Controllers:
        DefenseGridController - Orchestrates defense operations
        SelfHealingEngine - Autonomous recovery and self-healing

Usage:
    from src.defense_grid import (
        get_defense_store,
        get_defense_controller,
        get_self_healing_engine,
    )
    
    store = get_defense_store()
    controller = get_defense_controller()
    healing = get_self_healing_engine()
"""

from .models import (
    # Enums
    ActionStatus,
    ActionPriority,
    ThreatSeverity,
    NodeStatus,
    PolicyType,
    # Models
    DefensePolicy,
    MitigationAction,
    ContainmentAction,
    RecoveryPlan,
    DefenseEvent,
    ThreatResponse,
    GridNode,
)
from .store import DefenseStore, get_defense_store
from .controller import (
    DefenseGridController,
    DefenseCommand,
    get_defense_controller,
)
from .self_healing import (
    SelfHealingEngine,
    HealingAction,
    get_self_healing_engine,
)


__all__ = [
    # Enums
    "ActionStatus",
    "ActionPriority",
    "ThreatSeverity",
    "NodeStatus",
    "PolicyType",
    # Models
    "DefensePolicy",
    "MitigationAction",
    "ContainmentAction",
    "RecoveryPlan",
    "DefenseEvent",
    "ThreatResponse",
    "GridNode",
    # Store
    "DefenseStore",
    "get_defense_store",
    # Controllers
    "DefenseGridController",
    "DefenseCommand",
    "get_defense_controller",
    # Self-Healing
    "SelfHealingEngine",
    "HealingAction",
    "get_self_healing_engine",
]