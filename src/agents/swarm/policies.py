"""
Simulation Policy Engine
AegisGraph Sentinel - Configurable adversarial simulation policies.

Policies define the intensity, frequency and target patterns of adversarial
testing based on tenant risk profiles. The engine enforces role-based access
control so only authorised operators and administrators can mutate policies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class PolicyRole(str, Enum):
    """Roles that can interact with simulation policies."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class PolicyPermission(str, Enum):
    """Granular permissions used for role-based access control."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMINISTER = "administer"


ROLE_PERMISSIONS: Dict[PolicyRole, set] = {
    PolicyRole.VIEWER: {PolicyPermission.READ},
    PolicyRole.OPERATOR: {PolicyPermission.READ, PolicyPermission.WRITE},
    PolicyRole.ADMIN: {
        PolicyPermission.READ,
        PolicyPermission.WRITE,
        PolicyPermission.DELETE,
        PolicyPermission.ADMINISTER,
    },
}

DEFAULT_TARGET_PATTERNS = [
    "slow_drip",
    "structured_amounts",
    "entity_hopping",
    "fan_out",
    "fan_in",
    "smurfing",
]


@dataclass
class SimulationPolicy:
    """Defines how aggressively a tenant's environment is probed."""

    policy_id: str
    tenant_id: str
    intensity: float = 0.5
    frequency: str = "daily"
    target_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_TARGET_PATTERNS))
    mode: str = "standard"
    max_concurrent_agents: int = 32
    created_by: str = "system"


class PermissionDeniedError(PermissionError):
    """Raised when a role lacks permission for a policy operation."""


class SimulationPolicyEngine:
    """Tenant-configurable simulation policy engine with RBAC.

    Policy lifecycle:

        create -> update -> delete

    Mutations require ``OPERATOR`` (create/update) or ``ADMIN`` (delete);
    reads are available to any authenticated role.
    """

    def __init__(self) -> None:
        self._policies: Dict[str, SimulationPolicy] = {}
        self._tenant_profiles: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Policy lifecycle (RBAC guarded)
    # ------------------------------------------------------------------

    def create_policy(
        self,
        tenant_id: str,
        actor_role: PolicyRole,
        intensity: float = 0.5,
        frequency: str = "daily",
        target_patterns: Optional[List[str]] = None,
        mode: str = "standard",
        max_concurrent_agents: int = 32,
    ) -> SimulationPolicy:
        """Create a policy for a tenant.

        Raises:
            PermissionDeniedError: if the actor role cannot write policies.
            ValueError: if intensity is outside ``[0, 1]``.
        """
        self._require(actor_role, PolicyPermission.WRITE)
        if not 0.0 <= intensity <= 1.0:
            raise ValueError("intensity must be within [0.0, 1.0]")
        policy = SimulationPolicy(
            policy_id=f"policy-{uuid4().hex[:12]}",
            tenant_id=tenant_id,
            intensity=intensity,
            frequency=frequency,
            target_patterns=list(target_patterns or DEFAULT_TARGET_PATTERNS),
            mode=mode,
            max_concurrent_agents=max_concurrent_agents,
            created_by=actor_role.value,
        )
        self._policies[policy.policy_id] = policy
        return policy

    def update_policy(
        self,
        policy_id: str,
        actor_role: PolicyRole,
        **updates: Any,
    ) -> Optional[SimulationPolicy]:
        """Update fields of an existing policy.

        Raises:
            PermissionDeniedError: if the actor role cannot write policies.
        """
        self._require(actor_role, PolicyPermission.WRITE)
        policy = self._policies.get(policy_id)
        if policy is None:
            return None
        if "intensity" in updates:
            value = float(updates["intensity"])
            if not 0.0 <= value <= 1.0:
                raise ValueError("intensity must be within [0.0, 1.0]")
            policy.intensity = value
        if "frequency" in updates:
            policy.frequency = str(updates["frequency"])
        if "target_patterns" in updates:
            policy.target_patterns = list(updates["target_patterns"])
        if "mode" in updates:
            policy.mode = str(updates["mode"])
        if "max_concurrent_agents" in updates:
            policy.max_concurrent_agents = int(updates["max_concurrent_agents"])
        return policy

    def delete_policy(self, policy_id: str, actor_role: PolicyRole) -> bool:
        """Delete a policy (admin only)."""
        self._require(actor_role, PolicyPermission.DELETE)
        return self._policies.pop(policy_id, None) is not None

    def get_policy(self, policy_id: str, actor_role: PolicyRole) -> Optional[SimulationPolicy]:
        """Read a single policy."""
        self._require(actor_role, PolicyPermission.READ)
        return self._policies.get(policy_id)

    def list_policies(self, actor_role: PolicyRole, tenant_id: Optional[str] = None) -> List[SimulationPolicy]:
        """List policies, optionally filtered by tenant."""
        self._require(actor_role, PolicyPermission.READ)
        policies = list(self._policies.values())
        if tenant_id is not None:
            policies = [p for p in policies if p.tenant_id == tenant_id]
        return policies

    # ------------------------------------------------------------------
    # Tenant risk profiles
    # ------------------------------------------------------------------

    def set_tenant_profile(self, tenant_id: str, risk_level: str) -> None:
        """Register the risk profile of a tenant (high/medium/low)."""
        self._tenant_profiles[tenant_id] = {"risk_level": risk_level}

    def apply_to_tenant(self, tenant_id: str) -> SimulationPolicy:
        """Resolve the effective policy for a tenant.

        Tenants without an explicit policy receive a risk-proportional
        default: high-risk tenants get more aggressive coverage.
        """
        for policy in self._policies.values():
            if policy.tenant_id == tenant_id:
                return policy
        profile = self._tenant_profiles.get(tenant_id, {"risk_level": "medium"})
        if profile["risk_level"] == "high":
            intensity = 0.8
        elif profile["risk_level"] == "low":
            intensity = 0.3
        else:
            intensity = 0.5
        return SimulationPolicy(
            policy_id=f"policy-default-{tenant_id}",
            tenant_id=tenant_id,
            intensity=intensity,
            frequency="daily",
            target_patterns=list(DEFAULT_TARGET_PATTERNS),
            mode="standard",
        )

    # ------------------------------------------------------------------
    # RBAC helpers
    # ------------------------------------------------------------------

    def _require(self, actor_role: PolicyRole, permission: PolicyPermission) -> None:
        if permission not in ROLE_PERMISSIONS.get(actor_role, set()):
            raise PermissionDeniedError(
                f"Role '{actor_role.value}' lacks permission '{permission.value}'"
            )
