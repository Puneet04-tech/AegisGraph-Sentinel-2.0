"""
Encryption Governance Service.

Manages cryptographic governance policies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import CryptoAlgorithm, GovernancePolicy, RiskLevel
from .store import QuantumSecurityStore, get_quantum_store


class GovernanceEngine:
    """Engine for cryptographic governance."""

    def __init__(self, store: Optional[QuantumSecurityStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_quantum_store()

    def create_policy(
        self,
        name: str,
        description: str,
        rules: List[Dict[str, Any]],
        enforced: bool = True,
    ) -> GovernancePolicy:
        """Create a governance policy."""
        policy_id = f"policy-{uuid.uuid4().hex[:12]}"
        
        policy = GovernancePolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            rules=rules,
            enforced=enforced,
        )
        
        self.store.add_policy(policy)
        
        self.store.log_audit(
            user_id="system",
            action="policy_created",
            resource_type="governance_policy",
            resource_id=policy_id,
            details={"name": name},
        )
        
        return policy

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get policy details."""
        policy = self.store.get_policy(policy_id)
        if not policy:
            return None
        
        return {
            "policy_id": policy.policy_id,
            "name": policy.name,
            "description": policy.description,
            "rules": policy.rules,
            "enforced": policy.enforced,
            "created_at": policy.created_at.isoformat(),
        }

    def get_all_policies(self) -> List[Dict[str, Any]]:
        """Get all policies."""
        policies = list(self.store._policies.values())
        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "description": p.description,
                "enforced": p.enforced,
            }
            for p in policies
        ]

    def validate_compliance(
        self,
        algorithm: str,
        key_size: int,
    ) -> Dict[str, Any]:
        """Validate cryptographic compliance."""
        algo_enum = CryptoAlgorithm(algorithm)
        enforced_policies = self.store.get_enforced_policies()
        
        violations = []
        for policy in enforced_policies:
            for rule in policy.rules:
                if rule.get("type") == "algorithm_restriction":
                    allowed = rule.get("allowed_algorithms", [])
                    if algo_enum.value not in allowed:
                        violations.append({
                            "policy": policy.name,
                            "violation": f"Algorithm {algorithm} not in allowed list",
                        })
                
                elif rule.get("type") == "key_size_requirement":
                    min_size = rule.get("minimum_key_size", 0)
                    if key_size < min_size:
                        violations.append({
                            "policy": policy.name,
                            "violation": f"Key size {key_size} below minimum {min_size}",
                        })
        
        return {
            "compliant": len(violations) == 0,
            "algorithm": algorithm,
            "key_size": key_size,
            "violations": violations,
        }

    def get_governance_status(self) -> Dict[str, Any]:
        """Get governance status."""
        policies = list(self.store._policies.values())
        enforced = len([p for p in policies if p.enforced])
        
        return {
            "total_policies": len(policies),
            "enforced_policies": enforced,
            "non_enforced_policies": len(policies) - enforced,
        }


# Singleton instance
_engine: Optional[GovernanceEngine] = None


def get_governance_engine() -> GovernanceEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = GovernanceEngine()
    return _engine


def reset_governance_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None