"""
Data Governance Engine.

Manages data policies, classification, and access control.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import DataClassification, DataDomain, DataPolicy
from .store import SecurityDataFabricStore, get_fabric_store


class GovernanceEngine:
    """Engine for data governance operations."""

    def __init__(self, store: Optional[SecurityDataFabricStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_fabric_store()

    def create_policy(
        self,
        name: str,
        description: str,
        domain: str,
        classification: str,
        rules: List[Dict[str, Any]],
        enforced: bool = True,
    ) -> DataPolicy:
        """Create a new data policy."""
        policy_id = f"policy-{uuid.uuid4().hex[:12]}"
        
        policy = DataPolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            domain=DataDomain(domain),
            classification=DataClassification(classification),
            rules=rules,
            enforced=enforced,
        )
        
        self.store.add_policy(policy)
        return policy

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get a policy by ID."""
        policy = self.store.get_policy(policy_id)
        if not policy:
            return None
        
        return {
            "policy_id": policy.policy_id,
            "name": policy.name,
            "description": policy.description,
            "domain": policy.domain.value,
            "classification": policy.classification.value,
            "rules": policy.rules,
            "enforced": policy.enforced,
            "created_at": policy.created_at.isoformat(),
        }

    def get_applicable_policies(
        self,
        domain: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get policies applicable to a domain/classification."""
        policies = list(self.store._policies.values())
        
        if domain:
            domain_enum = DataDomain(domain)
            policies = [p for p in policies if p.domain == domain_enum]
        
        if classification:
            class_enum = DataClassification(classification)
            policies = [p for p in policies if p.classification == class_enum]
        
        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "rules": p.rules,
                "enforced": p.enforced,
            }
            for p in policies
        ]

    def validate_access(
        self,
        user_id: str,
        asset_domain: str,
        asset_classification: str,
        action: str,
    ) -> Dict[str, Any]:
        """Validate if a user can perform an action on an asset."""
        applicable = self.get_applicable_policies(domain=asset_domain, classification=asset_classification)
        
        for policy in applicable:
            if not policy["enforced"]:
                continue
            
            for rule in policy["rules"]:
                if rule.get("action") == action or rule.get("action") == "*":
                    if rule.get("deny"):
                        return {
                            "allowed": False,
                            "reason": f"Policy {policy['name']} denies this action",
                            "policy_id": policy["policy_id"],
                        }
        
        return {
            "allowed": True,
            "reason": "No policy denies this action",
            "policies_checked": len(applicable),
        }

    def get_governance_report(self) -> Dict[str, Any]:
        """Get governance status report."""
        policies = list(self.store._policies.values())
        enforced = len([p for p in policies if p.enforced])
        
        return {
            "total_policies": len(policies),
            "enforced_policies": enforced,
            "policies_by_domain": {
                d.value: len([p for p in policies if p.domain == d])
                for d in DataDomain
            },
            "policies_by_classification": {
                c.value: len([p for p in policies if p.classification == c])
                for c in DataClassification
            },
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