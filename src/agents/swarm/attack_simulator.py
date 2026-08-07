"""
Attack Simulator
AegisGraph Sentinel - Synthetic mule behavior and attack pattern generation.

Generates realistic synthetic mule account behaviours, transaction
laundering patterns and identity fraud scenarios on the entity graph so the
swarm can probe detection coverage gaps before real attackers exploit them.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .models import AttackPattern

FRAUD_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "slow_drip": {
        "description": "Frequent small transfers kept below attention thresholds over a long window",
        "tactics": ["initial_access", "exfiltration"],
        "indicators": ["low_amount", "high_frequency", "long_duration", "consistent_schedule"],
        "temporal_context": "long_span",
        "ttp_reference": "T1005",
    },
    "structured_amounts": {
        "description": "Transaction amounts deliberately kept just below reporting thresholds",
        "tactics": ["defense_evasion"],
        "indicators": ["amount_just_below_threshold", "regular_intervals", "round_numbers"],
        "temporal_context": "short_burst",
        "ttp_reference": "T1030",
    },
    "entity_hopping": {
        "description": "Funds rapidly relayed across many freshly created accounts to obscure the trail",
        "tactics": ["defense_evasion", "resource_development"],
        "indicators": ["fresh_accounts", "short_hop_chain", "high_relay_speed"],
        "temporal_context": "short_burst",
        "ttp_reference": "T1565",
    },
    "fan_out": {
        "description": "A single mule account disburses to many downstream accounts in one burst",
        "tactics": ["exfiltration"],
        "indicators": ["one_to_many", "burst_timing", "disjoint_counterparties"],
        "temporal_context": "short_burst",
        "ttp_reference": "T1567",
    },
    "fan_in": {
        "description": "Many low-value accounts converge on a single accumulator account",
        "tactics": ["collection"],
        "indicators": ["many_to_one", "convergence", "amount_normalization"],
        "temporal_context": "medium_span",
        "ttp_reference": "T1074",
    },
    "smurfing": {
        "description": "A large amount split into many small transactions across accounts",
        "tactics": ["defense_evasion"],
        "indicators": ["split_amounts", "small_ticket", "aggregate_target", "coordinated_timing"],
        "temporal_context": "short_burst",
        "ttp_reference": "T1036",
    },
    "rapid_escalation": {
        "description": "Velocity of a freshly activated account ramps up unnaturally fast",
        "tactics": ["impact"],
        "indicators": ["velocity_spike", "fresh_account", "growing_amounts"],
        "temporal_context": "short_burst",
        "ttp_reference": "T1498",
    },
    "off_hours_activity": {
        "description": "Activity concentrated in hours that evade human review windows",
        "tactics": ["defense_evasion"],
        "indicators": ["unusual_hours", "weekend_cluster", "timing_evasion"],
        "temporal_context": "periodic",
        "ttp_reference": "T1027",
    },
    "round_trip": {
        "description": "Funds cycle back to the source through intermediary accounts",
        "tactics": ["defense_evasion", "exfiltration"],
        "indicators": ["cyclical_flow", "source_reconnect", "layered_hops"],
        "temporal_context": "medium_span",
        "ttp_reference": "T1071",
    },
    "identity_churn": {
        "description": "Repeated synthetic identity reuse across a fleet of mule accounts",
        "tactics": ["resource_development"],
        "indicators": ["identity_reuse", "synthetic_pii", "account_fleet"],
        "temporal_context": "long_span",
        "ttp_reference": "T1585",
    },
}

_MULE_TECHNIQUES = [
    "slow_drip",
    "structured_amounts",
    "entity_hopping",
    "fan_out",
    "fan_in",
    "smurfing",
    "rapid_escalation",
    "off_hours_activity",
    "round_trip",
    "identity_churn",
]


@dataclass
class SyntheticBehavior:
    """A single generated mule behaviour episode."""

    behavior_id: str
    account_id: str
    technique: str
    transaction_count: int
    total_amount: float
    duration_hours: float
    counterparties: List[str] = field(default_factory=list)
    timestamps: List[datetime] = field(default_factory=list)
    amounts: List[float] = field(default_factory=list)


class AttackSimulator:
    """Synthetic adversarial behaviour and attack pattern generator.

    The simulator draws on the ``FRAUD_SIGNATURES`` library so every
    generated behaviour can be validated against a known fraud signature.
    """

    def __init__(
        self,
        seed: Optional[int] = None,
        known_signatures: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self._rng = random.Random(seed)
        self._signatures = known_signatures or FRAUD_SIGNATURES
        self._generated: List[AttackPattern] = []
        self._behaviors: List[SyntheticBehavior] = []

    # ------------------------------------------------------------------
    # Attack pattern generation
    # ------------------------------------------------------------------

    def generate_patterns(self, count: int = 12) -> List[AttackPattern]:
        """Generate ``count`` validated attack patterns.

        Returns:
            List of AttackPattern objects drawn from the signature library.
        """
        patterns: List[AttackPattern] = []
        techniques = list(self._signatures.keys())
        for _ in range(count):
            technique = self._rng.choice(techniques)
            signature = self._signatures[technique]
            pattern = self._build_pattern(technique, signature)
            patterns.append(pattern)
            self._generated.append(pattern)
        return patterns

    def _build_pattern(
        self,
        technique: str,
        signature: Dict[str, Any],
    ) -> AttackPattern:
        return AttackPattern(
            pattern_id=f"pattern-{uuid4().hex[:12]}",
            name=f"{technique.replace('_', ' ').title()} Scenario",
            technique=technique,
            tactics=list(signature["tactics"]),
            entity_type=self._rng.choice(["account", "device", "ip", "identity"]),
            temporal_context=signature["temporal_context"],
            indicators=list(signature["indicators"]),
            detections={
                "simulated": True,
                "signature_match": technique,
            },
            ttp_reference=signature["ttp_reference"],
        )

    def validate_generated_patterns(self) -> Dict[str, Any]:
        """Validate generated patterns against the known signature library.

        Returns:
            Dict with coverage ratio and any unmatched patterns.
        """
        if not self._generated:
            return {"coverage": 0.0, "unmatched": 0, "total": 0, "validated": 0}
        unmatched = [p for p in self._generated if p.technique not in self._signatures]
        coverage = (len(self._generated) - len(unmatched)) / len(self._generated)
        return {
            "coverage": coverage,
            "validated": len(self._generated) - len(unmatched),
            "unmatched": len(unmatched),
            "total": len(self._generated),
        }

    # ------------------------------------------------------------------
    # Mule behaviour generation
    # ------------------------------------------------------------------

    def generate_mule_behavior(
        self,
        technique: Optional[str] = None,
        account_id: Optional[str] = None,
        counterparties: Optional[List[str]] = None,
    ) -> SyntheticBehavior:
        """Generate a synthetic mule behaviour episode."""
        technique = technique or self._rng.choice(_MULE_TECHNIQUES)
        account_id = account_id or f"acc-{uuid4().hex[:8]}"
        counterparties = counterparties or [f"acc-{uuid4().hex[:8]}" for _ in range(3)]

        count = self._rng.randint(8, 40)
        base_amount = self._rng.uniform(50.0, 900.0)
        amounts = [round(base_amount * self._rng.uniform(0.6, 1.4), 2) for _ in range(count)]
        now = datetime.now(timezone.utc)
        timestamps = [now - timedelta(hours=self._rng.uniform(0, 168)) for _ in range(count)]
        timestamps.sort()

        return SyntheticBehavior(
            behavior_id=f"behavior-{uuid4().hex[:12]}",
            account_id=account_id,
            technique=technique,
            transaction_count=count,
            total_amount=round(sum(amounts), 2),
            duration_hours=round((timestamps[-1] - timestamps[0]).total_seconds() / 3600, 2),
            counterparties=counterparties,
            timestamps=timestamps,
            amounts=amounts,
        )

    def generate_mule_fleet(self, size: int = 10) -> List[SyntheticBehavior]:
        """Generate a fleet of coordinated mule behaviours."""
        fleet = []
        for _ in range(size):
            behavior = self.generate_mule_behavior()
            fleet.append(behavior)
            self._behaviors.append(behavior)
        return fleet

    def build_synthetic_graph(self, mules: int = 8, hops: int = 2) -> Dict[str, Any]:
        """Build a synthetic entity graph embedding mule behaviours.

        Returns:
            A dict-based graph with ``nodes`` (entity id, type, attributes)
            and ``edges`` (source, target, amount, timestamp).
        """
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        for i in range(mules):
            mule = self.generate_mule_behavior()
            nodes.append({
                "id": mule.account_id,
                "type": "account",
                "is_mule": True,
                "technique": mule.technique,
            })
            for j in range(min(hops, len(mule.counterparties))):
                target = mule.counterparties[j]
                nodes.append({"id": target, "type": "account", "is_mule": False})
                edges.append({
                    "source": mule.account_id,
                    "target": target,
                    "amount": mule.amounts[j % len(mule.amounts)],
                    "timestamp": mule.timestamps[j % len(mule.timestamps)].isoformat(),
                })
        # Add legitimate decoy nodes so hunters must discriminate.
        for k in range(mules * 3):
            nodes.append({"id": f"legit-{k}", "type": "account", "is_mule": False})
        return {"nodes": nodes, "edges": edges}
