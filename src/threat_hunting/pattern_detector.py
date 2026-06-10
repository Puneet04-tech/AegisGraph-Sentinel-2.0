"""
Attack Pattern Detector Engine for AI Threat Hunting
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .models import ThreatIndicator, IndicatorType, ThreatSeverity
from .store import ThreatHuntingStore, get_store


class AttackPatternDetector:
    """Engine to detect multi-stage attack/fraud patterns."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None):
        self.store = store or get_store()

    def detect_patterns(
        self,
        user_id: str,
        events: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
    ) -> List[ThreatIndicator]:
        """Examine events and relationships to detect coordinated attack patterns."""
        detected: List[ThreatIndicator] = []

        # 1. Account Takeover (ATO) Pattern
        # Pattern: Multiple failed authentication attempts followed by a credential update or password reset
        failed_count = 0
        cred_updated = False
        large_txn_after = False

        for event in events:
            ev_type = event.get("event_type", "")
            if ev_type == "auth_failed":
                failed_count += 1
            elif ev_type == "credential_update" and failed_count >= 2:
                cred_updated = True
            elif ev_type == "transaction" and cred_updated:
                amount = event.get("amount", 0.0)
                if amount > 1000.0:  # Large transaction
                    large_txn_after = True

        if failed_count >= 2 and cred_updated and large_txn_after:
            ind = ThreatIndicator(
                indicator_type=IndicatorType.BEHAVIOR,
                value=user_id,
                description="Potential Account Takeover pattern: failed logins -> credential reset -> large transaction",
                severity=ThreatSeverity.CRITICAL,
                confidence=0.9,
                attributes={"failed_logins": failed_count, "cred_updated": True, "large_txn": True},
            )
            self.store.register_indicator(ind)
            detected.append(ind)

        # 2. Rapid Device Switching
        # Pattern: Multiple logins on different devices in short sequence
        devices = set()
        for event in events:
            device_id = event.get("device_id")
            if device_id and event.get("event_type") == "login":
                devices.add(device_id)

        if len(devices) >= 3:
            ind = ThreatIndicator(
                indicator_type=IndicatorType.FINGERPRINT,
                value=user_id,
                description=f"Rapid Device Switching pattern: Account accessed from {len(devices)} distinct devices",
                severity=ThreatSeverity.HIGH,
                confidence=0.8,
                attributes={"unique_devices": list(devices)},
            )
            self.store.register_indicator(ind)
            detected.append(ind)

        # 3. Circular Transfer Pattern (Loop)
        # Pattern: A -> B -> C -> A
        loops = self._detect_transfer_loops(relationships)
        if loops:
            ind = ThreatIndicator(
                indicator_type=IndicatorType.VELOCITY,
                value=user_id,
                description=f"Circular Transfer Loop detected involving user: {' -> '.join(loops[0])}",
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                attributes={"loops": loops},
            )
            self.store.register_indicator(ind)
            detected.append(ind)

        return detected

    def _detect_transfer_loops(self, relationships: List[Dict[str, Any]]) -> List[List[str]]:
        """Simple DFS-based transfer loop (cycle) detection."""
        adj = {}
        for rel in relationships:
            u = rel.get("from_id")
            v = rel.get("to_id")
            rel_type = rel.get("type", "")
            if u and v and rel_type == "transfer":
                if u not in adj:
                    adj[u] = []
                adj[u].append(v)

        loops = []
        visited = set()
        stack = []

        def dfs(node):
            if node in stack:
                # Loop found! Trace the path from the node's first occurrence in the stack
                idx = stack.index(node)
                loop_path = stack[idx:] + [node]
                loops.append(loop_path)
                return
            if node in visited:
                return

            visited.add(node)
            stack.append(node)
            for neighbor in adj.get(node, []):
                dfs(neighbor)
            stack.pop()

        for start_node in adj:
            dfs(start_node)

        return loops
