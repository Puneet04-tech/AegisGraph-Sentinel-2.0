"""
Behavior Analytics Engine for AI Threat Hunting
"""

import math
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .models import BehaviorProfile
from .store import ThreatHuntingStore, get_store


class BehaviorAnalyticsEngine:
    """Engine to build entity profiles and analyze baseline deviations."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None):
        self.store = store or get_store()

    def get_or_create_profile(self, entity_id: str, entity_type: str = "user") -> BehaviorProfile:
        """Fetch or create a baseline behavior profile for an entity."""
        profile = self.store.get_profile(entity_id)
        if not profile:
            profile = BehaviorProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                typical_hours=[9, 10, 11, 12, 13, 14, 15, 16, 17, 18],  # Business hours default
                typical_amount_mean=100.0,
                typical_amount_std=50.0,
                known_ips=[],
                known_devices=[],
                velocity_limit_per_min=5,
            )
            self.store.set_profile(profile)
        return profile

    def update_profile_statistics(
        self,
        entity_id: str,
        amounts: List[float],
        hours: List[int],
        ips: List[str],
        devices: List[str],
    ) -> BehaviorProfile:
        """Update behavior profile baseline stats with historical transaction data."""
        profile = self.get_or_create_profile(entity_id)

        if amounts:
            mean = sum(amounts) / len(amounts)
            variance = sum((x - mean) ** 2 for x in amounts) / len(amounts)
            std = math.sqrt(variance) if variance > 0 else 1.0
            profile.typical_amount_mean = mean
            profile.typical_amount_std = max(1.0, std)

        if hours:
            profile.typical_hours = list(set(hours))

        for ip in ips:
            if ip not in profile.known_ips:
                profile.known_ips.append(ip)

        for device in devices:
            if device not in profile.known_devices:
                profile.known_devices.append(device)

        return self.store.set_profile(profile)

    def evaluate_behavior(
        self,
        entity_id: str,
        amount: float,
        hour: int,
        ip: str,
        device_id: str,
        recent_txn_count_1m: int,
    ) -> Dict[str, Any]:
        """Evaluate current transaction parameters against the entity's baseline profile."""
        profile = self.get_or_create_profile(entity_id)

        # 1. Time deviation
        time_score = 0.0
        if profile.typical_hours and hour not in profile.typical_hours:
            time_score = 0.5  # Off-hours deviation

        # 2. Amount deviation (Z-score)
        amount_score = 0.0
        if profile.typical_amount_std > 0:
            z_score = abs(amount - profile.typical_amount_mean) / profile.typical_amount_std
            # Map Z-score to 0-1 range
            amount_score = min(1.0, z_score * 0.2)

        # 3. Network / Location / Device deviation
        network_score = 0.0
        if profile.known_ips and ip not in profile.known_ips:
            network_score += 0.3
        if profile.known_devices and device_id not in profile.known_devices:
            network_score += 0.4
        network_score = min(1.0, network_score)

        # 4. Velocity deviation
        velocity_score = 0.0
        if recent_txn_count_1m > profile.velocity_limit_per_min:
            velocity_score = min(1.0, (recent_txn_count_1m - profile.velocity_limit_per_min) * 0.2)

        # Overall behavioral deviation score (simple average of dimensions)
        overall_score = (time_score + amount_score + network_score + velocity_score) / 4.0
        overall_score = max(0.0, min(1.0, overall_score))

        return {
            "overall_deviation": overall_score,
            "breakdown": {
                "time_deviation": time_score,
                "amount_deviation": amount_score,
                "network_deviation": network_score,
                "velocity_deviation": velocity_score,
            },
        }
