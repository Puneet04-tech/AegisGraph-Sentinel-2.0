"""
Fraud Campaign Detector Engine for AI Threat Hunting
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .models import ThreatCampaign, CampaignStatus, ThreatSeverity, ThreatIndicator
from .store import ThreatHuntingStore, get_store


class CampaignDetector:
    """Engine to cluster threat indicators into coordinated fraud campaigns."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None) -> None:
        self.store = store or get_store()

    def _extract_entity(self, ind: ThreatIndicator) -> Optional[str]:
        """Return the affected entity identifier carried by an indicator.

        Entity context is stored per-indicator in ``attributes`` (e.g. the
        ``entity_id`` used as detector input, or the account/device context).
        The raw ``value`` is only the shared grouping attribute (shared IP,
        fingerprint, etc.), so it must never be conflated with the entity ID.
        """
        for key in ("entity_id", "user_id", "account_id"):
            entity = ind.attributes.get(key)
            if entity:
                return str(entity)
        return None

    def detect_campaigns(self) -> List[ThreatCampaign]:
        """Cluster indicators based on shared attributes to identify campaigns."""
        indicators = self.store.list_indicators()

        # Group indicators by value (e.g. shared IP subnet, device fingerprint)
        groups: Dict[str, List[ThreatIndicator]] = {}
        for ind in indicators:
            val = ind.value
            if val:
                if val not in groups:
                    groups[val] = []
                groups[val].append(ind)

        campaigns: List[ThreatCampaign] = []

        for val, ind_list in groups.items():
            # If 3 or more indicators share the same target value, we classify it as a campaign
            if len(ind_list) >= 3:
                entities = list(set(
                    self._extract_entity(ind) or ind.value
                    for ind in ind_list
                ))
                # Fallback to the shared indicator value if no entity context exists
                if not entities:
                    entities = [val]

                indicator_ids = [ind.indicator_id for ind in ind_list]

                # Check if this campaign was already registered
                existing_campaign = None
                for camp in self.store.list_campaigns():
                    if camp.name == f"Coordinated Activity on {val}":
                        existing_campaign = camp
                        break

                if existing_campaign:
                    existing_campaign.associated_entities = list(set(existing_campaign.associated_entities + entities))
                    existing_campaign.associated_indicators = list(set(existing_campaign.associated_indicators + indicator_ids))
                    existing_campaign.last_active = datetime.now(timezone.utc).isoformat()
                    self.store.set_campaign(existing_campaign)
                    campaigns.append(existing_campaign)
                else:
                    campaign = ThreatCampaign(
                        name=f"Coordinated Activity on {val}",
                        description=f"Automated clustering detected {len(ind_list)} threat indicators linked to target '{val}'",
                        status=CampaignStatus.ACTIVE,
                        severity=ThreatSeverity.HIGH,
                        associated_entities=entities,
                        associated_indicators=indicator_ids,
                        confidence=0.8,
                    )
                    self.store.set_campaign(campaign)
                    campaigns.append(campaign)

        return campaigns
