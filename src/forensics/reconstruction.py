"""Attack Reconstruction Engine to trace fraud paths and build attack chains.

This module is deliberately self-contained so that Phase 8 can be deployed
without depending on Phase 7 (threat_intelligence).  Campaign metadata is
derived from the case store and a simple indicator-extraction helper defined
below.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from src.case_management import get_case_store
from .models import AttackChain
from .store import get_forensics_store

logger = logging.getLogger("forensics.reconstruction")


# ---------------------------------------------------------------------------
# Standalone helpers (no Phase 7 dependency)
# ---------------------------------------------------------------------------

def _extract_features_from_case(case: object) -> Tuple[str, str, str]:
    """Extract (ip, device, account) indicator strings from a case object.

    Derives indicators from the ``tags`` list on FraudCase using the
    ``key:value`` tag convention (e.g. ``ip:1.2.3.4``, ``device:DEV_X``).
    Falls back to empty strings for any missing indicator.
    """
    tags: List[str] = list(getattr(case, "tags", []) or [])
    ip = device = account = ""
    for tag in tags:
        if tag.startswith("ip:"):
            ip = tag[3:]
        elif tag.startswith("device:"):
            device = tag[7:]
        elif tag.startswith("account:"):
            account = tag[8:]
    return ip, device, account


class _InMemoryCampaign:
    """Lightweight struct that groups cases sharing the same campaign_id tag."""

    def __init__(self, campaign_id: str, case_ids: List[str]) -> None:
        self.campaign_id = campaign_id
        self.case_ids = case_ids


def _find_campaign(case_store, campaign_id: str) -> Optional[_InMemoryCampaign]:
    """Locate all cases tagged ``campaign:<campaign_id>`` from the case store.

    Uses the public ``list_cases`` interface so it does not depend on any
    threat-intelligence layer.  Cases opt into a campaign by carrying the
    tag ``campaign:<campaign_id>`` in their tags list.

    Note: list_cases() returns (List[FraudCase], total_count) — we unpack it.
    """
    try:
        all_cases, _ = case_store.list_cases(page=1, page_size=10_000)
    except Exception:
        all_cases = []

    tag_prefix = f"campaign:{campaign_id}"
    matched_ids: List[str] = [
        getattr(case, "case_id", str(id(case)))
        for case in all_cases
        if tag_prefix in (getattr(case, "tags", []) or [])
    ]

    if not matched_ids:
        return None
    return _InMemoryCampaign(campaign_id=campaign_id, case_ids=matched_ids)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AttackReconstructionEngine:
    """Discovers and reconstructs chronological multi-hop attack paths and fraud loops."""

    def __init__(self) -> None:
        self.forensics_store = get_forensics_store()
        self.case_store = get_case_store()

    def reconstruct_campaign(self, campaign_id: str) -> Optional[AttackChain]:
        """Trace transaction flows and indicators within a campaign to build an attack chain.

        Returns the cached chain if one already exists.  Otherwise derives the
        chain from the case store and persists it.
        """
        # 1. Return cached chain if available
        cached_chain = self.forensics_store.get_chain_by_campaign(campaign_id)
        if cached_chain:
            return cached_chain

        # 2. Find campaign (derived from cases — no Phase 7 dependency)
        campaign = _find_campaign(self.case_store, campaign_id)
        if not campaign:
            logger.warning("Campaign ID '%s' not found.", campaign_id)
            return None

        # 3. Gather all cases associated with the campaign
        campaign_cases = []
        for case_id in campaign.case_ids:
            case = self.case_store.get_case(case_id)
            if case:
                campaign_cases.append(case)

        # Sort chronologically (ISO-8601 string sort is lexicographically correct)
        campaign_cases.sort(key=lambda c: getattr(c, "created_at", ""))

        # 4. Construct attack hops
        steps: List[Dict] = []
        confidence_accum = 0.0

        for index, case in enumerate(campaign_cases):
            ip, device, account = _extract_features_from_case(case)

            if index == 0:
                transition_type = "INITIAL_COMPROMISE"
            elif index == len(campaign_cases) - 1:
                transition_type = "FRAUD_CASHOUT"
            else:
                transition_type = "LATERAL_PROPAGATION"

            risk_score = float(getattr(case, "risk_score", 0.5) or 0.5)
            step = {
                "step_index": index,
                "case_id": getattr(case, "case_id", ""),
                "transaction_id": getattr(case, "transaction_id", ""),
                "risk_score": risk_score,
                "timestamp": str(getattr(case, "created_at", "")),
                "action": transition_type,
                "indicators": {
                    "ip": ip,
                    "device": device,
                    "account": account,
                },
            }
            steps.append(step)
            confidence_accum += risk_score

        # 5. Derive confidence score
        if steps:
            confidence_score = min(0.95, confidence_accum / len(steps))
        else:
            confidence_score = 0.5

        chain = AttackChain(
            campaign_id=campaign_id,
            steps=steps,
            confidence_score=round(confidence_score, 3),
        )

        self.forensics_store.add_chain(chain)
        logger.info(
            "Attack chain '%s' reconstructed for campaign '%s' (confidence=%.3f).",
            chain.id,
            campaign_id,
            confidence_score,
        )
        return chain
