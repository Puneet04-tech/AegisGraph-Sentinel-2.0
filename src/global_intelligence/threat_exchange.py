"""
Threat Intelligence Exchange for federated threat sharing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    IntelligenceSource,
    ThreatIndicator,
    ThreatLevel,
    ThreatCorrelation,
    CorrelationStrength,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store


@dataclass
class ThreatIndicatorSync:
    """Sync record for threat indicators."""
    sync_id: str
    partner_id: str
    indicators: List[ThreatIndicator]
    sync_type: str
    timestamp: datetime
    success: bool
    error_message: Optional[str] = None


@dataclass
class ThreatIntelligenceConfig:
    """Configuration for threat intelligence exchange."""
    min_confidence: float = 0.5
    auto_expire_days: int = 90
    dedup_enabled: bool = True
    enrichment_enabled: bool = True


class ThreatIntelligenceExchange:
    """
    Manages federated threat intelligence exchange.

    Handles:
    - Threat indicator sharing
    - Cross-organization threat correlation
    - Indicator enrichment
    - Threat synchronization
    """

    def __init__(
        self,
        store: Optional[GlobalIntelligenceStore] = None,
        config: Optional[ThreatIntelligenceConfig] = None,
    ):
        self._store = store or get_global_intelligence_store()
        self._config = config or ThreatIntelligenceConfig()

    def add_indicator(
        self,
        indicator_type: str,
        value: str,
        threat_type: str,
        threat_level: ThreatLevel,
        source: IntelligenceSource,
        confidence: float = 0.8,
        tags: Optional[List[str]] = None,
        partner_id: Optional[str] = None,
        expiration_days: Optional[int] = None,
    ) -> ThreatIndicator:
        """Add a new threat indicator."""
        indicator = ThreatIndicator(
            indicator_id=str(uuid.uuid4()),
            indicator_type=indicator_type,
            value=value,
            source=source,
            threat_type=threat_type,
            threat_level=threat_level,
            confidence=confidence,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            expiration=(
                datetime.now(timezone.utc) + timedelta(days=expiration_days or self._config.auto_expire_days)
            ),
            partner_id=partner_id,
            tags=tags or [],
        )

        self._store.store_indicator(indicator)
        return indicator

    def share_indicator(
        self,
        indicator_id: str,
        target_partners: List[str],
    ) -> bool:
        """Share an indicator with partners."""
        indicator = self._store.get_indicator(indicator_id)
        if not indicator or indicator.is_expired():
            return False

        # In production, would send to partner APIs
        return True

    def receive_indicators(
        self,
        partner_id: str,
        indicators: List[ThreatIndicator],
    ) -> int:
        """Receive indicators from a partner."""
        received = 0

        for indicator in indicators:
            # Check if already exists (deduplication)
            if self._config.dedup_enabled:
                existing = self._find_duplicate(indicator)
                if existing:
                    # Update existing
                    existing.last_seen = datetime.now(timezone.utc)
                    self._store.store_indicator(existing)
                    continue

            # Set partner info
            indicator.partner_id = partner_id
            indicator.source = IntelligenceSource.FEDERATION

            self._store.store_indicator(indicator)
            received += 1

        return received

    def search_indicators(
        self,
        query: Optional[str] = None,
        indicator_type: Optional[str] = None,
        threat_level: Optional[ThreatLevel] = None,
        limit: int = 100,
    ) -> List[ThreatIndicator]:
        """Search for threat indicators."""
        if query:
            return self._store.search_indicators(query, threat_level, limit)

        if indicator_type:
            return self._store.get_indicators_by_type(indicator_type, limit)

        return self._store.get_active_indicators(threat_level, limit)

    def find_correlations(
        self,
        indicator_id: str,
        min_confidence: float = 0.5,
    ) -> List[ThreatCorrelation]:
        """Find correlations between indicators."""
        indicator = self._store.get_indicator(indicator_id)
        if not indicator:
            return []

        correlations: List[ThreatCorrelation] = []

        # Search for related indicators
        related = self._store.search_indicators(
            indicator.value[:10],  # Use prefix for search
            threat_level=indicator.threat_level,
            limit=100,
        )

        for related_indicator in related:
            if related_indicator.indicator_id == indicator_id:
                continue

            # Calculate correlation
            correlation = self._calculate_correlation(indicator, related_indicator)
            if correlation.confidence >= min_confidence:
                correlations.append(correlation)

        return correlations

    def enrich_indicator(
        self,
        indicator_id: str,
    ) -> Optional[ThreatIndicator]:
        """Enrich an indicator with additional context."""
        indicator = self._store.get_indicator(indicator_id)
        if not indicator:
            return None

        # In production, would call external enrichment APIs
        # For now, just update last_seen
        indicator.last_seen = datetime.now(timezone.utc)
        self._store.store_indicator(indicator)

        return indicator

    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        indicators = self._store.get_active_indicators(limit=10000)

        by_type: Dict[str, int] = {}
        by_level: Dict[str, int] = {}
        by_source: Dict[str, int] = {}

        for ind in indicators:
            by_type[ind.threat_type] = by_type.get(ind.threat_type, 0) + 1
            by_level[ind.threat_level.value] = by_level.get(ind.threat_level.value, 0) + 1
            by_source[ind.source.value] = by_source.get(ind.source.value, 0) + 1

        return {
            "total_indicators": len(indicators),
            "by_type": by_type,
            "by_threat_level": by_level,
            "by_source": by_source,
        }

    def sync_with_partner(
        self,
        partner_id: str,
        last_sync: Optional[datetime] = None,
    ) -> ThreatIndicatorSync:
        """Synchronize indicators with a partner."""
        sync_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)

        try:
            # Get indicators to share
            indicators_to_share = []
            for indicator in self._store.get_active_indicators(limit=1000):
                if indicator.source == IntelligenceSource.INTERNAL:
                    indicators_to_share.append(indicator)

            # Receive updates from partner (simulated)
            received = self.receive_indicators(partner_id, [])

            return ThreatIndicatorSync(
                sync_id=sync_id,
                partner_id=partner_id,
                indicators=indicators_to_share,
                sync_type="bidirectional",
                timestamp=timestamp,
                success=True,
            )

        except Exception as e:
            return ThreatIndicatorSync(
                sync_id=sync_id,
                partner_id=partner_id,
                indicators=[],
                sync_type="bidirectional",
                timestamp=timestamp,
                success=False,
                error_message=str(e),
            )

    def _find_duplicate(self, indicator: ThreatIndicator) -> Optional[ThreatIndicator]:
        """Find duplicate indicator."""
        existing = self._store.search_indicators(
            indicator.value, limit=10
        )

        for ex in existing:
            if (
                ex.indicator_type == indicator.indicator_type
                and ex.value == indicator.value
            ):
                return ex

        return None

    def _calculate_correlation(
        self,
        ind1: ThreatIndicator,
        ind2: ThreatIndicator,
    ) -> ThreatCorrelation:
        """Calculate correlation between two indicators."""
        score = 0.0
        shared_indicators: List[str] = []

        # Same type
        if ind1.threat_type == ind2.threat_type:
            score += 0.3
            shared_indicators.append("threat_type")

        # Same level
        if ind1.threat_level == ind2.threat_level:
            score += 0.2
            shared_indicators.append("threat_level")

        # Value similarity
        if ind1.value == ind2.value:
            score += 0.3
            shared_indicators.append("value")

        # Time proximity
        time_diff = abs((ind1.last_seen - ind2.last_seen).total_seconds())
        if time_diff < 3600:  # Within 1 hour
            score += 0.1
            shared_indicators.append("time_proximity")

        # Determine strength
        if score >= 0.9:
            strength = CorrelationStrength.DEFINITIVE
        elif score >= 0.7:
            strength = CorrelationStrength.STRONG
        elif score >= 0.5:
            strength = CorrelationStrength.MODERATE
        else:
            strength = CorrelationStrength.WEAK

        return ThreatCorrelation(
            correlation_id=str(uuid.uuid4()),
            indicator_1_id=ind1.indicator_id,
            indicator_2_id=ind2.indicator_id,
            correlation_type="indicator_match",
            strength=strength,
            confidence=score,
            shared_indicators=shared_indicators,
            discovered_at=datetime.now(timezone.utc),
            verified=False,
        )


# Global exchange instance
_exchange: Optional[ThreatIntelligenceExchange] = None


def get_threat_exchange() -> ThreatIntelligenceExchange:
    """Get the global threat exchange instance."""
    global _exchange
    if _exchange is None:
        _exchange = ThreatIntelligenceExchange()
    return _exchange