"""Watchlist Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class WatchlistType(Enum):
    """Watchlist types"""
    SANCTIONS = "SANCTIONS"
    PEP = "PEP"
    ADVERSE_MEDIA = "ADVERSE_MEDIA"
    CUSTOM = "CUSTOM"

class MatchResult(Enum):
    """Match result"""
    NO_MATCH = "NO_MATCH"
    POTENTIAL_MATCH = "POTENTIAL_MATCH"
    CONFIRMED_MATCH = "CONFIRMED_MATCH"

@dataclass
class WatchlistEntry:
    """Watchlist entry"""
    entry_id: str
    watchlist_type: WatchlistType
    name: str
    aliases: List[str] = field(default_factory=list)
    identifiers: Dict[str, str] = field(default_factory=dict)
    risk_score: float = 0.5
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "watchlist_type": self.watchlist_type.value,
            "name": self.name,
            "aliases": self.aliases,
            "identifiers": self.identifiers,
            "risk_score": self.risk_score,
            "source": self.source
        }

@dataclass
class ScreeningResult:
    """Screening result"""
    result_id: str
    entity_name: str
    entity_id: str
    match_result: MatchResult
    matched_entry_id: Optional[str]
    confidence: float
    screened_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "entity_name": self.entity_name,
            "entity_id": self.entity_id,
            "match_result": self.match_result.value,
            "matched_entry_id": self.matched_entry_id,
            "confidence": self.confidence,
            "screened_at": self.screened_at.isoformat()
        }