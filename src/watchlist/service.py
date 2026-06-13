"""Watchlist Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import WatchlistEntry, ScreeningResult, WatchlistType, MatchResult

class WatchlistService:
    """Enterprise Watchlist Service"""
    
    def __init__(self) -> None:
        self.watchlists: Dict[str, WatchlistEntry] = {}
        self.results: Dict[str, ScreeningResult] = {}
        self._init_default_watchlists()
    
    def _init_default_watchlists(self) -> None:
        """Initialize default watchlists"""
        entries = [
            WatchlistEntry(
                entry_id="wl-001",
                watchlist_type=WatchlistType.SANCTIONS,
                name="Known Bad Actor",
                aliases=["KBA", "Bad Actor"],
                identifiers={"country": "XX"},
                risk_score=0.95,
                source="OFAC"
            )
        ]
        for entry in entries:
            self.watchlists[entry.entry_id] = entry
    
    def add_entry(
        self,
        watchlist_type: str,
        name: str,
        aliases: Optional[List[str]] = None,
        identifiers: Optional[Dict[str, str]] = None,
        risk_score: float = 0.5,
        source: str = ""
    ) -> Dict[str, Any]:
        """Add a watchlist entry"""
        entry = WatchlistEntry(
            entry_id=str(uuid4())[:8],
            watchlist_type=WatchlistType(watchlist_type),
            name=name,
            aliases=aliases or [],
            identifiers=identifiers or {},
            risk_score=risk_score,
            source=source
        )
        self.watchlists[entry.entry_id] = entry
        return entry.to_dict()
    
    def screen(
        self,
        entity_name: str,
        entity_id: str
    ) -> Dict[str, Any]:
        """Screen an entity against watchlists"""
        matched_entry_id = None
        match_result = MatchResult.NO_MATCH
        confidence = 0.0
        
        # Simple matching logic
        for entry in self.watchlists.values():
            if entity_name.lower() in entry.name.lower() or \
               entry.name.lower() in entity_name.lower():
                matched_entry_id = entry.entry_id
                confidence = 0.9
                match_result = MatchResult.POTENTIAL_MATCH if confidence < 0.95 else MatchResult.CONFIRMED_MATCH
                break
        
        result = ScreeningResult(
            result_id=str(uuid4())[:8],
            entity_name=entity_name,
            entity_id=entity_id,
            match_result=match_result,
            matched_entry_id=matched_entry_id,
            confidence=confidence
        )
        self.results[result.result_id] = result
        return result.to_dict()
    
    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get a watchlist entry"""
        entry = self.watchlists.get(entry_id)
        return entry.to_dict() if entry else None
    
    def get_all_entries(self) -> List[Dict[str, Any]]:
        """Get all watchlist entries"""
        return [e.to_dict() for e in self.watchlists.values()]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get watchlist dashboard"""
        type_counts: Dict[str, int] = {}
        for entry in self.watchlists.values():
            type_counts[entry.watchlist_type.value] = type_counts.get(entry.watchlist_type.value, 0) + 1
        
        match_counts = {
            "no_match": len([r for r in self.results.values() if r.match_result == MatchResult.NO_MATCH]),
            "potential": len([r for r in self.results.values() if r.match_result == MatchResult.POTENTIAL_MATCH]),
            "confirmed": len([r for r in self.results.values() if r.match_result == MatchResult.CONFIRMED_MATCH])
        }
        
        return {
            "total_entries": len(self.watchlists),
            "total_screenings": len(self.results),
            "entries_by_type": type_counts,
            "match_results": match_counts
        }


_watchlist_service: Optional[WatchlistService] = None

def get_watchlist_service() -> WatchlistService:
    """Get the global service instance"""
    global _watchlist_service
    if _watchlist_service is None:
        _watchlist_service = WatchlistService()
    return _watchlist_service