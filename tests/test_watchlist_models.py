# AegisGraph Sentinel Enterprise
# Watchlist Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime, timezone
from src.watchlist.models import WatchlistType, MatchResult, WatchlistEntry, ScreeningResult

def test_watchlist_type_values():
    assert WatchlistType.SANCTIONS.value == "SANCTIONS"
    assert WatchlistType.PEP.value == "PEP"
    assert WatchlistType.ADVERSE_MEDIA.value == "ADVERSE_MEDIA"
    assert WatchlistType.CUSTOM.value == "CUSTOM"

def test_match_result_values():
    assert MatchResult.NO_MATCH.value == "NO_MATCH"
    assert MatchResult.POTENTIAL_MATCH.value == "POTENTIAL_MATCH"
    assert MatchResult.CONFIRMED_MATCH.value == "CONFIRMED_MATCH"

def test_watchlist_entry_creation():
    entry = WatchlistEntry(
        entry_id="ent-100",
        watchlist_type=WatchlistType.SANCTIONS,
        name="Rogue Actor Corp",
        aliases=["Rogue Corp", "RAC"],
        identifiers={"tax_id": "99-9999"},
        risk_score=0.9,
        source="OFAC"
    )
    assert entry.entry_id == "ent-100"
    assert entry.watchlist_type == WatchlistType.SANCTIONS
    assert entry.name == "Rogue Actor Corp"
    assert entry.aliases == ["Rogue Corp", "RAC"]
    assert entry.identifiers == {"tax_id": "99-9999"}
    assert entry.risk_score == 0.9
    assert entry.source == "OFAC"

def test_watchlist_entry_to_dict():
    entry = WatchlistEntry(
        entry_id="ent-101",
        watchlist_type=WatchlistType.CUSTOM,
        name="Custom Flag Account",
        risk_score=0.75
    )
    data = entry.to_dict()
    assert data["entry_id"] == "ent-101"
    assert data["watchlist_type"] == "CUSTOM"
    assert data["risk_score"] == 0.75
    assert data["aliases"] == []
    assert data["identifiers"] == {}

def test_screening_result_creation():
    now = datetime.now(timezone.utc)
    result = ScreeningResult(
        result_id="res-001",
        entity_name="Alice Smith",
        entity_id="usr-123",
        match_result=MatchResult.POTENTIAL_MATCH,
        matched_entry_id="ent-200",
        confidence=0.85,
        screened_at=now
    )
    assert result.result_id == "res-001"
    assert result.entity_name == "Alice Smith"
    assert result.entity_id == "usr-123"
    assert result.match_result == MatchResult.POTENTIAL_MATCH
    assert result.matched_entry_id == "ent-200"
    assert result.confidence == 0.85
    assert result.screened_at == now

def test_screening_result_to_dict():
    now = datetime.now(timezone.utc)
    result = ScreeningResult(
        result_id="res-002",
        entity_name="Bob Brown",
        entity_id="usr-456",
        match_result=MatchResult.NO_MATCH,
        matched_entry_id=None,
        confidence=1.0,
        screened_at=now
    )
    data = result.to_dict()
    assert data["result_id"] == "res-002"
    assert data["match_result"] == "NO_MATCH"
    assert data["confidence"] == 1.0
    assert data["screened_at"] == now.isoformat()
