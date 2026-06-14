"""Tests for Watchlist Module"""
import pytest
from src.watchlist import WatchlistService

def test_service_init():
    service = WatchlistService()
    assert service is not None
    assert len(service.watchlists) >= 1

def test_add_entry():
    service = WatchlistService()
    entry = service.add_entry(
        watchlist_type="CUSTOM",
        name="Test Entity",
        risk_score=0.8,
        source="Internal"
    )
    assert entry is not None
    assert entry["name"] == "Test Entity"

def test_screen_no_match():
    service = WatchlistService()
    result = service.screen("Unknown Entity", "ent-001")
    assert result is not None
    assert result["match_result"] == "NO_MATCH"

def test_screen_potential_match():
    service = WatchlistService()
    result = service.screen("Known Bad Actor", "ent-002")
    assert result is not None
    assert result["match_result"] != "NO_MATCH"

def test_get_dashboard():
    service = WatchlistService()
    service.screen("Test", "ent-003")
    dashboard = service.get_dashboard()
    assert "total_entries" in dashboard
    assert "total_screenings" in dashboard