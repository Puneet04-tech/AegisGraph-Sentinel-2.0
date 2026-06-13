"""Tests for Feed Intelligence Module"""
import pytest
from src.feed_intel import FeedIntelligenceService, IOCType

def test_service_init():
    service = FeedIntelligenceService()
    assert service is not None
    assert len(service.feeds) >= 2

def test_register_feed():
    service = FeedIntelligenceService()
    feed = service.register_feed("Test Feed", "Test description", "Custom", "https://test.com")
    assert feed is not None
    assert feed["name"] == "Test Feed"

def test_add_ioc():
    service = FeedIntelligenceService()
    ioc = service.add_ioc("192.168.1.1", "IPV4", "feed-001", "malware", 0.9, ["malware"])
    assert ioc is not None
    assert ioc["value"] == "192.168.1.1"

def test_search_iocs():
    service = FeedIntelligenceService()
    service.add_ioc("evil.com", "DOMAIN", "feed-001", "phishing", 0.8)
    results = service.search_iocs(ioc_type="DOMAIN")
    assert len(results) >= 1

def test_get_dashboard():
    service = FeedIntelligenceService()
    service.add_ioc("1.2.3.4", "IPV4", "feed-001", "botnet", 0.7)
    dashboard = service.get_dashboard()
    assert "total_iocs" in dashboard