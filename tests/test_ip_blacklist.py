import pytest
from src.features.ip_blacklist import is_ip_blacklisted, is_location_blacklisted, check_blacklist

def test_ip_blacklist_exact_match() -> None:
    assert is_ip_blacklisted("203.0.113.5") is True
    assert is_ip_blacklisted("198.51.100.10") is True
    assert is_ip_blacklisted("192.0.2.1") is True

def test_ip_blacklist_no_match() -> None:
    assert is_ip_blacklisted("8.8.8.8") is False
    assert is_ip_blacklisted("127.0.0.1") is False

def test_ip_blacklist_invalid_format() -> None:
    assert is_ip_blacklisted("invalid-ip") is False
    assert is_ip_blacklisted("") is False

def test_location_blacklist_match() -> None:
    assert is_location_blacklisted("Tehran, Iran") is True
    assert is_location_blacklisted("Pyongyang, North Korea") is True
    assert is_location_blacklisted("DPRK") is True
    assert is_location_blacklisted("SD") is True

def test_location_blacklist_no_match() -> None:
    assert is_location_blacklisted("Mumbai, India") is False
    assert is_location_blacklisted("New York, US") is False
    assert is_location_blacklisted("") is False

def test_check_blacklist_combined() -> None:
    # Match both
    assert check_blacklist("203.0.113.1", "Tehran, Iran") is True
    # Match IP only
    assert check_blacklist("203.0.113.1", "Mumbai, India") is True
    # Match Location only
    assert check_blacklist("8.8.8.8", "DPRK") is True
    # Match neither
    assert check_blacklist("8.8.8.8", "Mumbai, India") is False
