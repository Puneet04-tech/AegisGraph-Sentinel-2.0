import ipaddress

import pytest

from src.features.ip_blacklist import (
    is_ip_blacklisted,
    is_location_blacklisted,
    check_blacklist,
)

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
    assert is_ip_blacklisted("   ") is False
    assert is_ip_blacklisted("192.0.2.999") is False
    assert is_ip_blacklisted("[not-an-ip") is False

def test_ip_blacklist_ipv4_with_port() -> None:
    # IPv4 with port suffix should still match the underlying address
    assert is_ip_blacklisted("203.0.113.5:8080") is True
    assert is_ip_blacklisted("192.0.2.1:443") is True
    assert is_ip_blacklisted("8.8.8.8:53") is False
    # A non-numeric suffix is treated as an (ignored) port; the host is still
    # checked so a blacklisted address can never slip through.
    assert is_ip_blacklisted("203.0.113.5:notaport") is True

def test_ip_blacklist_ipv6_exact_match() -> None:
    # An IPv6 subnet in the blacklist must be honored (regression: the address
    # used to be truncated at the first colon and silently skipped).
    v6_subnet = ipaddress.ip_network("2001:db8::/32")
    from src.features.ip_blacklist import BLACKLISTED_SUBNETS
    BLACKLISTED_SUBNETS.add(v6_subnet)
    try:
        assert is_ip_blacklisted("2001:db8::1") is True
        assert is_ip_blacklisted("2001:db8:85a3::8a2e:370:7334") is True
        assert is_ip_blacklisted("[2001:db8::1]:8080") is True
        assert is_ip_blacklisted("2001:db8::1:8080") is True
        assert is_ip_blacklisted("2607:f8b0:4004:800::200e") is False
    finally:
        BLACKLISTED_SUBNETS.discard(v6_subnet)

def test_ip_blacklist_ipv6_no_match() -> None:
    assert is_ip_blacklisted("2001:db8:85a3::8a2e:370:7334") is False
    assert is_ip_blacklisted("[2001:4860:4860::8888]:443") is False

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

def test_ip_blacklist_ipv4_whitespace_and_leading_zeros() -> None:
    # Whitespace is stripped before matching
    assert is_ip_blacklisted("  203.0.113.5  ") is True
    assert is_ip_blacklisted(" 8.8.8.8 ") is False
    # Modern ipaddress rejects leading zeros (ambiguous octal-style notation)
    assert is_ip_blacklisted("203.0.113.005") is False

def test_ip_blacklist_ipv6_case_normalization() -> None:
    # ipaddress lowercases hex, so uppercase addresses must still match
    v6_subnet = ipaddress.ip_network("2001:db8::/32")
    from src.features.ip_blacklist import BLACKLISTED_SUBNETS
    BLACKLISTED_SUBNETS.add(v6_subnet)
    try:
        assert is_ip_blacklisted("2001:DB8::1") is True
        assert is_ip_blacklisted("[2001:DB8:85A3::8A2E:370:7334]:443") is True
    finally:
        BLACKLISTED_SUBNETS.discard(v6_subnet)

def test_ip_blacklist_ipv6_sibling_subnet_not_matched() -> None:
    # An address just outside the blacklisted prefix must not be flagged
    v6_subnet = ipaddress.ip_network("2001:db8::/32")
    from src.features.ip_blacklist import BLACKLISTED_SUBNETS
    BLACKLISTED_SUBNETS.add(v6_subnet)
    try:
        assert is_ip_blacklisted("2001:db9::1") is False
        assert is_ip_blacklisted("2001:db9::1:8080") is False
    finally:
        BLACKLISTED_SUBNETS.discard(v6_subnet)

def test_ip_blacklist_bracketed_ipv4() -> None:
    # Brackets are tolerated for IPv4 as well
    assert is_ip_blacklisted("[203.0.113.5]") is True
    assert is_ip_blacklisted("[8.8.8.8]") is False

def test_ip_blacklist_ipv6_zone_id() -> None:
    # Link-local / scoped addresses with zone IDs never crash and never match
    assert is_ip_blacklisted("fe80::1%eth0") is False
    assert is_ip_blacklisted("fe80::1%25eth0") is False
    assert is_ip_blacklisted("2607:f8b0::1%eth0") is False

def test_ip_blacklist_ipv6_bracketed_not_blacklisted() -> None:
    assert is_ip_blacklisted("[2607:f8b0:4004:800::200e]") is False
    assert is_ip_blacklisted("[2607:f8b0:4004:800::200e]:8080") is False

def test_ip_blacklist_malformed_brackets() -> None:
    assert is_ip_blacklisted("[2001:db8::1") is False
    assert is_ip_blacklisted("2001:db8::1]") is False
    assert is_ip_blacklisted("[]") is False
    assert is_ip_blacklisted("[::]junk") is False

def test_ip_blacklist_ipv4_multi_port_suffix() -> None:
    # More than one colon makes the string unparseable rather than guessing
    assert is_ip_blacklisted("1.2.3.4:8080:80") is False
    # A trailing colon is tolerated as an empty port
    assert is_ip_blacklisted("203.0.113.5:") is True

def test_ip_blacklist_none_and_non_string() -> None:
    # Non-string input is rejected defensively instead of raising
    assert is_ip_blacklisted(None) is False
    assert is_ip_blacklisted(12345) is False
    assert is_ip_blacklisted([]) is False

def test_location_blacklist_word_boundaries() -> None:
    # "IR" must not match inside "IRELAND"; standalone codes still match
    assert is_location_blacklisted("IRELAND") is False
    assert is_location_blacklisted("Dublin, Ireland") is False
    assert is_location_blacklisted("IR") is True
    assert is_location_blacklisted("Tehran, Iran, IR") is True

def test_location_blacklist_non_string() -> None:
    assert is_location_blacklisted(None) is False
    assert is_location_blacklisted(12345) is False
    assert is_location_blacklisted("  ") is False

def test_check_blacklist_none_values() -> None:
    # Neither input provided
    assert check_blacklist() is False
    # Only location provided
    assert check_blacklist(location="Tehran, Iran") is True
    # Only IP provided
    assert check_blacklist(ip_address="203.0.113.1") is True
    assert check_blacklist(ip_address="8.8.8.8", location="") is False
