import pytest
import os
from unittest.mock import Mock, patch
from src.api.dependencies.ip_resolution import get_remote_address, is_trusted_proxy

class MockClient:
    def __init__(self, host):
        self.host = host

class MockRequest:
    def __init__(self, client_host, headers=None):
        self.client = MockClient(client_host)
        self.headers = headers or {}

@pytest.fixture(autouse=True)
def reset_trusted_networks():
    # Because _TRUSTED_NETWORKS is evaluated at import time, we patch it for tests
    with patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', []):
        yield

def test_direct_connection_no_proxy():
    request = MockRequest("12.34.56.78")
    assert get_remote_address(request) == "12.34.56.78"

def test_untrusted_proxy_spoofing():
    request = MockRequest("12.34.56.78", {"X-Forwarded-For": "1.1.1.1"})
    # Since 12.34.56.78 is not trusted, it ignores the header
    assert get_remote_address(request) == "12.34.56.78"

@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', [__import__('ipaddress').ip_network('10.0.0.0/8')])
def test_trusted_proxy_single_client():
    request = MockRequest("10.0.0.1", {"X-Forwarded-For": "8.8.8.8"})
    # 10.0.0.1 is trusted, so it trusts the header
    assert get_remote_address(request) == "8.8.8.8"

@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', [__import__('ipaddress').ip_network('10.0.0.0/8')])
def test_trusted_proxy_multiple_hops():
    # 10.0.0.1 -> 10.0.0.2 -> Client
    request = MockRequest("10.0.0.1", {"X-Forwarded-For": "8.8.8.8, 10.0.0.2"})
    assert get_remote_address(request) == "8.8.8.8"

@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', [__import__('ipaddress').ip_network('10.0.0.0/8')])
def test_trusted_proxy_spoofing_attempt():
    # Attacker connects through trusted proxy, but puts fake IPs in X-Forwarded-For
    # Real client is 8.8.8.8, but they injected 1.1.1.1
    request = MockRequest("10.0.0.1", {"X-Forwarded-For": "1.1.1.1, 8.8.8.8"})
    # It checks 8.8.8.8 -> Not trusted. So it stops and returns 8.8.8.8, ignoring 1.1.1.1
    assert get_remote_address(request) == "8.8.8.8"

@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', [__import__('ipaddress').ip_network('10.0.0.0/8')])
def test_trusted_proxy_empty_header():
    request = MockRequest("10.0.0.1", {"X-Forwarded-For": ""})
    assert get_remote_address(request) == "10.0.0.1"

@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', [__import__('ipaddress').ip_network('10.0.0.0/8')])
def test_trusted_proxy_all_trusted_chain():
    request = MockRequest("10.0.0.1", {"X-Forwarded-For": "10.0.0.3, 10.0.0.2"})
    # If the whole chain is trusted proxies, the true client is the left-most IP
    assert get_remote_address(request) == "10.0.0.3"

# ---------------------------------------------------------------------------
# The resolved value is used as a rate limit key, so it must be an address.
# A trusted proxy vouches for the connection, not for the contents of the
# headers it forwards, which a client may still control.
# ---------------------------------------------------------------------------

TRUSTED = [__import__('ipaddress').ip_network('10.0.0.0/8')]


@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', TRUSTED)
@pytest.mark.parametrize("value", [
    "attacker-1",
    "not-an-ip-at-all",
    "1.1.1.1' OR 1=1--",
    "A" * 200,
    "1.1.1.1\nInjected: header",
    "999.999.999.999",
])
def test_non_address_x_real_ip_falls_back_to_peer(value):
    request = MockRequest("10.0.0.1", {"X-Real-IP": value})
    assert get_remote_address(request) == "10.0.0.1"


@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', TRUSTED)
@pytest.mark.parametrize("value", [
    "junk-1",
    "not-an-ip-at-all",
    "A" * 200,
])
def test_non_address_x_forwarded_for_falls_back_to_peer(value):
    request = MockRequest("10.0.0.1", {"X-Forwarded-For": value})
    assert get_remote_address(request) == "10.0.0.1"


@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', TRUSTED)
def test_valid_x_real_ip_is_still_honoured():
    request = MockRequest("10.0.0.1", {"X-Real-IP": "8.8.8.8"})
    assert get_remote_address(request) == "8.8.8.8"


@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', TRUSTED)
def test_ipv6_x_real_ip_is_still_honoured():
    request = MockRequest("10.0.0.1", {"X-Real-IP": "2001:db8::1"})
    assert get_remote_address(request) == "2001:db8::1"


@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', TRUSTED)
def test_leading_junk_does_not_hide_the_real_client():
    """A spoofed left-most entry must not stop the real client being found."""
    request = MockRequest("10.0.0.1", {"X-Forwarded-For": "junk, 8.8.8.8, 10.0.0.2"})
    assert get_remote_address(request) == "8.8.8.8"


@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', TRUSTED)
def test_all_trusted_chain_with_non_address_head_falls_back():
    request = MockRequest("10.0.0.1", {"X-Forwarded-For": "junk, 10.0.0.2"})
    assert get_remote_address(request) == "10.0.0.1"


@patch('src.api.dependencies.ip_resolution._TRUSTED_NETWORKS', TRUSTED)
def test_distinct_non_address_values_share_one_key():
    """Rotating the header must not mint distinct rate limit keys."""
    resolved = {
        get_remote_address(MockRequest("10.0.0.1", {"X-Real-IP": "attacker-%d" % i}))
        for i in range(50)
    }
    assert resolved == {"10.0.0.1"}
