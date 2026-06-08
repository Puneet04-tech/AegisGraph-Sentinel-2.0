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
