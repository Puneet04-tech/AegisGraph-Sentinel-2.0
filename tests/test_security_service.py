import pytest
from src.adaptive_risk_control.service import scan_external_security_endpoint, is_private_ip_or_host


def test_unverified_ssl_raises_security_violation():
    with pytest.raises(ValueError, match="verify=True is mandatory"):
        scan_external_security_endpoint("https://example.com", verify=False)


def test_private_ip_and_metadata_ssrf_blocked():
    assert is_private_ip_or_host("http://127.0.0.1/admin") is True
    assert is_private_ip_or_host("http://169.254.169.254/latest/meta-data") is True
    assert is_private_ip_or_host("http://localhost:8080") is True

    with pytest.raises(ValueError, match="restricted private network range"):
        scan_external_security_endpoint("http://169.254.169.254/latest/meta-data")


def test_public_url_validation_passes():
    assert is_private_ip_or_host("https://example.com") is False
