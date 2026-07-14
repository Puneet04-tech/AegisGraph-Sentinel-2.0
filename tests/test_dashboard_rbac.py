import pytest

from config.security import SecurityError, check_admin_access, is_admin_role


def test_is_admin_role_positive():
    """Assert admin roles return True."""
    assert is_admin_role("Administrator") is True
    assert is_admin_role("admin") is True
    assert is_admin_role("super_admin") is True
    assert is_admin_role("superadmin") is True
    assert is_admin_role("  ADMIN  ") is True


def test_is_admin_role_negative():
    """Assert non-admin/operator roles return False."""
    assert is_admin_role("Operator") is False
    assert is_admin_role("viewer") is False
    assert is_admin_role("analyst") is False
    assert is_admin_role("") is False
    assert is_admin_role(None) is False


def test_check_admin_access_allowed():
    """Assert check_admin_access does not raise error for admins."""
    # Should run without raising exception
    check_admin_access("Administrator")
    check_admin_access("admin")


def test_check_admin_access_denied():
    """Assert check_admin_access raises SecurityError for operators."""
    with pytest.raises(SecurityError) as exc_info:
        check_admin_access("Operator")
    assert "Insufficient permissions" in str(exc_info.value)
