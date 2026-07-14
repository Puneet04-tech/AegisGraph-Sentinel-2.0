class SecurityError(Exception):
    """Exception raised when security validation fails."""

    pass


def is_admin_role(role: str) -> bool:
    """Check if the given role has administrative access.

    Roles supported:
    - Administrator (full control)
    - Operator (read-only monitoring)
    """
    if not role:
        return False
    normalized = role.strip().lower()
    return normalized in ("administrator", "admin", "super_admin", "superadmin")


def check_admin_access(role: str) -> None:
    """Raise SecurityError if role lacks admin access."""
    if not is_admin_role(role):
        msg = "Insufficient permissions. Administrator role is required."
        raise SecurityError(msg)
