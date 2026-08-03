"""Password strength policy.

AegisGraph Sentinel Enterprise

Applied at every point where a password is set — user creation, password
change, and password reset confirmation — so a weak password cannot enter the
system through whichever entry point happens to skip the check.

The Pydantic models already enforce ``min_length=8``; this adds the checks a
length bound cannot express, and centralises them so the three call sites
cannot drift apart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

MIN_LENGTH = 12
MAX_LENGTH = 256

# Rejected outright regardless of composition. Kept short and illustrative
# rather than an exhaustive breach corpus — deployments handling real traffic
# should front this with a proper breached-password service.
_COMMON_PASSWORDS = frozenset(
    {
        "password", "password1", "password123", "passw0rd", "letmein",
        "qwerty", "qwerty123", "welcome", "welcome1", "admin", "admin123",
        "changeme", "iloveyou", "monkey", "dragon", "sunshine", "princess",
        "football", "baseball", "abc123", "123456", "12345678", "123456789",
        "1234567890", "111111", "000000", "aegisgraph", "sentinel",
    }
)

_SEQUENTIAL_RUNS = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop")


@dataclass
class PasswordValidationResult:
    """Outcome of a policy check."""

    valid: bool
    errors: List[str] = field(default_factory=list)

    @property
    def message(self) -> str:
        return "; ".join(self.errors)


class PasswordPolicyError(ValueError):
    """Raised when a password fails the policy."""

    def __init__(self, result: PasswordValidationResult) -> None:
        super().__init__(result.message)
        self.result = result


def _has_long_run(password: str) -> bool:
    """Detect four or more sequential or repeated characters."""
    lowered = password.lower()
    for run in _SEQUENTIAL_RUNS:
        for start in range(len(run) - 3):
            fragment = run[start : start + 4]
            if fragment in lowered or fragment[::-1] in lowered:
                return True
    return bool(re.search(r"(.)\1{3,}", password))


def validate_password(
    password: str,
    email: Optional[str] = None,
    username: Optional[str] = None,
) -> PasswordValidationResult:
    """Check *password* against the policy and report every failure.

    All failures are collected rather than short-circuiting on the first, so a
    user fixing their password sees the complete list instead of discovering
    one rule at a time.
    """
    errors: List[str] = []

    if not password:
        return PasswordValidationResult(False, ["Password must not be empty"])

    if len(password) < MIN_LENGTH:
        errors.append(f"Password must be at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        errors.append(f"Password must be at most {MAX_LENGTH} characters")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain a lowercase letter")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain an uppercase letter")
    if not re.search(r"\d", password):
        errors.append("Password must contain a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain a symbol")

    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        errors.append("Password is too common")
    else:
        # Catch "Password123!" style variants of a common base.
        stripped = re.sub(r"[^a-z]", "", lowered)
        if stripped in _COMMON_PASSWORDS:
            errors.append("Password is too common")

    if _has_long_run(password):
        errors.append("Password must not contain long repeated or sequential runs")

    # A password containing the account identifier is trivially guessable by
    # anyone who knows the account.
    if email:
        local_part = email.split("@", 1)[0].strip().lower()
        if len(local_part) >= 3 and local_part in lowered:
            errors.append("Password must not contain your email address")
    if username and len(username) >= 3 and username.strip().lower() in lowered:
        errors.append("Password must not contain your username")

    return PasswordValidationResult(valid=not errors, errors=errors)


def enforce_password_policy(
    password: str,
    email: Optional[str] = None,
    username: Optional[str] = None,
) -> None:
    """Validate *password*, raising :class:`PasswordPolicyError` on failure."""
    result = validate_password(password, email=email, username=username)
    if not result.valid:
        raise PasswordPolicyError(result)
