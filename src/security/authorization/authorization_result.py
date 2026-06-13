"""Authorization decision result."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AuthorizationResult:
    allowed: bool
    role: str
    permission: str
    reason: str
