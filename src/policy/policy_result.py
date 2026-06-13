"""Runtime policy evaluation result model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PolicyResult:
    """Outcome of a single policy evaluation."""

    allowed: bool
    policy_name: str
    reason: str
