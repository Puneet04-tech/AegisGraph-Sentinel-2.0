"""Attribute-Based Access Control entry point.

This module previously consisted of a three-line stub that returned ``True``
unconditionally, ignoring both of its arguments.  Sitting under the security
package, it read as a real authorization check, so any caller that imported it
received a decision function that granted access to everyone.

It now delegates to :class:`src.saas.auth.service.ABACService`, which evaluates
registered policies with default-deny and deny-override semantics.  The
original signature still works, so existing imports keep working — but the
answer is now a real one.

A module-level service instance holds the policy set.  Register policies with
:func:`add_policy` during application start-up; until at least one policy
allows a request, every call denies.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from src.saas.auth.service import ABACDecision, ABACService

logger = logging.getLogger(__name__)

# Process-wide policy set. Kept module-level so the historical function-style
# API remains usable without threading a service object through every caller.
_abac_service = ABACService()


def get_abac_service() -> ABACService:
    """Return the module-level policy engine, for registering policies."""
    return _abac_service


def add_policy(policy: Dict[str, Any]) -> None:
    """Register a policy on the module-level engine.

    Raises ``ValueError`` for a malformed policy so the failure surfaces at
    start-up rather than as a silently over-broad rule at request time.
    """
    _abac_service.add_policy(policy)


def reset_policies() -> None:
    """Drop all registered policies. Intended for use in tests."""
    _abac_service.policies.clear()


def evaluate_abac_policy(
    user_attributes: Optional[Dict[str, Any]],
    resource_attributes: Optional[Dict[str, Any]],
    action: str = "access",
    environment: Optional[Dict[str, Any]] = None,
) -> bool:
    """Return True only when a registered policy explicitly allows the request.

    ``action`` and ``environment`` are optional so the original two-argument
    call signature still works; callers that omit them are evaluated against
    the generic ``"access"`` action.

    Any failure denies.  An authorization check that cannot reach a decision
    must not answer "allowed".
    """
    return evaluate_abac_policy_detailed(
        user_attributes, resource_attributes, action, environment
    ).allowed


def evaluate_abac_policy_detailed(
    user_attributes: Optional[Dict[str, Any]],
    resource_attributes: Optional[Dict[str, Any]],
    action: str = "access",
    environment: Optional[Dict[str, Any]] = None,
) -> ABACDecision:
    """Evaluate the request and report the decision with its reason.

    Use this rather than :func:`evaluate_abac_policy` where a denial should be
    audit-logged, so the log records which policy refused the request.
    """
    try:
        return _abac_service.evaluate_detailed(
            subject=user_attributes or {},
            resource=resource_attributes or {},
            action=action,
            environment=environment or {},
        )
    except Exception as exc:
        logger.error("ABAC evaluation raised, denying access: %s", exc, exc_info=True)
        return ABACDecision(allowed=False, reason="Policy evaluation error")
