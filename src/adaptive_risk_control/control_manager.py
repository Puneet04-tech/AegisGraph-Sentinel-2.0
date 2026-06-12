"""
Dynamic Control Manager for adaptive security controls.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    ControlRule,
    MitigationAction,
    RiskLevel,
)


class DynamicControlManager:
    """
    Manages dynamic security controls.

    Handles:
    - Control activation/deactivation
    - Adaptive control adjustment
    - Control performance monitoring
    - Emergency controls
    """

    def __init__(self):
        self._active_controls: Dict[str, ControlRule] = {}
        self._control_history: List[Dict[str, Any]] = []

    async def activate_control(
        self,
        rule: ControlRule,
    ) -> Dict[str, Any]:
        """Activate a security control."""
        rule.is_active = True
        rule.updated_at = datetime.now(timezone.utc)

        self._active_controls[rule.rule_id] = rule

        self._record_control_action(
            "activate",
            rule.rule_id,
            {"status": "activated"},
        )

        return {
            "control_id": rule.rule_id,
            "status": "active",
            "activated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def deactivate_control(
        self,
        rule_id: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Deactivate a security control."""
        if rule_id in self._active_controls:
            rule = self._active_controls[rule_id]
            rule.is_active = False
            rule.updated_at = datetime.now(timezone.utc)

            del self._active_controls[rule_id]

            self._record_control_action(
                "deactivate",
                rule_id,
                {"reason": reason},
            )

            return {
                "control_id": rule_id,
                "status": "inactive",
                "deactivated_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
            }

        return {"error": "Control not found"}

    async def adjust_control(
        self,
        rule_id: str,
        adjustments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Adjust control parameters."""
        if rule_id in self._active_controls:
            rule = self._active_controls[rule_id]

            # Apply adjustments
            if "risk_threshold" in adjustments:
                rule.risk_threshold = adjustments["risk_threshold"]
            if "priority" in adjustments:
                rule.priority = adjustments["priority"]
            if "conditions" in adjustments:
                rule.conditions.update(adjustments["conditions"])

            rule.updated_at = datetime.now(timezone.utc)

            self._record_control_action(
                "adjust",
                rule_id,
                {"adjustments": adjustments},
            )

            return {
                "control_id": rule_id,
                "status": "adjusted",
                "new_threshold": rule.risk_threshold,
            }

        return {"error": "Control not found"}

    async def get_active_controls(
        self,
        risk_level: Optional[RiskLevel] = None,
    ) -> List[Dict[str, Any]]:
        """Get active controls, optionally filtered by risk level."""
        controls = []

        for rule in self._active_controls.values():
            if risk_level:
                threshold = self._risk_level_to_threshold(risk_level)
                if rule.risk_threshold < threshold:
                    continue

            controls.append({
                "rule_id": rule.rule_id,
                "name": rule.name,
                "rule_type": rule.rule_type,
                "action": rule.action.value,
                "risk_threshold": rule.risk_threshold,
                "priority": rule.priority,
                "trigger_count": rule.trigger_count,
            })

        # Sort by priority
        controls.sort(key=lambda c: c["priority"], reverse=True)

        return controls

    async def get_control_performance(
        self,
        rule_id: str,
    ) -> Dict[str, Any]:
        """Get control performance metrics."""
        if rule_id in self._active_controls:
            rule = self._active_controls[rule_id]

            return {
                "rule_id": rule_id,
                "name": rule.name,
                "is_active": rule.is_active,
                "trigger_count": rule.trigger_count,
                "false_positive_rate": rule.false_positive_rate,
                "last_triggered": (
                    rule.last_triggered.isoformat()
                    if rule.last_triggered else None
                ),
            }

        return {"error": "Control not found"}

    async def trigger_control(
        self,
        rule_id: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Trigger a control and record the action."""
        if rule_id in self._active_controls:
            rule = self._active_controls[rule_id]

            rule.trigger_count += 1
            rule.last_triggered = datetime.now(timezone.utc)

            self._record_control_action(
                "trigger",
                rule_id,
                {"context": context},
            )

            return {
                "rule_id": rule_id,
                "action": rule.action.value,
                "triggered_at": datetime.now(timezone.utc).isoformat(),
            }

        return {"error": "Control not found"}

    async def enable_emergency_controls(
        self,
        reason: str,
    ) -> Dict[str, Any]:
        """Enable emergency controls for high-risk situations."""
        emergency_rules = [
            "block_all_high_risk",
            "require_mfa_all",
            "disable_new_accounts",
        ]

        enabled = []
        for rule_id in emergency_rules:
            result = await self.activate_control(
                ControlRule(
                    rule_id=rule_id,
                    name=f"Emergency: {rule_id}",
                    rule_type="emergency",
                    conditions={"emergency": True},
                    action=MitigationAction.BLOCK,
                    risk_threshold=0.5,
                    priority=1000,
                )
            )
            enabled.append(result)

        self._record_control_action(
            "emergency_enable",
            "emergency_group",
            {"reason": reason, "rules_enabled": len(enabled)},
        )

        return {
            "status": "emergency_controls_active",
            "rules_enabled": len(enabled),
            "reason": reason,
            "activated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def disable_emergency_controls(self) -> Dict[str, Any]:
        """Disable emergency controls."""
        emergency_rules = [
            "block_all_high_risk",
            "require_mfa_all",
            "disable_new_accounts",
        ]

        disabled = []
        for rule_id in emergency_rules:
            if rule_id in self._active_controls:
                result = await self.deactivate_control(rule_id, "Emergency resolved")
                disabled.append(result)

        self._record_control_action(
            "emergency_disable",
            "emergency_group",
            {"rules_disabled": len(disabled)},
        )

        return {
            "status": "emergency_controls_inactive",
            "rules_disabled": len(disabled),
            "deactivated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_control_history(
        self,
        rule_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get control action history."""
        history = self._control_history

        if rule_id:
            history = [h for h in history if h.get("rule_id") == rule_id]

        return history[-limit:]

    def _record_control_action(
        self,
        action: str,
        rule_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Record control action for audit."""
        self._control_history.append({
            "action": action,
            "rule_id": rule_id,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Keep last 10000 actions
        if len(self._control_history) > 10000:
            self._control_history = self._control_history[-10000:]

    def _risk_level_to_threshold(self, risk_level: RiskLevel) -> float:
        """Convert risk level to threshold."""
        thresholds = {
            RiskLevel.MINIMAL: 0.1,
            RiskLevel.LOW: 0.3,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.7,
            RiskLevel.CRITICAL: 0.9,
        }
        return thresholds.get(risk_level, 0.5)


# Global manager instance
_manager: Optional[DynamicControlManager] = None


def get_control_manager() -> DynamicControlManager:
    """Get the dynamic control manager instance."""
    global _manager
    if _manager is None:
        _manager = DynamicControlManager()
    return _manager