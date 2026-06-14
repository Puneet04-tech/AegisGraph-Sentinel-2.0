"""
Control Validation Service for Regulatory Fabric.

Validates control implementation and effectiveness.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
import threading
import random


@dataclass
class ValidationResult:
    """Control validation result."""
    validation_id: str
    control_id: str
    validation_type: str
    status: str
    score: float
    findings: List[Dict[str, Any]] = field(default_factory=list)
    validated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    next_validation: Optional[datetime] = None


class ControlValidationService:
    """Validates control implementation and effectiveness.
    
    Performs automated testing and assessment of security controls.
    """

    def __init__(self, store: Any):
        """Initialize the control validation service.
        
        Args:
            store: Compliance store instance
        """
        self.store = store
        self._validators: Dict[str, Callable] = {}
        self._validation_history: Dict[str, List[ValidationResult]] = {}
        self._lock = threading.Lock()

    def register_validator(self, validation_type: str, validator_func: Callable) -> None:
        """Register a custom validator function.
        
        Args:
            validation_type: Type of validation
            validator_func: Function to perform validation
        """
        with self._lock:
            self._validators[validation_type] = validator_func

    def validate_control(
        self,
        control_id: str,
        validation_type: str = "AUTOMATED",
        perform_test: bool = True,
    ) -> ValidationResult:
        """Validate a control.
        
        Args:
            control_id: Control to validate
            validation_type: Type of validation to perform
            perform_test: Whether to perform actual testing
            
        Returns:
            Validation result
        """
        control = self.store.get_control(control_id)
        if not control:
            return ValidationResult(
                validation_id="",
                control_id=control_id,
                validation_type=validation_type,
                status="ERROR",
                score=0.0,
                findings=[{"error": "Control not found"}],
            )
        
        # Perform validation
        findings = []
        score = 0.0
        
        if validation_type in self._validators:
            result = self._validators[validation_type](control)
            findings = result.get("findings", [])
            score = result.get("score", 0.0)
        else:
            # Default validation logic
            score, findings = self._default_validation(control, perform_test)
        
        # Determine status
        if score >= 0.9:
            status = "EFFECTIVE"
        elif score >= 0.7:
            status = "NEEDS_IMPROVEMENT"
        else:
            status = "INEFFECTIVE"
        
        result = ValidationResult(
            validation_id=f"val_{control_id}_{datetime.now(timezone.utc).timestamp()}",
            control_id=control_id,
            validation_type=validation_type,
            status=status,
            score=score,
            findings=findings,
            next_validation=datetime.now(timezone.utc) + timedelta(days=control.get("test_frequency_days", 90)),
        )
        
        # Store in history
        with self._lock:
            if control_id not in self._validation_history:
                self._validation_history[control_id] = []
            self._validation_history[control_id].append(result)
            # Keep only last 100 results
            if len(self._validation_history[control_id]) > 100:
                self._validation_history[control_id] = self._validation_history[control_id][-100:]
        
        # Update control status based on validation
        self._update_control_status(control_id, status, score)
        
        return result

    def _default_validation(self, control: Dict, perform_test: bool) -> tuple:
        """Perform default validation.
        
        Args:
            control: Control data
            perform_test: Whether to perform actual testing
            
        Returns:
            Tuple of (score, findings)
        """
        findings = []
        score = 1.0
        
        # Check implementation status
        impl = control.get("implementation", "")
        if not impl or len(impl) < 50:
            findings.append({
                "type": "IMPLEMENTATION",
                "severity": "MEDIUM",
                "message": "Control implementation is incomplete or missing",
            })
            score -= 0.2
        
        # Check last test date
        last_test = control.get("last_tested")
        if last_test:
            if isinstance(last_test, str):
                last_test = datetime.fromisoformat(last_test)
            days_since = (datetime.now(timezone.utc) - last_test).days
            if days_since > 90:
                findings.append({
                    "type": "TESTING",
                    "severity": "HIGH",
                    "message": f"Control not tested in {days_since} days",
                })
                score -= 0.3
        else:
            findings.append({
                "type": "TESTING",
                "severity": "HIGH",
                "message": "Control has never been tested",
            })
            score -= 0.3
        
        # Check owner assignment
        owner = control.get("owner", "")
        if not owner:
            findings.append({
                "type": "GOVERNANCE",
                "severity": "LOW",
                "message": "Control has no assigned owner",
            })
            score -= 0.1
        
        # Simulate automated testing if requested
        if perform_test:
            test_result = self._perform_control_test(control)
            if not test_result["passed"]:
                findings.append({
                    "type": "AUTOMATED_TEST",
                    "severity": "HIGH",
                    "message": test_result["message"],
                })
                score -= 0.3
        
        score = max(0.0, min(1.0, score))
        return score, findings

    def _perform_control_test(self, control: Dict) -> Dict[str, Any]:
        """Perform automated testing of a control.
        
        In production, this would integrate with actual testing systems.
        
        Args:
            control: Control to test
            
        Returns:
            Test result
        """
        # Simulate test - in production, actual testing logic would be here
        test_passed = random.random() > 0.1  # 90% pass rate simulation
        
        if test_passed:
            return {"passed": True, "message": "Control test passed"}
        else:
            return {
                "passed": False,
                "message": f"Control {control.get('control_id')} test failed",
            }

    def _update_control_status(self, control_id: str, status: str, score: float) -> None:
        """Update control status based on validation.
        
        Args:
            control_id: Control ID
            status: Validation status
            score: Validation score
        """
        control = self.store.get_control(control_id)
        if not control:
            return
        
        # Map validation status to control status
        status_map = {
            "EFFECTIVE": "COMPLIANT",
            "NEEDS_IMPROVEMENT": "PARTIALLY_COMPLIANT",
            "INEFFECTIVE": "NON_COMPLIANT",
        }
        
        # Map validation status to effectiveness
        effectiveness_map = {
            "EFFECTIVE": "EFFECTIVE",
            "NEEDS_IMPROVEMENT": "NEEDS_IMPROVEMENT",
            "INEFFECTIVE": "INEFFECTIVE",
        }
        
        control["status"] = status_map.get(status, "UNDER_REVIEW")
        control["effectiveness"] = effectiveness_map.get(status, "UNKNOWN")
        control["last_tested"] = datetime.now(timezone.utc)
        control["test_frequency_days"] = control.get("test_frequency_days", 90)
        control["next_test"] = datetime.now(timezone.utc) + timedelta(days=control["test_frequency_days"])

    def batch_validate(
        self,
        control_ids: List[str],
        validation_type: str = "AUTOMATED",
    ) -> Dict[str, Any]:
        """Validate multiple controls.
        
        Args:
            control_ids: List of control IDs to validate
            validation_type: Type of validation
            
        Returns:
            Batch validation results
        """
        results = []
        for ctrl_id in control_ids:
            result = self.validate_control(ctrl_id, validation_type)
            results.append({
                "control_id": ctrl_id,
                "status": result.status,
                "score": result.score,
                "findings_count": len(result.findings),
            })
        
        passed = len([r for r in results if r["status"] == "EFFECTIVE"])
        needs_improvement = len([r for r in results if r["status"] == "NEEDS_IMPROVEMENT"])
        ineffective = len([r for r in results if r["status"] == "INEFFECTIVE"])
        
        return {
            "total": len(results),
            "effective": passed,
            "needs_improvement": needs_improvement,
            "ineffective": ineffective,
            "pass_rate": (passed / len(results) * 100) if results else 0,
            "results": results,
        }

    def get_validation_trend(self, control_id: str, days: int = 90) -> Dict[str, Any]:
        """Get validation trend for a control.
        
        Args:
            control_id: Control ID
            days: Number of days to analyze
            
        Returns:
            Trend analysis
        """
        history = self._validation_history.get(control_id, [])
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        recent_validations = [
            v for v in history
            if v.validated_at >= cutoff
        ]
        
        if not recent_validations:
            return {
                "control_id": control_id,
                "trend": "NO_DATA",
                "validations_count": 0,
            }
        
        scores = [v.score for v in recent_validations]
        current_score = scores[-1] if scores else 0
        
        # Calculate trend
        if len(scores) >= 2:
            delta = scores[-1] - scores[0]
            if delta > 0.1:
                trend = "IMPROVING"
            elif delta < -0.1:
                trend = "DECLINING"
            else:
                trend = "STABLE"
        else:
            trend = "STABLE"
        
        return {
            "control_id": control_id,
            "trend": trend,
            "validations_count": len(recent_validations),
            "current_score": current_score,
            "average_score": sum(scores) / len(scores),
            "highest_score": max(scores),
            "lowest_score": min(scores),
            "score_history": [
                {"date": v.validated_at.isoformat(), "score": v.score}
                for v in recent_validations[-10:]
            ],
        }

    def get_effectiveness_report(self) -> Dict[str, Any]:
        """Get overall control effectiveness report."""
        all_controls = list(self.store.controls.values())
        
        effectiveness_counts = {
            "EFFECTIVE": 0,
            "NEEDS_IMPROVEMENT": 0,
            "INEFFECTIVE": 0,
            "UNKNOWN": 0,
        }
        
        category_effectiveness = {}
        
        for ctrl in all_controls:
            eff = ctrl.get("effectiveness", "UNKNOWN")
            effectiveness_counts[eff] = effectiveness_counts.get(eff, 0) + 1
            
            cat = ctrl.get("category", "UNCATEGORIZED")
            if cat not in category_effectiveness:
                category_effectiveness[cat] = {"EFFECTIVE": 0, "INEFFECTIVE": 0}
            if eff == "EFFECTIVE":
                category_effectiveness[cat]["EFFECTIVE"] += 1
            elif eff in ("INEFFECTIVE", "NEEDS_IMPROVEMENT"):
                category_effectiveness[cat]["INEFFECTIVE"] += 1
        
        total_controls = len(all_controls)
        
        return {
            "total_controls": total_controls,
            "effectiveness_distribution": effectiveness_counts,
            "effectiveness_rate": (effectiveness_counts.get("EFFECTIVE", 0) / total_controls * 100) if total_controls > 0 else 0,
            "category_effectiveness": category_effectiveness,
            "controls_needing_attention": [
                ctrl.get("control_id")
                for ctrl in all_controls
                if ctrl.get("effectiveness") in ("INEFFECTIVE", "NEEDS_IMPROVEMENT")
            ],
        }


def get_control_validator() -> ControlValidationService:
    """Get the global control validation service instance."""
    from .store import get_compliance_store
    store = get_compliance_store()
    return ControlValidationService(store)