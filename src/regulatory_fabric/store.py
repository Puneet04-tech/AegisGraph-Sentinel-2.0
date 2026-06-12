"""
Storage layer for Regulatory Intelligence & Compliance Fabric.

Provides persistent storage for regulations, controls, assessments, and evidence.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import threading
import uuid


@dataclass
class ComplianceStore:
    """Central storage for compliance data.
    
    Thread-safe in-memory storage with persistence capabilities.
    """
    regulations: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    controls: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    control_mappings: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    assessments: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    evidence: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    risks: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    regulatory_updates: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_regulation(self, regulation: Dict[str, Any]) -> str:
        """Add a new regulation."""
        with self._lock:
            reg_id = regulation.get("regulation_id", str(uuid.uuid4()))
            regulation["regulation_id"] = reg_id
            self.regulations[reg_id] = regulation
            return reg_id

    def get_regulation(self, regulation_id: str) -> Optional[Dict[str, Any]]:
        """Get a regulation by ID."""
        return self.regulations.get(regulation_id)

    def list_regulations(self, domain: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List regulations with optional filtering."""
        results = list(self.regulations.values())
        if domain:
            results = [r for r in results if r.get("domain") == domain]
        if status:
            results = [r for r in results if r.get("status") == status]
        return results

    def add_control(self, control: Dict[str, Any]) -> str:
        """Add a new control."""
        with self._lock:
            ctrl_id = control.get("control_id", str(uuid.uuid4()))
            control["control_id"] = ctrl_id
            self.controls[ctrl_id] = control
            return ctrl_id

    def get_control(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Get a control by ID."""
        return self.controls.get(control_id)

    def list_controls(self, status: Optional[str] = None, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """List controls with optional filtering."""
        results = list(self.controls.values())
        if status:
            results = [c for c in results if c.get("status") == status]
        if category:
            results = [c for c in results if c.get("category") == category]
        return results

    def add_control_mapping(self, mapping: Dict[str, Any]) -> str:
        """Add a control mapping."""
        with self._lock:
            mapping_id = mapping.get("mapping_id", str(uuid.uuid4()))
            mapping["mapping_id"] = mapping_id
            self.control_mappings[mapping_id] = mapping
            return mapping_id

    def get_controls_for_regulation(self, regulation_id: str) -> List[Dict[str, Any]]:
        """Get all controls mapped to a regulation."""
        mapping_ids = [
            m for m in self.control_mappings.values()
            if m.get("regulation_id") == regulation_id
        ]
        controls = []
        for mapping in mapping_ids:
            ctrl = self.controls.get(mapping.get("control_id"))
            if ctrl:
                ctrl["mapping"] = mapping
                controls.append(ctrl)
        return controls

    def add_assessment(self, assessment: Dict[str, Any]) -> str:
        """Add a new assessment."""
        with self._lock:
            assess_id = assessment.get("assessment_id", str(uuid.uuid4()))
            assessment["assessment_id"] = assess_id
            self.assessments[assess_id] = assessment
            return assess_id

    def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get an assessment by ID."""
        return self.assessments.get(assessment_id)

    def list_assessments(self, regulation_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List assessments with optional filtering."""
        results = list(self.assessments.values())
        if regulation_id:
            results = [a for a in results if a.get("regulation_id") == regulation_id]
        if status:
            results = [a for a in results if a.get("status") == status]
        return sorted(results, key=lambda x: x.get("assessment_date", ""), reverse=True)

    def add_evidence(self, evidence: Dict[str, Any]) -> str:
        """Add new evidence."""
        with self._lock:
            evid_id = evidence.get("evidence_id", str(uuid.uuid4()))
            evidence["evidence_id"] = evid_id
            self.evidence[evid_id] = evidence
            return evid_id

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Get evidence by ID."""
        return self.evidence.get(evidence_id)

    def list_evidence(self, control_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List evidence with optional filtering."""
        results = list(self.evidence.values())
        if control_id:
            results = [e for e in results if e.get("control_id") == control_id]
        if status:
            results = [e for e in results if e.get("status") == status]
        return results

    def add_risk(self, risk: Dict[str, Any]) -> str:
        """Add a compliance risk."""
        with self._lock:
            risk_id = risk.get("risk_id", str(uuid.uuid4()))
            risk["risk_id"] = risk_id
            self.risks[risk_id] = risk
            return risk_id

    def get_risk(self, risk_id: str) -> Optional[Dict[str, Any]]:
        """Get a risk by ID."""
        return self.risks.get(risk_id)

    def list_risks(self, regulation_id: Optional[str] = None, risk_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """List risks with optional filtering."""
        results = list(self.risks.values())
        if regulation_id:
            results = [r for r in results if r.get("regulation_id") == regulation_id]
        if risk_level:
            results = [r for r in results if r.get("risk_level") == risk_level]
        return sorted(results, key=lambda x: x.get("risk_score", 0), reverse=True)

    def add_regulatory_update(self, update: Dict[str, Any]) -> str:
        """Add a regulatory update."""
        with self._lock:
            update_id = update.get("update_id", str(uuid.uuid4()))
            update["update_id"] = update_id
            self.regulatory_updates[update_id] = update
            return update_id

    def get_regulatory_update(self, update_id: str) -> Optional[Dict[str, Any]]:
        """Get a regulatory update by ID."""
        return self.regulatory_updates.get(update_id)

    def list_regulatory_updates(self, regulation_id: Optional[str] = None, processed: Optional[bool] = None) -> List[Dict[str, Any]]:
        """List regulatory updates with optional filtering."""
        results = list(self.regulatory_updates.values())
        if regulation_id:
            results = [u for u in results if u.get("regulation_id") == regulation_id]
        if processed is not None:
            results = [u for u in results if u.get("processed") == processed]
        return sorted(results, key=lambda x: x.get("published_date", ""), reverse=True)

    def add_policy(self, policy: Dict[str, Any]) -> str:
        """Add a new policy."""
        with self._lock:
            policy_id = policy.get("policy_id", str(uuid.uuid4()))
            policy["policy_id"] = policy_id
            self.policies[policy_id] = policy
            return policy_id

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get a policy by ID."""
        return self.policies.get(policy_id)

    def list_policies(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """List policies with optional filtering."""
        results = list(self.policies.values())
        if domain:
            results = [p for p in results if p.get("domain") == domain]
        return results

    def get_compliance_score(self, regulation_id: Optional[str] = None) -> float:
        """Calculate overall compliance score."""
        if regulation_id:
            assessments = self.list_assessments(regulation_id=regulation_id, status="COMPLETED")
        else:
            assessments = self.list_assessments(status="COMPLETED")
        
        if not assessments:
            return 0.0
        
        total_score = sum(a.get("overall_score", 0) for a in assessments)
        return total_score / len(assessments)

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics."""
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        for risk in self.risks.values():
            level = risk.get("risk_level", "MEDIUM")
            risk_counts[level] = risk_counts.get(level, 0) + 1

        control_status_counts = {"COMPLIANT": 0, "NON_COMPLIANT": 0, "PARTIALLY_COMPLIANT": 0, "NOT_APPLICABLE": 0}
        for control in self.controls.values():
            status = control.get("status", "UNDER_REVIEW")
            control_status_counts[status] = control_status_counts.get(status, 0) + 1

        return {
            "total_regulations": len(self.regulations),
            "total_controls": len(self.controls),
            "total_assessments": len(self.assessments),
            "total_evidence": len(self.evidence),
            "total_risks": len(self.risks),
            "total_regulatory_updates": len(self.regulatory_updates),
            "unprocessed_updates": len([u for u in self.regulatory_updates.values() if not u.get("processed")]),
            "risk_distribution": risk_counts,
            "control_status_distribution": control_status_counts,
            "overall_compliance_score": self.get_compliance_score(),
        }


# Singleton instance
_store: Optional[ComplianceStore] = None


def get_compliance_store() -> ComplianceStore:
    """Get the global compliance store instance."""
    global _store
    if _store is None:
        _store = ComplianceStore()
    return _store