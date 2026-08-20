# AegisGraph Sentinel Enterprise
# Regulatory Compliance Fabric Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.regulatory_fabric.models import (
    RegulationDomain, RegulationStatus, ControlStatus, ControlEffectiveness, 
    AssessmentStatus, EvidenceStatus, RiskLevel, Regulation, Control, Policy, 
    ControlMapping, ComplianceAssessment, AuditEvidence, ComplianceRisk, RegulatoryUpdate, ComplianceDashboard
)

def test_regulation_to_dict():
    reg = Regulation(
        domain=RegulationDomain.PCI_DSS,
        name="PCI DSS Core",
        version="4.0",
        description="Payment card industry data security standard"
    )
    data = reg.to_dict()
    assert data["domain"] == "PCI_DSS"
    assert data["name"] == "PCI DSS Core"
    assert data["version"] == "4.0"

def test_control_to_dict():
    ctrl = Control(
        control_name="MFA Enforcement",
        control_number="CC6.1",
        description="Enforce multi-factor authentication",
        status=ControlStatus.COMPLIANT,
        effectiveness=ControlEffectiveness.EFFECTIVE
    )
    data = ctrl.to_dict()
    assert data["control_name"] == "MFA Enforcement"
    assert data["status"] == "COMPLIANT"
    assert data["effectiveness"] == "EFFECTIVE"

def test_policy_to_dict():
    pol = Policy(
        name="Access Control Policy",
        domain=RegulationDomain.SOC2,
        status="APPROVED"
    )
    data = pol.to_dict()
    assert data["name"] == "Access Control Policy"
    assert data["domain"] == "SOC2"
    assert data["status"] == "APPROVED"

def test_control_mapping_to_dict():
    mapping = ControlMapping(
        regulation_id="reg-123",
        control_id="ctrl-456",
        mapping_type="DIRECT",
        confidence=0.95
    )
    data = mapping.to_dict()
    assert data["regulation_id"] == "reg-123"
    assert data["confidence"] == 0.95

def test_compliance_assessment_to_dict():
    assessment = ComplianceAssessment(
        regulation_id="reg-1",
        status=AssessmentStatus.COMPLETED,
        overall_score=92.5,
        controls_assessed=10,
        controls_passed=9,
        controls_failed=1
    )
    data = assessment.to_dict()
    assert data["overall_score"] == 92.5
    assert data["controls_passed"] == 9

def test_audit_evidence_to_dict():
    evidence = AuditEvidence(
        control_id="ctrl-1",
        evidence_type="config_file",
        status=EvidenceStatus.VERIFIED,
        source_system="AWS IAM"
    )
    data = evidence.to_dict()
    assert data["control_id"] == "ctrl-1"
    assert data["status"] == "VERIFIED"

def test_compliance_risk_to_dict():
    risk = ComplianceRisk(
        risk_level=RiskLevel.HIGH,
        description="Inadequate logging",
        likelihood=0.5,
        impact=0.8
    )
    data = risk.to_dict()
    assert data["risk_level"] == "HIGH"
    assert data["risk_score"] == 0.4

def test_regulatory_update_to_dict():
    update = RegulatoryUpdate(
        regulation_id="reg-1",
        title="Amendment to RBI security guidelines",
        compliance_impact="HIGH"
    )
    data = update.to_dict()
    assert data["title"] == "Amendment to RBI security guidelines"
    assert data["compliance_impact"] == "HIGH"

def test_compliance_dashboard_to_dict():
    db = ComplianceDashboard(
        overall_score=88.0,
        open_findings=3,
        critical_findings=0
    )
    data = db.to_dict()
    assert data["overall_score"] == 88.0
    assert data["open_findings"] == 3
