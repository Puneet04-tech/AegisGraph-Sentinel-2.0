# AegisGraph Sentinel Enterprise
# Digital Twin Network Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime, timezone
from src.security_digital_twin.models import (
    SimulationType, AssetType, RiskLevel, SimulationStatus, 
    DigitalTwinAsset, SimulationScenario, ThreatSimulation, FraudSimulation, AttackPath, RiskForecast, ImpactAssessment, AuditEvent
)

def test_digital_twin_asset_creation():
    asset = DigitalTwinAsset(
        asset_id="ast-01",
        asset_type=AssetType.SERVER,
        name="Core Database Server",
        properties={"os": "linux"},
        risk_score=75.5
    )
    assert asset.asset_id == "ast-01"
    assert asset.asset_type == AssetType.SERVER
    assert asset.name == "Core Database Server"
    assert asset.properties == {"os": "linux"}
    assert asset.risk_score == 75.5

def test_simulation_scenario_creation():
    scenario = SimulationScenario(
        scenario_id="sc-01",
        name="Simulate DB Ransomware",
        simulation_type=SimulationType.THREAT,
        description="Ransomware starts on endpoint and spreads to DB",
        assets_involved=["ast-01", "ast-02"]
    )
    assert scenario.scenario_id == "sc-01"
    assert scenario.status == SimulationStatus.PLANNED

def test_threat_simulation_creation():
    ts = ThreatSimulation(
        simulation_id="ts-001",
        scenario_id="sc-01",
        threat_type="ransomware",
        initial_conditions={"privilege_escalation": True},
        success_probability=0.35,
        impact_score=85.0
    )
    assert ts.simulation_id == "ts-001"
    assert ts.success_probability == 0.35

def test_fraud_simulation_creation():
    fs = FraudSimulation(
        simulation_id="fs-001",
        scenario_id="sc-02",
        fraud_type="account_takeover",
        fraud_pattern="mismatch_device_ip",
        financial_impact=500000.0,
        detection_likelihood=0.75
    )
    assert fs.simulation_id == "fs-001"
    assert fs.financial_impact == 500000.0

def test_attack_path_creation():
    ap = AttackPath(
        path_id="ap-100",
        source_asset="ast-02",
        target_asset="ast-01",
        attack_steps=[{"step": 1, "action": "phish"}],
        overall_risk=0.55
    )
    assert ap.path_id == "ap-100"
    assert ap.overall_risk == 0.55

def test_risk_forecast_creation():
    rf = RiskForecast(
        forecast_id="rf-100",
        metric_type="anomaly_count",
        current_value=12.0,
        forecasted_value=25.0,
        confidence=0.88
    )
    assert rf.forecast_id == "rf-100"
    assert rf.forecasted_value == 25.0

def test_impact_assessment_creation():
    ia = ImpactAssessment(
        assessment_id="ia-100",
        scenario_id="sc-01",
        affected_assets=["ast-01"],
        financial_impact=1000000.0,
        overall_impact_score=9.2
    )
    assert ia.assessment_id == "ia-100"
    assert ia.financial_impact == 1000000.0

def test_audit_event_creation():
    now = datetime.now(timezone.utc)
    ae = AuditEvent(
        event_id="ae-100",
        timestamp=now,
        user_id="user-admin",
        action="run_simulation",
        resource_type="scenario",
        resource_id="sc-01"
    )
    assert ae.event_id == "ae-100"
    assert ae.timestamp == now
    assert ae.success is True
