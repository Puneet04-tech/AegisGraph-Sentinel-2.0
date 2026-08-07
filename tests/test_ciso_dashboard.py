import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from src.command_center.dashboards.ciso import (
    BoardReport,
    BoardReporting,
    CISODashboard,
    ComplianceStatus,
    ComplianceSummary,
    ExecutiveMetrics,
    GlobalThreatView,
    RiskLevel,
    ThreatOverview,
)

FROZEN_NOW = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(FROZEN_NOW.year, FROZEN_NOW.month, FROZEN_NOW.day,
                   FROZEN_NOW.hour, FROZEN_NOW.minute, FROZEN_NOW.second,
                   FROZEN_NOW.microsecond, tzinfo=tz or timezone.utc)


def run(coro):
    return asyncio.run(coro)


def frozen_ciso(monkeypatch):
    monkeypatch.setattr("src.command_center.dashboards.ciso.datetime", _FrozenDateTime)


class TestRiskLevel:
    def test_enum_members(self):
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MINIMAL.value == "minimal"

    def test_str_enum_equality(self):
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.CRITICAL != "low"

    def test_all_defined_values(self):
        assert {level.value for level in RiskLevel} == {
            "critical", "high", "medium", "low", "minimal",
        }


class TestComplianceStatus:
    def test_enum_members(self):
        assert ComplianceStatus.COMPLIANT.value == "compliant"
        assert ComplianceStatus.PARTIAL.value == "partial"
        assert ComplianceStatus.NON_COMPLIANT.value == "non_compliant"
        assert ComplianceStatus.UNKNOWN.value == "unknown"

    def test_str_enum_equality(self):
        assert ComplianceStatus.COMPLIANT == "compliant"
        assert ComplianceStatus.NON_COMPLIANT != "partial"


class TestExecutiveMetrics:
    def test_dataclass_fields(self):
        m = ExecutiveMetrics(
            total_cases=1, open_cases=2, high_risk_cases=3, resolved_cases_today=4,
            resolved_cases_week=5, avg_resolution_time_hours=1.5,
            fraud_prevention_amount=100.0, false_positive_rate=0.1, detection_rate=0.9,
            system_uptime_percent=99.0, api_calls_today=10, active_users=2,
        )
        assert m.total_cases == 1
        assert m.open_cases == 2
        assert m.high_risk_cases == 3
        assert m.resolved_cases_today == 4
        assert m.resolved_cases_week == 5
        assert m.avg_resolution_time_hours == pytest.approx(1.5)
        assert m.fraud_prevention_amount == pytest.approx(100.0)
        assert m.false_positive_rate == pytest.approx(0.1)
        assert m.detection_rate == pytest.approx(0.9)
        assert m.system_uptime_percent == pytest.approx(99.0)
        assert m.api_calls_today == 10
        assert m.active_users == 2

    def test_defaults_not_required(self):
        with pytest.raises(TypeError):
            ExecutiveMetrics()

    def test_zero_negative_values_allowed(self):
        m = ExecutiveMetrics(
            total_cases=0, open_cases=0, high_risk_cases=0, resolved_cases_today=0,
            resolved_cases_week=0, avg_resolution_time_hours=0.0,
            fraud_prevention_amount=-5.0, false_positive_rate=0.0, detection_rate=0.0,
            system_uptime_percent=0.0, api_calls_today=0, active_users=0,
        )
        assert m.fraud_prevention_amount == pytest.approx(-5.0)
        assert m.active_users == 0


class TestThreatOverview:
    def test_dataclass_fields(self):
        t = ThreatOverview(
            total_threats=10, active_threats=2, blocked_threats=8,
            threats_by_type={"mule_accounts": 10}, threats_by_region={},
            emerging_threats=[{"type": "x"}], threat_level=RiskLevel.LOW,
        )
        assert t.total_threats == 10
        assert t.active_threats == 2
        assert t.blocked_threats == 8
        assert t.threats_by_type == {"mule_accounts": 10}
        assert t.emerging_threats == [{"type": "x"}]
        assert t.threat_level == RiskLevel.LOW

    def test_empty_collections(self):
        t = ThreatOverview(0, 0, 0, {}, {}, [], RiskLevel.MINIMAL)
        assert t.threats_by_type == {}
        assert t.emerging_threats == []


class TestComplianceSummary:
    def test_dataclass_fields(self):
        c = ComplianceSummary(
            framework="GDPR", status=ComplianceStatus.COMPLIANT, score=92.0,
            requirements_met=46, requirements_total=50, gaps=["Art. 30"],
            last_audit=FROZEN_NOW,
        )
        assert c.framework == "GDPR"
        assert c.status == ComplianceStatus.COMPLIANT
        assert c.score == pytest.approx(92.0)
        assert c.requirements_met == 46
        assert c.requirements_total == 50
        assert c.gaps == ["Art. 30"]
        assert c.last_audit == FROZEN_NOW

    def test_zero_requirements(self):
        c = ComplianceSummary(
            framework="SOC2", status=ComplianceStatus.PARTIAL, score=0.0,
            requirements_met=0, requirements_total=0, gaps=[], last_audit=FROZEN_NOW,
        )
        assert c.requirements_met <= c.requirements_total
        assert c.score == pytest.approx(0.0)


class TestBoardReport:
    def test_dataclass_fields(self):
        r = BoardReport(
            period="August 2026", executive_summary="summary", key_metrics={"a": 1},
            risk_landscape={"risk": "low"}, compliance_status={},
            recommendations=["r"], risk_factors=[{"factor": "f"}],
            investment_roi={"roi": 1.0}, generated_at=FROZEN_NOW,
        )
        assert r.period == "August 2026"
        assert r.executive_summary == "summary"
        assert r.key_metrics == {"a": 1}
        assert r.risk_landscape == {"risk": "low"}
        assert r.recommendations == ["r"]
        assert r.investment_roi == {"roi": 1.0}
        assert r.generated_at == FROZEN_NOW


class TestCISODashboard:
    def test_init(self):
        d = CISODashboard("org-123")
        assert d.organization_id == "org-123"
        assert d.cache_ttl == 60

    def test_get_executive_metrics(self):
        m = run(CISODashboard("org")._get_executive_metrics())
        assert m.total_cases == 1250
        assert m.open_cases == 45
        assert m.high_risk_cases == 12
        assert m.resolved_cases_today == 8
        assert m.resolved_cases_week == 42
        assert m.avg_resolution_time_hours == pytest.approx(4.5)
        assert m.fraud_prevention_amount == pytest.approx(27600000)
        assert m.false_positive_rate == pytest.approx(0.03)
        assert m.detection_rate == pytest.approx(0.968)
        assert m.system_uptime_percent == pytest.approx(99.99)
        assert m.api_calls_today == 125000
        assert m.active_users == 245

    def test_get_threat_overview(self):
        t = run(CISODashboard("org")._get_threat_overview())
        assert t.total_threats == 892
        assert t.active_threats == 15
        assert t.blocked_threats == 877
        assert t.total_threats == t.active_threats + t.blocked_threats
        assert t.threats_by_type == {
            "mule_accounts": 425,
            "account_takeover": 156,
            "payment_fraud": 201,
            "identity_theft": 78,
            "social_engineering": 32,
        }
        assert sum(t.threats_by_type.values()) == t.total_threats
        assert t.threats_by_region == {
            "North America": 312,
            "Europe": 245,
            "Asia Pacific": 289,
            "Latin America": 34,
            "Africa": 12,
        }
        assert sum(t.threats_by_region.values()) == t.total_threats
        assert t.threat_level == RiskLevel.MEDIUM
        assert len(t.emerging_threats) == 2
        assert t.emerging_threats[0]["type"] == "AI-generated phishing"
        assert t.emerging_threats[0]["severity"] == "high"
        assert t.emerging_threats[0]["affected_count"] == 45
        assert t.emerging_threats[1]["type"] == "Synthetic identity fraud"
        assert t.emerging_threats[1]["affected_count"] == 23

    def test_get_threat_overview_frozen_time(self, monkeypatch):
        frozen_ciso(monkeypatch)
        t = run(CISODashboard("org")._get_threat_overview())
        assert t.emerging_threats[0]["detected_at"] == FROZEN_NOW.isoformat()
        assert t.emerging_threats[1]["detected_at"] == (
            FROZEN_NOW - timedelta(hours=6)
        ).isoformat()

    def test_get_compliance_summary(self):
        summaries = run(CISODashboard("org")._get_compliance_summary())
        assert len(summaries) == 4
        assert [s.framework for s in summaries] == [
            "PCI-DSS", "SOC2 Type II", "GDPR", "RBI Guidelines",
        ]
        assert [s.score for s in summaries] == pytest.approx([98.5, 95.0, 92.0, 96.0])
        for s in summaries:
            assert s.status == ComplianceStatus.COMPLIANT
            assert s.requirements_met <= s.requirements_total
            assert s.gaps == [g for g in s.gaps]
        assert summaries[0].gaps == ["6.4.1 - Automated vulnerability scans"]
        assert summaries[1].gaps == []
        assert summaries[2].gaps == ["Art. 30 - Records of processing activities"]

    def test_get_compliance_summary_audit_dates_frozen(self, monkeypatch):
        frozen_ciso(monkeypatch)
        summaries = run(CISODashboard("org")._get_compliance_summary())
        expected = [30, 15, 45, 20]
        for s, days in zip(summaries, expected):
            assert s.last_audit == FROZEN_NOW - timedelta(days=days)

    def test_get_trend_data(self):
        trends = run(CISODashboard("org")._get_trend_data())
        assert set(trends) == {
            "fraud_cases_trend",
            "detection_rate_trend",
            "resolution_time_trend",
            "api_calls_trend",
        }
        for key in trends:
            assert len(trends[key]["dates"]) == 30
            assert len(trends[key]["values"]) == 30
            assert trends[key]["dates"] == trends["fraud_cases_trend"]["dates"]
        assert trends["fraud_cases_trend"]["values"] == [45 + (i % 10) for i in range(30)]
        assert trends["detection_rate_trend"]["values"] == [96 + (i % 3) for i in range(30)]
        assert trends["resolution_time_trend"]["values"] == pytest.approx(
            [4.5 - (i * 0.05) for i in range(30)]
        )
        assert trends["api_calls_trend"]["values"] == [100000 + (i * 1000) for i in range(30)]

    def test_get_trend_data_frozen_dates(self, monkeypatch):
        frozen_ciso(monkeypatch)
        trends = run(CISODashboard("org")._get_trend_data())
        expected = [(FROZEN_NOW - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(30, 0, -1)]
        assert trends["fraud_cases_trend"]["dates"] == expected
        assert expected[0] == (FROZEN_NOW - timedelta(days=30)).strftime("%Y-%m-%d")
        assert expected[-1] == (FROZEN_NOW - timedelta(days=1)).strftime("%Y-%m-%d")

    def test_get_active_alerts(self):
        alerts = run(CISODashboard("org")._get_active_alerts())
        assert len(alerts) == 3
        assert [a["id"] for a in alerts] == ["ALT_001", "ALT_002", "ALT_003"]
        assert alerts[0]["type"] == "high_risk_case"
        assert alerts[0]["severity"] == "critical"
        assert alerts[0]["action_required"] is True
        assert alerts[1]["type"] == "compliance"
        assert alerts[1]["action_required"] is True
        assert alerts[2]["type"] == "system"
        assert alerts[2]["action_required"] is False
        for a in alerts:
            datetime.fromisoformat(a["timestamp"])
            assert a["title"]
            assert a["description"]

    def test_get_active_alerts_frozen_time(self, monkeypatch):
        frozen_ciso(monkeypatch)
        alerts = run(CISODashboard("org")._get_active_alerts())
        assert alerts[0]["timestamp"] == FROZEN_NOW.isoformat()
        assert alerts[1]["timestamp"] == (FROZEN_NOW - timedelta(hours=2)).isoformat()
        assert alerts[2]["timestamp"] == (FROZEN_NOW - timedelta(hours=4)).isoformat()

    def test_get_dashboard_data(self):
        data = run(CISODashboard("org-1").get_dashboard_data())
        assert set(data) == {
            "metrics", "threats", "compliance", "trends", "alerts", "last_updated",
        }
        assert data["metrics"].total_cases == 1250
        assert data["metrics"].detection_rate == pytest.approx(0.968)
        assert data["threats"].total_threats == 892
        assert data["threats"].threat_level == RiskLevel.MEDIUM
        assert len(data["compliance"]) == 4
        assert len(data["trends"]["fraud_cases_trend"]["dates"]) == 30
        assert len(data["alerts"]) == 3
        datetime.fromisoformat(data["last_updated"])

    def test_get_dashboard_data_frozen_time(self, monkeypatch):
        frozen_ciso(monkeypatch)
        data = run(CISODashboard("org-1").get_dashboard_data())
        assert data["last_updated"] == FROZEN_NOW.isoformat()


class TestBoardReporting:
    def test_init(self):
        b = BoardReporting("org-1")
        assert b.organization_id == "org-1"

    def test_aggregate_period_metrics(self):
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        end = datetime(2026, 8, 31, tzinfo=timezone.utc)
        m = run(BoardReporting("org")._aggregate_period_metrics(start, end))
        assert m["fraud_prevention_amount"] == 27600000
        assert m["detection_rate"] == pytest.approx(0.968)
        assert m["false_positive_rate"] == pytest.approx(0.03)
        assert m["resolved_cases"] == 342
        assert m["avg_resolution_time"] == pytest.approx(4.5)
        assert m["uptime"] == pytest.approx(99.99)
        assert m["api_calls"] == 3750000

    def test_analyze_risk_landscape(self):
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        end = datetime(2026, 8, 31, tzinfo=timezone.utc)
        r = run(BoardReporting("org")._analyze_risk_landscape(start, end))
        assert r["overall_risk"] == "medium"
        assert r["active_threats"] == 15
        assert r["threat_categories"] == {
            "mule_accounts": 8, "account_takeover": 4, "payment_fraud": 3,
        }
        assert r["geographic_distribution"] == {
            "high_risk_regions": ["South Asia", "Southeast Asia"],
            "emerging_threats": ["Synthetic Identity", "AI-Generated Fraud"],
        }
        assert r["trend"] == "increasing"
        assert r["confidence"] == pytest.approx(0.85)

    def test_get_compliance_status(self):
        c = run(BoardReporting("org")._get_compliance_status())
        assert set(c) == {"pci_dss", "soc2", "gdpr"}
        assert c["pci_dss"]["status"] == "compliant"
        assert c["pci_dss"]["score"] == pytest.approx(98.5)
        assert c["soc2"]["status"] == "compliant"
        assert c["soc2"]["score"] == pytest.approx(95.0)
        assert c["gdpr"]["status"] == "compliant"
        assert c["gdpr"]["score"] == pytest.approx(92.0)
        for entry in c.values():
            datetime.fromisoformat(entry["next_audit"])

    def test_get_compliance_status_frozen_audits(self, monkeypatch):
        frozen_ciso(monkeypatch)
        c = run(BoardReporting("org")._get_compliance_status())
        assert c["pci_dss"]["next_audit"] == (FROZEN_NOW + timedelta(days=60)).isoformat()
        assert c["soc2"]["next_audit"] == (FROZEN_NOW + timedelta(days=45)).isoformat()
        assert c["gdpr"]["next_audit"] == (FROZEN_NOW + timedelta(days=90)).isoformat()

    def test_calculate_roi_default_metrics(self):
        metrics = {"fraud_prevention_amount": 27600000, "resolved_cases": 342}
        roi = run(BoardReporting("org")._calculate_roi(metrics))
        expected_benefit = 27600000 + 342 * 5000
        assert roi["implementation_cost"] == 5000000
        assert roi["annual_operational_cost"] == 1200000
        assert roi["total_benefit"] == pytest.approx(expected_benefit)
        assert roi["annual_roi_percent"] == pytest.approx(
            ((expected_benefit - 1200000) / 1200000) * 100
        )
        assert roi["payback_period_months"] == 3
        assert roi["five_year_npv"] == pytest.approx(expected_benefit * 4 - 5000000)

    def test_calculate_roi_custom_metrics(self):
        metrics = {"fraud_prevention_amount": 10000000, "resolved_cases": 100}
        roi = run(BoardReporting("org")._calculate_roi(metrics))
        expected_benefit = 10000000 + 100 * 5000
        assert roi["total_benefit"] == pytest.approx(expected_benefit)
        assert roi["annual_roi_percent"] == pytest.approx(
            ((expected_benefit - 1200000) / 1200000) * 100
        )
        assert roi["five_year_npv"] == pytest.approx(expected_benefit * 4 - 5000000)

    def test_calculate_roi_zero_values(self):
        roi = run(BoardReporting("org")._calculate_roi(
            {"fraud_prevention_amount": 0, "resolved_cases": 0}
        ))
        assert roi["total_benefit"] == pytest.approx(0.0)
        assert roi["annual_roi_percent"] == pytest.approx(-100.0)
        assert roi["five_year_npv"] == pytest.approx(-5000000)

    def test_calculate_roi_negative_values(self):
        roi = run(BoardReporting("org")._calculate_roi(
            {"fraud_prevention_amount": -1000000, "resolved_cases": -10}
        ))
        expected_benefit = -1000000 - 50000
        assert roi["total_benefit"] == pytest.approx(expected_benefit)
        assert roi["annual_roi_percent"] == pytest.approx(
            ((expected_benefit - 1200000) / 1200000) * 100
        )
        assert roi["five_year_npv"] == pytest.approx(expected_benefit * 4 - 5000000)

    def test_calculate_roi_missing_key_raises(self):
        with pytest.raises(KeyError):
            run(BoardReporting("org")._calculate_roi({"resolved_cases": 342}))

    def test_calculate_roi_empty_metrics_raises(self):
        with pytest.raises(KeyError):
            run(BoardReporting("org")._calculate_roi({}))

    def test_generate_recommendations_nominal(self):
        metrics = {"detection_rate": 0.968, "false_positive_rate": 0.03}
        risk_landscape = {"active_threats": 15}
        recs = run(BoardReporting("org")._generate_recommendations(metrics, risk_landscape))
        assert len(recs) == 3
        assert "Increase monitoring frequency for high-risk accounts" in recs
        assert "Schedule quarterly board review meetings for risk oversight" in recs
        assert "Implement additional AI agent capabilities for proactive threat hunting" in recs
        assert all("model retraining" not in r for r in recs)
        assert all("false positive" not in r for r in recs)

    def test_generate_recommendations_low_detection(self):
        metrics = {"detection_rate": 0.90, "false_positive_rate": 0.03}
        risk_landscape = {"active_threats": 5}
        recs = run(BoardReporting("org")._generate_recommendations(metrics, risk_landscape))
        assert "Consider model retraining to improve detection rate above 95%" in recs
        assert len(recs) == 3

    def test_generate_recommendations_high_false_positive(self):
        metrics = {"detection_rate": 0.968, "false_positive_rate": 0.10}
        risk_landscape = {"active_threats": 5}
        recs = run(BoardReporting("org")._generate_recommendations(metrics, risk_landscape))
        assert "Review threshold settings to reduce false positive rate" in recs
        assert len(recs) == 3

    def test_generate_recommendations_low_threats(self):
        metrics = {"detection_rate": 0.968, "false_positive_rate": 0.03}
        risk_landscape = {"active_threats": 5}
        recs = run(BoardReporting("org")._generate_recommendations(metrics, risk_landscape))
        assert len(recs) == 2
        assert all("monitoring frequency" not in r for r in recs)

    def test_generate_recommendations_all_conditions(self):
        metrics = {"detection_rate": 0.90, "false_positive_rate": 0.10}
        risk_landscape = {"active_threats": 15}
        recs = run(BoardReporting("org")._generate_recommendations(metrics, risk_landscape))
        assert len(recs) == 5
        assert "Consider model retraining to improve detection rate above 95%" in recs
        assert "Review threshold settings to reduce false positive rate" in recs
        assert "Increase monitoring frequency for high-risk accounts" in recs

    def test_generate_recommendations_boundary_values(self):
        metrics = {"detection_rate": 0.95, "false_positive_rate": 0.05}
        risk_landscape = {"active_threats": 10}
        recs = run(BoardReporting("org")._generate_recommendations(metrics, risk_landscape))
        assert len(recs) == 2
        assert all("model retraining" not in r for r in recs)
        assert all("false positive" not in r for r in recs)
        assert all("monitoring frequency" not in r for r in recs)

    def test_generate_recommendations_missing_key_raises(self):
        with pytest.raises(KeyError):
            run(BoardReporting("org")._generate_recommendations(
                {"false_positive_rate": 0.03}, {"active_threats": 5}
            ))

    def test_generate_recommendations_empty_risk_raises(self):
        with pytest.raises(KeyError):
            run(BoardReporting("org")._generate_recommendations(
                {"detection_rate": 0.968, "false_positive_rate": 0.03}, {}
            ))

    def test_identify_risk_factors(self):
        factors = run(BoardReporting("org")._identify_risk_factors({}))
        assert len(factors) == 3
        assert factors[0]["factor"] == "Emerging AI-generated fraud techniques"
        assert factors[0]["impact"] == "high"
        assert factors[0]["likelihood"] == "medium"
        assert factors[0]["mitigation"]
        assert factors[1]["factor"] == "Seasonal fraud spikes (festivals, holidays)"
        assert factors[2]["factor"] == "Third-party integration vulnerabilities"
        for f in factors:
            assert set(f) == {"factor", "impact", "likelihood", "mitigation"}

    def test_generate_board_report(self):
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        end = datetime(2026, 8, 31, tzinfo=timezone.utc)
        report = run(BoardReporting("org-1").generate_board_report(start, end))
        assert report.period == "August 2026"
        assert "August 2026" in report.executive_summary
        assert "2.8 Crore" in report.executive_summary
        assert "96.8% detection rate" in report.executive_summary
        assert "3.0% false positive rate" in report.executive_summary
        assert "Resolved 342 cases" in report.executive_summary
        assert "4.5 hours" in report.executive_summary
        assert "99.99%" in report.executive_summary
        assert "medium risk level with 15 active threats" in report.executive_summary
        assert report.key_metrics["fraud_prevention"] == 27600000
        assert report.key_metrics["detection_rate"] == pytest.approx(0.968)
        assert report.key_metrics["false_positive_rate"] == pytest.approx(0.03)
        assert report.key_metrics["cases_resolved"] == 342
        assert report.key_metrics["avg_resolution_hours"] == pytest.approx(4.5)
        assert report.key_metrics["system_uptime"] == pytest.approx(99.99)
        assert report.key_metrics["api_calls_processed"] == 3750000
        assert report.risk_landscape["overall_risk"] == "medium"
        assert report.risk_landscape["active_threats"] == 15
        assert report.compliance_status["pci_dss"]["score"] == pytest.approx(98.5)
        assert report.recommendations[0] == "Increase monitoring frequency for high-risk accounts"
        assert len(report.recommendations) == 3
        assert len(report.risk_factors) == 3
        assert report.investment_roi["total_benefit"] == pytest.approx(29310000)
        assert report.investment_roi["annual_roi_percent"] == pytest.approx(2342.5)
        assert report.investment_roi["five_year_npv"] == pytest.approx(112240000)
        assert report.generated_at.tzinfo is not None
        assert report.generated_at <= datetime.now(timezone.utc)

    def test_generate_board_report_frozen_time(self, monkeypatch):
        frozen_ciso(monkeypatch)
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        end = datetime(2026, 8, 31, tzinfo=timezone.utc)
        report = run(BoardReporting("org-1").generate_board_report(start, end))
        assert report.generated_at == FROZEN_NOW
        assert report.compliance_status["pci_dss"]["next_audit"] == (
            FROZEN_NOW + timedelta(days=60)
        ).isoformat()

    def test_generate_board_report_include_predictions_false(self):
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        end = datetime(2026, 8, 31, tzinfo=timezone.utc)
        report = run(BoardReporting("org-1").generate_board_report(
            start, end, include_predictions=False
        ))
        assert report.period == "August 2026"
        assert report.executive_summary


class TestGlobalThreatView:
    def test_init(self):
        g = GlobalThreatView()
        assert g.threat_intel_sources == []

    def test_get_active_campaigns(self):
        c = run(GlobalThreatView()._get_active_campaigns())
        assert len(c) == 2
        assert [x["name"] for x in c] == ["Operation GoldBrick", "SilentBanker"]
        assert c[0]["type"] == "mule_account_network"
        assert c[0]["target"] == "financial_services"
        assert c[0]["confidence"] == pytest.approx(0.85)
        assert c[0]["affected_regions"] == ["South Asia", "Southeast Asia"]
        assert c[1]["type"] == "atm_fraud"
        assert c[1]["confidence"] == pytest.approx(0.72)

    def test_get_threat_actors(self):
        a = run(GlobalThreatView()._get_threat_actors())
        assert len(a) == 2
        assert a[0]["name"] == "APT-41"
        assert a[0]["type"] == "nation_state"
        assert a[1]["name"] == "Silence Group"
        assert a[1]["type"] == "cybercrime"
        assert all(actor["motivation"] == "financial" for actor in a)
        assert all(actor["active"] is True for actor in a)

    def test_get_ttps(self):
        t = run(GlobalThreatView()._get_ttps())
        assert set(t) == {"initial_access", "execution", "persistence", "impact"}
        assert t["initial_access"] == ["phishing", "valid_accounts"]
        assert t["execution"] == ["scripting", "native_api"]
        assert t["persistence"] == ["account_manipulation"]
        assert t["impact"] == ["financial_theft"]

    def test_get_exploits(self):
        e = run(GlobalThreatView()._get_exploits())
        assert len(e) == 1
        assert e[0]["cve"] == "CVE-2024-XXXX"
        assert e[0]["severity"] == "critical"
        assert e[0]["description"]

    def test_get_geographic_threats(self):
        g = run(GlobalThreatView()._get_geographic_threats())
        assert g["high_risk"] == ["Nigeria", "India", "Brazil", "Indonesia"]
        assert g["medium_risk"] == ["Philippines", "Pakistan", "Bangladesh"]
        assert g["trending_up"] == ["Vietnam", "Thailand", "Myanmar"]

    def test_get_industry_threats(self):
        i = run(GlobalThreatView()._get_industry_threats())
        assert set(i) == {"banking", "fintech"}
        assert i["banking"]["primary_threats"] == ["mule_accounts", "atm_fraud"]
        assert i["banking"]["attack_volume"] == 12500
        assert i["fintech"]["primary_threats"] == ["synthetic_identity", "account_takeover"]
        assert i["fintech"]["attack_volume"] == 8500

    def test_get_global_threat_data(self):
        data = run(GlobalThreatView().get_global_threat_data())
        assert data["global_threat_level"] == "elevated"
        assert len(data["active_campaigns"]) == 2
        assert len(data["threat_actors"]) == 2
        assert set(data["tactics_techniques"]) == {
            "initial_access", "execution", "persistence", "impact",
        }
        assert len(data["vulnerability_exploits"]) == 1
        assert data["geo_threats"]["high_risk"][0] == "Nigeria"
        assert data["industry_threats"]["banking"]["attack_volume"] == 12500
        assert data["industry_threats"]["fintech"]["attack_volume"] == 8500
