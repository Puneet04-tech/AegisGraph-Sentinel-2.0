"""Tests that digital twin threat modelling derives its numbers.

Attack path likelihood and impact were ``random.uniform`` draws, and
``evaluate_risk`` ignored both of its arguments and returned four unrelated
random numbers.
"""

import inspect

import pytest

from src.digital_twin import digital_twin_engine as digital_twin_engine_module
from src.digital_twin.digital_twin_engine import ThreatModelingEngine


@pytest.fixture
def engine():
    return ThreatModelingEngine()


class TestDeterminism:
    """Threat models must not be scored by dice."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(digital_twin_engine_module)
        assert "import random" not in source

    def test_identical_scenarios_produce_identical_scores(self, engine):
        scenario = {"attack_types": ["phishing", "malware"]}

        first = engine.models[engine.create_threat_model("t1", scenario)]
        second = engine.models[engine.create_threat_model("t1", scenario)]

        assert (
            [(p["likelihood"], p["impact"]) for p in first["attack_paths"]]
            == [(p["likelihood"], p["impact"]) for p in second["attack_paths"]]
        )


class TestAttackPaths:
    """Likelihood and impact follow the attack type and scenario."""

    def _paths(self, engine, scenario):
        model_id = engine.create_threat_model("t1", scenario)
        return {
            p["attack_type"]: p for p in engine.models[model_id]["attack_paths"]
        }

    def test_supply_chain_outranks_ddos_on_impact(self, engine):
        paths = self._paths(engine, {"attack_types": ["supply_chain", "ddos"]})

        assert paths["supply_chain"]["impact"] > paths["ddos"]["impact"]

    def test_phishing_is_likelier_than_supply_chain(self, engine):
        paths = self._paths(engine, {"attack_types": ["phishing", "supply_chain"]})

        assert paths["phishing"]["likelihood"] > paths["supply_chain"]["likelihood"]

    def test_controls_reduce_likelihood(self, engine):
        unhardened = self._paths(engine, {"attack_types": ["phishing"]})
        hardened = self._paths(engine, {
            "attack_types": ["phishing"], "controls_effectiveness": 0.9,
        })

        assert hardened["phishing"]["likelihood"] < unhardened["phishing"]["likelihood"]

    def test_sophistication_raises_likelihood(self, engine):
        baseline = self._paths(engine, {"attack_types": ["malware"]})
        advanced = self._paths(engine, {
            "attack_types": ["malware"], "sophistication": 1.0,
        })

        assert advanced["malware"]["likelihood"] > baseline["malware"]["likelihood"]

    def test_asset_criticality_raises_impact(self, engine):
        baseline = self._paths(engine, {"attack_types": ["malware"]})
        critical = self._paths(engine, {
            "attack_types": ["malware"], "asset_criticality": 1.0,
        })

        assert critical["malware"]["impact"] > baseline["malware"]["impact"]

    def test_unknown_attack_types_get_the_default(self, engine):
        paths = self._paths(engine, {"attack_types": ["quantum_hijack"]})

        assert 0 < paths["quantum_hijack"]["likelihood"] <= 1
        assert 0 < paths["quantum_hijack"]["impact"] <= 1

    def test_values_stay_in_range_under_extreme_modifiers(self, engine):
        paths = self._paths(engine, {
            "attack_types": ["phishing"],
            "sophistication": 99,
            "asset_criticality": 99,
        })

        assert 0 <= paths["phishing"]["likelihood"] <= 1
        assert 0 <= paths["phishing"]["impact"] <= 1

    def test_nonsense_modifiers_do_not_raise(self, engine):
        paths = self._paths(engine, {
            "attack_types": ["phishing"], "sophistication": "very",
        })

        assert 0 <= paths["phishing"]["likelihood"] <= 1


class TestEvaluateRisk:
    """evaluate_risk reads the twin's threat models."""

    def test_twin_without_a_model_reports_no_threats(self, engine):
        result = engine.evaluate_risk("unmodelled_twin")

        assert result["threat_count"] == 0
        assert result["risk_score"] == 0.0
        assert result["insufficient_data"] is True

    def test_threat_count_matches_the_attack_paths(self, engine):
        engine.create_threat_model("t1", {
            "attack_types": ["phishing", "malware", "insider"],
        })

        assert engine.evaluate_risk("t1")["threat_count"] == 3

    def test_other_twins_models_are_not_counted(self, engine):
        engine.create_threat_model("t1", {"attack_types": ["phishing"]})
        engine.create_threat_model("t2", {"attack_types": ["malware", "insider"]})

        assert engine.evaluate_risk("t1")["threat_count"] == 1

    def test_a_specific_model_can_be_evaluated(self, engine):
        engine.create_threat_model("t1", {"attack_types": ["phishing"]})
        model_id = engine.create_threat_model("t1", {
            "attack_types": ["malware", "insider"],
        })

        assert engine.evaluate_risk("t1", model_id)["threat_count"] == 2

    def test_unknown_model_id_reports_no_data(self, engine):
        engine.create_threat_model("t1", {"attack_types": ["phishing"]})

        assert engine.evaluate_risk("t1", "no-such-model")["insufficient_data"] is True

    def test_risk_score_is_the_worst_path(self, engine):
        model_id = engine.create_threat_model("t1", {
            "attack_types": ["phishing", "ddos", "supply_chain"],
        })
        paths = engine.models[model_id]["attack_paths"]
        worst = max(p["likelihood"] * p["impact"] for p in paths)

        assert engine.evaluate_risk("t1")["risk_score"] == pytest.approx(worst, abs=1e-3)

    def test_more_paths_raise_the_attack_probability(self, engine):
        engine.create_threat_model("t1", {"attack_types": ["phishing"]})
        engine.create_threat_model("t2", {
            "attack_types": ["phishing", "malware", "insider"],
        })

        assert (
            engine.evaluate_risk("t2")["attack_probability"]
            > engine.evaluate_risk("t1")["attack_probability"]
        )

    def test_hardened_twin_scores_lower(self, engine):
        engine.create_threat_model("exposed", {"attack_types": ["phishing"]})
        engine.create_threat_model("hardened", {
            "attack_types": ["phishing"], "controls_effectiveness": 0.9,
        })

        assert (
            engine.evaluate_risk("hardened")["risk_score"]
            < engine.evaluate_risk("exposed")["risk_score"]
        )

    def test_vulnerability_count_comes_from_the_model(self, engine):
        model_id = engine.create_threat_model("t1", {"attack_types": ["phishing"]})
        engine.models[model_id]["vulnerabilities"] = [{"id": "v1"}, {"id": "v2"}]

        assert engine.evaluate_risk("t1")["vulnerability_count"] == 2
