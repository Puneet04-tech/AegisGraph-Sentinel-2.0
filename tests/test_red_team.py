"""Unit tests for the AI red team & adversarial fraud simulator.

Covers ``src.red_team.simulator.AdversarialSimulator`` including attack
simulation, perturbation, campaign execution, vulnerability identification,
recommendations, and the module-level singleton.
"""

from __future__ import annotations

import random

import pytest

from src.red_team.models import (
    AdversarialSample,
    AttackResult,
    AttackType,
    CampaignResult,
)
from src.red_team.simulator import (
    AdversarialSimulator,
    get_adversarial_simulator,
)


@pytest.fixture
def simulator() -> AdversarialSimulator:
    random.seed(42)
    return AdversarialSimulator()


# ---------------------------------------------------------------------------
# simulate_attack
# ---------------------------------------------------------------------------


class TestSimulateAttack:
    def test_result_preserves_attack_type_and_target(self, simulator):
        result = simulator.simulate_attack(
            AttackType.EVASION,
            "htgnn-v1",
            {"amount": 1000.0, "velocity": 3.0},
        )

        assert isinstance(result, AttackResult)
        assert result.attack_type == AttackType.EVASION
        assert result.target_model == "htgnn-v1"

    def test_detection_avoided_mirrors_success(self, simulator):
        result = simulator.simulate_attack(
            AttackType.DATA_POISONING,
            "htgnn-v1",
            {"amount": 1000.0},
        )

        assert result.detection_avoided == result.success

    def test_evasion_rate_within_bounds(self, simulator):
        for _ in range(25):
            result = simulator.simulate_attack(
                AttackType.EVASION, "htgnn-v1", {"f": 1.0}
            )
            assert 0.1 <= result.evasion_rate <= 0.9

    def test_attack_is_recorded_in_history(self, simulator):
        assert len(simulator._attack_history) == 0

        simulator.simulate_attack(AttackType.MODEL_INVERSION, "htgnn-v1", {"f": 1.0})

        assert len(simulator._attack_history) == 1
        assert simulator._attack_history[0].attack_type == AttackType.MODEL_INVERSION


# ---------------------------------------------------------------------------
# _add_adversarial_perturbation
# ---------------------------------------------------------------------------


class TestAdversarialPerturbation:
    def test_preserves_feature_keys(self, simulator):
        features = {"amount": 1000.0, "velocity": 3.0, "risk": 0.5}
        perturbed = simulator._add_adversarial_perturbation(features)

        assert set(perturbed.keys()) == set(features.keys())

    def test_perturbation_is_bounded_relative(self, simulator):
        features = {"amount": 1000.0}
        perturbed = simulator._add_adversarial_perturbation(features)

        delta = abs(perturbed["amount"] - features["amount"])
        assert delta <= 0.1 * features["amount"]

    def test_perturbation_does_not_mutate_input(self, simulator):
        features = {"amount": 1000.0, "velocity": 3.0}
        snapshot = dict(features)

        simulator._add_adversarial_perturbation(features)

        assert features == snapshot

    def test_negative_feature_values_stay_valid(self, simulator):
        features = {"delta": -100.0}
        perturbed = simulator._add_adversarial_perturbation(features)

        assert abs(perturbed["delta"] - features["delta"]) <= 0.1 * abs(
            features["delta"]
        )

    def test_zero_feature_is_perturbed_to_zero(self, simulator):
        features = {"constant": 0.0}
        perturbed = simulator._add_adversarial_perturbation(features)

        assert perturbed["constant"] == 0.0


# ---------------------------------------------------------------------------
# run_campaign
# ---------------------------------------------------------------------------


class TestRunCampaign:
    def test_campaign_runs_requested_number_of_attacks(self, simulator):
        campaign = simulator.run_campaign(
            "Q1 Red Team", "htgnn-v1", num_attacks=12
        )

        assert isinstance(campaign, CampaignResult)
        assert campaign.campaign_name == "Q1 Red Team"
        assert len(campaign.attack_results) == 12

    def test_overall_success_rate_matches_results(self, simulator):
        campaign = simulator.run_campaign("Campaign A", "htgnn-v1", num_attacks=20)

        successes = sum(1 for r in campaign.attack_results if r.success)
        expected = successes / len(campaign.attack_results)
        assert campaign.overall_success_rate == pytest.approx(expected)

    def test_campaign_recorded_in_history(self, simulator):
        assert len(simulator._campaign_history) == 0

        simulator.run_campaign("Campaign B", "htgnn-v1", num_attacks=3)

        assert len(simulator._campaign_history) == 1
        assert simulator._campaign_history[0].campaign_name == "Campaign B"

    def test_zero_attacks_produces_empty_results(self, simulator):
        campaign = simulator.run_campaign("Empty", "htgnn-v1", num_attacks=0)

        assert campaign.attack_results == []
        assert campaign.overall_success_rate == 0.0

    def test_get_campaign_history_returns_recorded_campaigns(self, simulator):
        simulator.run_campaign("Campaign C", "htgnn-v1", num_attacks=2)

        history = simulator.get_campaign_history()
        assert len(history) == 1
        assert history[0].campaign_name == "Campaign C"


# ---------------------------------------------------------------------------
# Vulnerability identification
# ---------------------------------------------------------------------------


class TestIdentifyVulnerabilities:
    @staticmethod
    def _result(attack_type: AttackType, success: bool) -> AttackResult:
        return AttackResult(
            attack_type=attack_type,
            target_model="htgnn-v1",
            success=success,
            evasion_rate=0.7 if success else 0.2,
            detection_avoided=success,
        )

    def test_evasion_success_flags_vulnerability(self, simulator):
        results = [self._result(AttackType.EVASION, True)]

        vulnerabilities = simulator._identify_vulnerabilities(results)

        assert "Model vulnerable to evasion attacks" in vulnerabilities

    def test_perturbation_success_flags_vulnerability(self, simulator):
        results = [self._result(AttackType.ADVERSARIAL_PERTURBATION, True)]

        vulnerabilities = simulator._identify_vulnerabilities(results)

        assert "Model vulnerable to adversarial perturbations" in vulnerabilities

    def test_failed_attacks_produce_no_vulnerabilities(self, simulator):
        results = [
            self._result(AttackType.EVASION, False),
            self._result(AttackType.ADVERSARIAL_PERTURBATION, False),
        ]

        assert simulator._identify_vulnerabilities(results) == []

    def test_multiple_vulnerabilities_accumulate(self, simulator):
        results = [
            self._result(AttackType.EVASION, True),
            self._result(AttackType.ADVERSARIAL_PERTURBATION, True),
        ]

        vulnerabilities = simulator._identify_vulnerabilities(results)

        assert len(vulnerabilities) == 2


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


class TestRecommendations:
    def test_high_success_rate_recommends_hardening(self, simulator):
        recommendations = simulator._generate_recommendations(0.8)

        assert "Consider adversarial training" in recommendations
        assert "Implement input validation" in recommendations
        assert "Enhance feature preprocessing" in recommendations

    def test_low_success_rate_recommends_monitoring(self, simulator):
        recommendations = simulator._generate_recommendations(0.2)

        assert recommendations == ["Continue monitoring for new attack vectors"]

    def test_boundary_rate_uses_default_recommendation(self, simulator):
        recommendations = simulator._generate_recommendations(0.5)

        assert recommendations == ["Continue monitoring for new attack vectors"]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_adversarial_simulator_returns_same_instance(self):
        first = get_adversarial_simulator()
        second = get_adversarial_simulator()

        assert first is second
        assert isinstance(first, AdversarialSimulator)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestRedTeamModels:
    def test_adversarial_sample_round_trip(self):
        sample = AdversarialSample(
            original_features={"a": 1.0},
            perturbed_features={"a": 1.05},
            perturbation_magnitude=0.05,
            attack_type=AttackType.EVASION,
            evaded_detection=True,
        )

        assert sample.perturbation_magnitude == 0.05
        assert sample.attack_type == AttackType.EVASION
        assert sample.evaded_detection is True
        assert sample.sample_id

    def test_campaign_result_defaults(self):
        campaign = CampaignResult(
            campaign_name="Default", overall_success_rate=0.0
        )

        assert campaign.attack_results == []
        assert campaign.vulnerabilities_found == []
        assert campaign.recommendations == []
