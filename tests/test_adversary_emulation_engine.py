"""Unit tests for the adversary emulation subsystem.

Covers ``src.adversary_emulation``: ``CampaignGenerator``,
``SimulationEngine``, ``AdversaryStore`` and ``RedTeamFramework``.
"""

from __future__ import annotations

import pytest

from src.adversary_emulation.campaign_generator import CampaignGenerator
from src.adversary_emulation.models import AdversaryProfile, AttackCampaign
from src.adversary_emulation.red_team_framework import RedTeamFramework
from src.adversary_emulation.simulation_engine import SimulationEngine
from src.adversary_emulation.store import AdversaryStore


@pytest.fixture
def profile() -> AdversaryProfile:
    return AdversaryProfile(
        id="prof-1",
        name="APT-42",
        tactics=["Reconnaissance", "Initial Access", "Lateral Movement"],
        techniques=["T1595", "T1566", "T1021"],
    )


@pytest.fixture
def generator() -> CampaignGenerator:
    return CampaignGenerator()


@pytest.fixture
def engine() -> SimulationEngine:
    return SimulationEngine()


@pytest.fixture
def store() -> AdversaryStore:
    return AdversaryStore()


# ---------------------------------------------------------------------------
# CampaignGenerator
# ---------------------------------------------------------------------------


class TestCampaignGenerator:
    def test_generates_one_step_per_tactic(self, generator, profile):
        campaign = generator.generate(profile, target="finance-db")

        assert isinstance(campaign, AttackCampaign)
        assert campaign.profile_id == "prof-1"
        assert campaign.target_entity == "finance-db"
        assert campaign.status == "PENDING"
        assert len(campaign.steps) == 3

    def test_steps_are_simulated_pending(self, generator, profile):
        campaign = generator.generate(profile, target="t")

        for step, tactic in zip(campaign.steps, profile.tactics):
            assert step.tactic == tactic
            assert step.technique == "Simulated"
            assert step.status == "PENDING"

    def test_empty_tactics_produce_empty_campaign(self, generator):
        empty = AdversaryProfile(id="p", name="quiet", tactics=[], techniques=[])

        campaign = generator.generate(empty, target="t")

        assert campaign.steps == []


# ---------------------------------------------------------------------------
# SimulationEngine
# ---------------------------------------------------------------------------


class TestSimulationEngine:
    def test_execute_marks_steps_executed(self, engine, generator, profile):
        campaign = generator.generate(profile, target="t")

        result = engine.execute(campaign)

        assert all(s.status == "EXECUTED" for s in campaign.steps)

    def test_execute_success_rate_for_nonempty(self, engine, generator, profile):
        result = engine.execute(generator.generate(profile, target="t"))

        assert result.success_rate == 1.0
        assert result.detected_steps == 3
        assert result.total_steps == 3
        assert result.campaign_id is not None

    def test_execute_empty_campaign_zero_success(self, engine):
        campaign = AttackCampaign(id="c1", profile_id="p", target_entity="t", steps=[])

        result = engine.execute(campaign)

        assert result.success_rate == 0.0
        assert result.detected_steps == 0
        assert result.total_steps == 0

    def test_result_timestamp_set(self, engine, generator, profile):
        result = engine.execute(generator.generate(profile, target="t"))
        assert result.timestamp is not None


# ---------------------------------------------------------------------------
# AdversaryStore
# ---------------------------------------------------------------------------


class TestAdversaryStore:
    def test_profile_save_and_get_round_trip(self, store, profile):
        store.save_profile(profile)

        assert store.get_profile("prof-1") is profile
        assert store.get_profile("missing") is None

    def test_campaign_persisted_by_id(self, store, generator, profile):
        campaign = generator.generate(profile, target="t")

        store.save_campaign(campaign)

        assert store.campaigns[campaign.id] is campaign

    def test_result_persisted_by_campaign_id(self, store, engine, generator, profile):
        campaign = generator.generate(profile, target="t")
        result = engine.execute(campaign)

        store.save_result(result)

        assert store.results[result.campaign_id] is result


# ---------------------------------------------------------------------------
# RedTeamFramework
# ---------------------------------------------------------------------------


class TestRedTeamFramework:
    def test_evaluate_tactic_returns_covered(self):
        framework = RedTeamFramework()

        assert framework.evaluate_tactic("Initial Access") is True
        assert framework.evaluate_tactic("Unknown Tactic") is True
