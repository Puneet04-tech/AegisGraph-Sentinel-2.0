"""All four risk components must resolve on a constructed scorer.

PRs #3201, #3202 and #3203 each added an import and constructor wiring to the
same region of `production_scorer.py`. Each was verified against a base that
did not contain the other two, so none of them could catch the conflict — when
they merged, only the `device_risk` wiring survived and two hot-path components
started raising:

    _compute_temporal_risk  -> NameError: name 'hour_in_zone' is not defined
    _compute_velocity_risk  -> AttributeError: no attribute 'velocity_calculator'

Nothing exercised the constructor with all components present, so the loss was
invisible. This module is that check.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import torch.nn as nn

from src.inference.production_scorer import ProductionRiskScorer

# The four keys `score_transaction` assembles into `breakdown`.
COMPONENTS = ("graph_risk", "velocity_risk", "temporal_risk", "device_risk")


class _NullModel(nn.Module):
    def forward(self, _inputs):  # pragma: no cover - never called here
        raise NotImplementedError


@pytest.fixture
def scorer() -> ProductionRiskScorer:
    instance = ProductionRiskScorer(
        model=_NullModel(), graph_constructor=object(), model_version="test"
    )
    yield instance
    instance.close()


def transaction() -> dict:
    return {
        "transaction_id": "TXN1",
        "source_account": "ACC1",
        "target_account": "ACC2",
        "amount": 1000.0,
        "timestamp": datetime(2026, 5, 1, 3, 0, tzinfo=timezone.utc).isoformat(),
        "source_device_id": "DEV1",
    }


class TestConstructorWiring:
    """Each attribute a component depends on must exist after construction."""

    @pytest.mark.parametrize(
        "attribute",
        ["velocity_calculator", "device_calculator", "temporal_reference_zone"],
    )
    def test_component_dependency_is_wired(self, scorer, attribute):
        assert getattr(scorer, attribute, None) is not None, (
            f"{attribute} is missing: a merge has dropped its constructor wiring"
        )

    def test_the_temporal_reference_zone_defaults_to_utc(self, scorer):
        assert scorer.temporal_reference_zone == timezone.utc

    def test_calculators_are_injectable(self):
        from src.inference.device_risk import DeviceRiskCalculator
        from src.inference.velocity_risk import VelocityRiskCalculator

        velocity = VelocityRiskCalculator()
        device = DeviceRiskCalculator()
        instance = ProductionRiskScorer(
            model=_NullModel(),
            graph_constructor=object(),
            velocity_calculator=velocity,
            device_calculator=device,
        )
        try:
            assert instance.velocity_calculator is velocity
            assert instance.device_calculator is device
        finally:
            instance.close()


class TestComponentsResolve:
    """Each component must return a usable score rather than raising."""

    def test_velocity_risk_resolves(self, scorer):
        result = scorer._compute_velocity_risk(transaction())
        assert isinstance(result, float) and 0.0 <= result <= 1.0

    def test_temporal_risk_resolves(self, scorer):
        result = scorer._compute_temporal_risk(transaction())
        assert isinstance(result, float) and 0.0 <= result <= 1.0

    def test_device_risk_resolves(self, scorer):
        result = scorer._compute_device_risk(transaction())
        assert isinstance(result, float) and 0.0 <= result <= 1.0

    def test_all_components_resolve_together(self, scorer):
        """The specific failure: three worked in isolation, two broke merged."""
        payload = transaction()
        breakdown = {
            "velocity_risk": scorer._compute_velocity_risk(payload),
            "temporal_risk": scorer._compute_temporal_risk(payload),
            "device_risk": scorer._compute_device_risk(payload),
        }
        assert all(0.0 <= value <= 1.0 for value in breakdown.values())
        assert set(breakdown) < set(COMPONENTS)

    def test_components_still_resolve_for_a_sparse_transaction(self, scorer):
        """Missing optional fields must degrade, not raise."""
        sparse = {"transaction_id": "T", "source_account": "ACC1", "amount": 1.0}
        assert 0.0 <= scorer._compute_velocity_risk(sparse) <= 1.0
        assert 0.0 <= scorer._compute_temporal_risk(sparse) <= 1.0
        assert 0.0 <= scorer._compute_device_risk(sparse) <= 1.0


class TestModuleImports:
    """Guard the specific names a merge dropped."""

    @pytest.mark.parametrize(
        "name", ["hour_in_zone", "get_velocity_calculator", "get_device_calculator"]
    )
    def test_name_is_bound_in_the_scorer_module(self, name):
        import src.inference.production_scorer as module

        assert hasattr(module, name), (
            f"{name} is not imported: a merge has dropped it from the import block"
        )
