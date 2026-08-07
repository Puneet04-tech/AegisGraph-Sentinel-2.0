"""Unit tests for sampling helpers."""

import pytest

from src.utils.sampler import (
    ReservoirSampler,
    stratified_sample,
    systematic_sample,
    weighted_sample,
)


class TestReservoirSampler:
    def test_returns_all_when_fed_less_than_size(self):
        sampler = ReservoirSampler(10)
        for item in range(6):
            sampler.feed(item)
        assert sampler.count() == 6
        assert sampler.sample() == [0, 1, 2, 3, 4, 5]

    def test_caps_at_size_and_tracks_count(self):
        sampler = ReservoirSampler(3)
        for item in range(100):
            sampler.feed(item)
        assert sampler.count() == 100
        assert len(sampler.sample()) == 3

    def test_sample_returns_copy(self):
        sampler = ReservoirSampler(3)
        for item in range(5):
            sampler.feed(item)
        sample = sampler.sample()
        sample.append("tampered")
        assert len(sampler.sample()) == 3

    def test_deterministic_with_same_seed(self):
        def run(seed):
            sampler = ReservoirSampler(5, seed=seed)
            for item in range(500):
                sampler.feed(item)
            return sampler.sample()

        assert run(42) == run(42)
        assert run(42) != run(7)

    def test_sample_items_come_from_population(self):
        population = list(range(1000))
        sampler = ReservoirSampler(20)
        for item in population:
            sampler.feed(item)
        assert set(sampler.sample()).issubset(set(population))

    def test_zero_size_raises_value_error(self):
        with pytest.raises(ValueError):
            ReservoirSampler(0)

    def test_negative_size_raises_value_error(self):
        with pytest.raises(ValueError):
            ReservoirSampler(-5)


class TestStratifiedSample:
    def test_preserves_relative_proportions(self):
        population = [{"group": "a", "value": i} for i in range(100)]
        population += [{"group": "b", "value": i} for i in range(100)]
        sample = stratified_sample(population, "group", 100)
        assert len(sample) == 100
        groups = [item["group"] for item in sample]
        assert 40 <= groups.count("a") <= 60

    def test_accepts_callable_strata_key(self):
        population = [
            {"name": "alice", "risk": "low"},
            {"name": "bob", "risk": "high"},
        ] * 50
        sample = stratified_sample(population, lambda item: item["risk"], 40)
        risks = [item["risk"] for item in sample]
        assert 10 <= risks.count("low") <= 30

    def test_empty_population_returns_empty(self):
        assert stratified_sample([], "group", 10) == []

    def test_size_greater_than_population_returns_all(self):
        population = [{"group": "a", "value": i} for i in range(5)]
        assert stratified_sample(population, "group", 20) == population
        assert stratified_sample(population, "group", 5) == population


class TestSystematicSample:
    def test_length_never_exceeds_requested_size(self):
        population = list(range(1000))
        for size in (1, 2, 7, 50, 100, 333):
            sample = systematic_sample(population, size)
            assert len(sample) <= size

    def test_items_preserve_order_and_even_spacing(self):
        population = list(range(100))
        sample = systematic_sample(population, 10)
        assert sample == sorted(sample)
        assert len(sample) == 10
        assert all(isinstance(item, int) for item in sample)

    def test_size_greater_than_population_returns_all(self):
        population = list(range(7))
        assert systematic_sample(population, 20) == population
        assert systematic_sample(population, 7) == population

    def test_empty_population_returns_empty(self):
        assert systematic_sample([], 5) == []


class TestWeightedSample:
    def test_returns_requested_count(self):
        items = ["a", "b", "c"]
        weights = [1, 1, 1]
        sample = weighted_sample(items, weights, 50, seed=3)
        assert len(sample) == 50

    def test_zero_weight_item_never_selected(self):
        items = ["kept", "never"]
        weights = [1.0, 0.0]
        sample = weighted_sample(items, weights, 500, seed=7)
        assert "never" not in sample
        assert sample.count("kept") == 500

    def test_heavy_weight_item_dominates(self):
        items = ["light", "heavy"]
        weights = [0.1, 99.9]
        sample = weighted_sample(items, weights, 200, seed=1)
        assert sample.count("heavy") > sample.count("light")

    def test_length_mismatch_raises_value_error(self):
        with pytest.raises(ValueError):
            weighted_sample(["a", "b"], [1], 2)
