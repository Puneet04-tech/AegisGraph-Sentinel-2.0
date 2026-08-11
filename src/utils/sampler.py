"""Memory-bounded and proportional sampling helpers.

:class:`ReservoirSampler` keeps a bounded random sample of an unbounded
stream without storing the whole stream; the free functions draw
proportional (stratified), evenly spaced (systematic), and weight-biased
samples from finite populations.
"""

import random
from typing import Any, Callable, List, Optional


class ReservoirSampler:
    """Algorithm R reservoir sampler for a stream of unknown length."""

    def __init__(self, size: int, seed: Optional[int] = None):
        if size <= 0:
            raise ValueError("size must be positive")
        self._size = size
        self._rng = random.Random(seed)
        self._items: List[Any] = []
        self._count = 0

    def feed(self, item: Any) -> None:
        self._count += 1
        if len(self._items) < self._size:
            self._items.append(item)
            return
        slot = self._rng.randint(0, self._count - 1)
        if slot < self._size:
            self._items[slot] = item

    def sample(self) -> List[Any]:
        return list(self._items)

    def count(self) -> int:
        return self._count


def _key_of(strata_key: Any) -> Callable[[dict], Any]:
    if callable(strata_key):
        return strata_key
    return lambda item: item[strata_key]


def stratified_sample(population: List[dict], strata_key: Any, size: int) -> List[dict]:
    if not population:
        return []
    if size >= len(population):
        return list(population)
    key_fn = _key_of(strata_key)
    buckets: dict = {}
    for item in population:
        buckets.setdefault(key_fn(item), []).append(item)

    total = len(population)
    groups = list(buckets.values())
    quotas = [len(group) / total * size for group in groups]
    counts = [int(quota) for quota in quotas]
    remainder_slots = size - sum(counts)
    by_remainder = sorted(
        enumerate(quota - int(quota) for quota in quotas),
        key=lambda pair: pair[1],
        reverse=True,
    )
    for index, _ in by_remainder[:remainder_slots]:
        counts[index] += 1

    rng = random.Random()
    result: List[dict] = []
    for group, count in zip(groups, counts):
        result.extend(rng.sample(group, count))
    return result


def systematic_sample(population: list, size: int) -> list:
    if size >= len(population):
        return list(population)
    if size <= 0:
        return []
    step = len(population) // size
    rng = random.Random()
    start = rng.randint(0, step - 1)
    return [population[index] for index in range(start, len(population), step)][:size]


def weighted_sample(
    items: list,
    weights: list,
    size: int,
    seed: Optional[int] = None,
) -> list:
    if len(items) != len(weights):
        raise ValueError("items and weights must have the same length")
    if size <= 0:
        return []
    rng = random.Random(seed)
    return rng.choices(items, weights=weights, k=size)
