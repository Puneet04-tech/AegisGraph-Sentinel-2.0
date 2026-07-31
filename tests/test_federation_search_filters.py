"""
Regression tests for federated search query filters.

The federation path (FederatedSearchEngine._search_federation ->
FederationEngine.request_intelligence -> _matches_query) silently returned
zero results because _matches_query compared the entity_type value against the
list sent by the caller with `!=` (always mismatching), and the caller passed
None sentinels for empty filters, which made _matches_query raise a TypeError
for empty threat_levels.
"""

from datetime import datetime, timezone

import pytest

from src.global_intelligence.store import GlobalIntelligenceStore
from src.global_intelligence.models import (
    EntityType,
    FederatedEntity,
    FederationPartner,
    FederationStatus,
    ThreatLevel,
)
from src.global_intelligence.federation_engine import FederationEngine
from src.global_intelligence.federated_search import (
    FederatedSearchEngine,
    SearchQuery,
)

NOW = datetime.now(timezone.utc)


def make_entity(
    entity_id,
    entity_type=EntityType.ACCOUNT,
    threat_level=ThreatLevel.HIGH,
    partner_id="partner-1",
    attributes=None,
):
    return FederatedEntity(
        entity_id=entity_id,
        entity_type=entity_type,
        federation_id="fed-1",
        partner_id=partner_id,
        external_id=f"ext-{entity_id}",
        attributes=attributes or {"iban": f"DE{entity_id}"},
        risk_score=0.8,
        threat_level=threat_level,
        first_seen=NOW,
        last_updated=NOW,
    )


def make_store():
    """Fresh store with a partner and some entities."""
    store = GlobalIntelligenceStore()
    store.store_partner(
        FederationPartner(
            partner_id="partner-1",
            organization_name="Partner Bank",
            organization_type="bank",
            status=FederationStatus.ACTIVE,
            trust_level=80,
            api_endpoint="https://api.example.com",
            api_key_hash=None,
            joined_at=NOW,
            last_sync=NOW,
        )
    )
    return store


def make_engine(store):
    return FederatedSearchEngine(
        store=store,
        federation_engine=FederationEngine(store=store),
    )


def make_query(**overrides):
    defaults = dict(
        query_id="q-1",
        query_text="",
        entity_types=[],
        threat_levels=[],
        date_range_start=None,
        date_range_end=None,
        max_results_per_source=20,
        fuzzy_match=True,
    )
    defaults.update(overrides)
    return SearchQuery(**defaults)


class TestMatchesQueryEntityType:
    """_matches_query must accept entity_type as list or scalar."""

    def setup_method(self):
        self.store = make_store()
        self.engine = FederationEngine(store=self.store)
        self.entity = make_entity("e1")

    def test_list_of_types_matches(self):
        query = {"entity_type": ["account", "device"]}
        assert self.engine._matches_query(self.entity, query) is True

    def test_list_excludes_non_matching_type(self):
        query = {"entity_type": ["device", "email"]}
        assert self.engine._matches_query(self.entity, query) is False

    def test_scalar_type_matches(self):
        query = {"entity_type": "account"}
        assert self.engine._matches_query(self.entity, query) is True

    def test_scalar_type_excludes(self):
        query = {"entity_type": "device"}
        assert self.engine._matches_query(self.entity, query) is False

    def test_tuple_supported(self):
        query = {"entity_type": ("account", "card")}
        assert self.engine._matches_query(self.entity, query) is True

    def test_set_supported(self):
        query = {"entity_type": {"email", "account"}}
        assert self.engine._matches_query(self.entity, query) is True

    def test_none_type_is_no_filter(self):
        query = {"entity_type": None}
        assert self.engine._matches_query(self.entity, query) is True

    def test_empty_list_is_no_filter(self):
        query = {"entity_type": []}
        assert self.engine._matches_query(self.entity, query) is True


class TestMatchesQueryThreatLevels:
    """_matches_query must handle threat_levels None/empty/list/scalar."""

    def setup_method(self):
        self.store = make_store()
        self.engine = FederationEngine(store=self.store)
        self.entity = make_entity("e1")

    def test_list_of_levels_matches(self):
        query = {"threat_levels": ["high", "critical"]}
        assert self.engine._matches_query(self.entity, query) is True

    def test_list_excludes_non_matching_level(self):
        query = {"threat_levels": ["low", "medium"]}
        assert self.engine._matches_query(self.entity, query) is False

    def test_scalar_level_matches(self):
        query = {"threat_levels": "high"}
        assert self.engine._matches_query(self.entity, query) is True

    def test_none_levels_is_no_filter(self):
        query = {"threat_levels": None}
        assert self.engine._matches_query(self.entity, query) is True

    def test_empty_list_is_no_filter(self):
        query = {"threat_levels": []}
        assert self.engine._matches_query(self.entity, query) is True

    def test_empty_levels_no_typeerror(self):
        query = {"threat_levels": []}
        assert self.engine._matches_query(self.entity, query) is not None


class TestMatchesQueryAttributes:
    """Attribute filters keep working."""

    def setup_method(self):
        self.store = make_store()
        self.engine = FederationEngine(store=self.store)
        self.entity = make_entity("e1", attributes={"iban": "DE0001", "country": "DE"})

    def test_attribute_match(self):
        query = {"attributes": {"iban": "DE0001"}}
        assert self.engine._matches_query(self.entity, query) is True

    def test_attribute_mismatch(self):
        query = {"attributes": {"iban": "US0001"}}
        assert self.engine._matches_query(self.entity, query) is False


class TestRequestIntelligence:
    """request_intelligence must return matching partner entities."""

    def setup_method(self):
        self.store = make_store()
        self.engine = FederationEngine(store=self.store)

    def test_returns_matching_entity(self):
        self.store.store_entity(make_entity("e1"))
        results = self.engine.request_intelligence(
            "self",
            {"entity_type": ["account"], "threat_levels": ["high"], "max_results": 20},
        )
        assert [r.entity_id for r in results] == ["e1"]

    def test_excludes_wrong_type(self):
        self.store.store_entity(make_entity("e1", entity_type=EntityType.ACCOUNT))
        self.store.store_entity(make_entity("e2", entity_type=EntityType.DEVICE))
        results = self.engine.request_intelligence(
            "self",
            {"entity_type": ["account"], "max_results": 20},
        )
        assert [r.entity_id for r in results] == ["e1"]

    def test_excludes_wrong_threat_level(self):
        self.store.store_entity(make_entity("e1", threat_level=ThreatLevel.HIGH))
        self.store.store_entity(make_entity("e2", threat_level=ThreatLevel.LOW))
        results = self.engine.request_intelligence(
            "self",
            {"threat_levels": ["high"], "max_results": 20},
        )
        assert [r.entity_id for r in results] == ["e1"]

    def test_empty_filters_return_all(self):
        self.store.store_entity(make_entity("e1"))
        self.store.store_entity(make_entity("e2", entity_type=EntityType.DEVICE))
        results = self.engine.request_intelligence("self", {"max_results": 20})
        assert sorted(r.entity_id for r in results) == ["e1", "e2"]

    def test_empty_filters_with_none_sentinels_do_not_crash(self):
        self.store.store_entity(make_entity("e1"))
        results = self.engine.request_intelligence(
            "self",
            {"entity_type": None, "threat_levels": None, "max_results": 20},
        )
        assert [r.entity_id for r in results] == ["e1"]

    def test_anonymizes_foreign_entities(self):
        self.store.store_entity(make_entity("e1"))
        results = self.engine.request_intelligence(
            "self",
            {"entity_type": ["account"], "max_results": 20},
        )
        assert len(results) == 1
        assert results[0].is_anonymized is True
        assert results[0].external_id == "REDACTED"

    def test_max_results_respected(self):
        for i in range(5):
            self.store.store_entity(make_entity(f"e{i}"))
        results = self.engine.request_intelligence("self", {"max_results": 3})
        assert len(results) == 3


class TestFederatedSearchEngine:
    """End-to-end federation search must surface partner entities."""

    def setup_method(self):
        self.store = make_store()
        self.search = make_engine(self.store)

    def test_federation_only_search_returns_partner_entity(self):
        self.store.store_entity(make_entity("e1"))
        query = make_query(
            query_text="",
            entity_types=[EntityType.ACCOUNT],
            threat_levels=[ThreatLevel.HIGH],
            include_internal=False,
            include_federation=True,
        )
        results = self.search.search(query)
        assert len(results) == 1
        assert results[0].entity.entity_id == "e1"

    def test_federation_search_with_empty_filters_does_not_crash(self):
        self.store.store_entity(make_entity("e1"))
        query = make_query(
            query_text="",
            entity_types=[],
            threat_levels=[],
            include_internal=False,
            include_federation=True,
        )
        results = self.search.search(query)
        assert [r.entity.entity_id for r in results] == ["e1"]

    def test_federation_search_excludes_wrong_type(self):
        self.store.store_entity(make_entity("e1", entity_type=EntityType.ACCOUNT))
        self.store.store_entity(make_entity("e2", entity_type=EntityType.DEVICE))
        query = make_query(
            entity_types=[EntityType.ACCOUNT],
            include_internal=False,
            include_federation=True,
        )
        results = self.search.search(query)
        assert [r.entity.entity_id for r in results] == ["e1"]

    def test_federation_search_excludes_wrong_threat_level(self):
        self.store.store_entity(make_entity("e1", threat_level=ThreatLevel.HIGH))
        self.store.store_entity(make_entity("e2", threat_level=ThreatLevel.LOW))
        query = make_query(
            threat_levels=[ThreatLevel.HIGH],
            include_internal=False,
            include_federation=True,
        )
        results = self.search.search(query)
        assert [r.entity.entity_id for r in results] == ["e1"]

    def test_federation_results_are_ranked(self):
        for i in range(5):
            self.store.store_entity(make_entity(f"e{i}"))
        query = make_query(
            entity_types=[EntityType.ACCOUNT],
            include_internal=False,
            include_federation=True,
            max_results_per_source=2,
        )
        results = self.search.search(query)
        assert len(results) <= 6
        assert all(r.relevance_score == 0.7 for r in results)

    def test_full_search_deduplicates_single_entity(self):
        self.store.store_entity(make_entity("e1"))
        query = make_query(
            query_text="e1",
            entity_types=[EntityType.ACCOUNT],
            threat_levels=[ThreatLevel.HIGH],
        )
        results = self.search.search(query)
        assert len(results) == 1

    def test_full_search_keeps_higher_score(self):
        self.store.store_entity(
            make_entity(
                "e1",
                attributes={"iban": "DEe1", "email": "e1@bank.com", "ref": "e1"},
            )
        )
        query = make_query(
            query_text="e1",
            entity_types=[EntityType.ACCOUNT],
            threat_levels=[ThreatLevel.HIGH],
        )
        results = self.search.search(query)
        assert len(results) == 1
        assert results[0].relevance_score == 1.0
        assert results[0].source.value == "internal"

    def test_internal_only_skips_federation(self):
        self.store.store_entity(make_entity("e1"))
        query = make_query(
            query_text="",
            entity_types=[EntityType.ACCOUNT],
            threat_levels=[ThreatLevel.HIGH],
            include_internal=True,
            include_federation=False,
        )
        results = self.search.search(query)
        assert all(r.source.value == "internal" for r in results)

    def test_federation_result_source_tag(self):
        self.store.store_entity(make_entity("e1"))
        query = make_query(
            entity_types=[EntityType.ACCOUNT],
            threat_levels=[ThreatLevel.HIGH],
            include_internal=False,
            include_federation=True,
        )
        results = self.search.search(query)
        assert all(r.source.value == "federation" for r in results)
        assert all(r.partner_id == "partner-1" for r in results)

    def test_search_by_example_ignores_same_entity(self):
        example = make_entity("e1")
        self.store.store_entity(example)
        self.store.store_entity(make_entity("e2"))
        results = self.search.search_by_example(example)
        assert all(r.entity.entity_id != "e1" for r in results)
