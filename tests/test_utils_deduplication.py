"""Unit tests for the record deduplication utilities."""

import pytest

from src.utils.deduplication import (
    exact_dedupe,
    fuzzy_dedupe,
    jaccard_similarity,
    merge_group,
    normalize_value,
)


class TestExactDedupe:
    def test_removes_exact_duplicates_preserving_order(self):
        records = [
            {"account_id": "a1", "name": "Alice"},
            {"account_id": "b2", "name": "Bob"},
            {"account_id": "a1", "name": "Alice"},
        ]
        assert exact_dedupe(records) == [
            {"account_id": "a1", "name": "Alice"},
            {"account_id": "b2", "name": "Bob"},
        ]

    def test_no_duplicates_returns_same_records(self):
        records = [{"id": 1}, {"id": 2}]
        assert exact_dedupe(records) == records

    def test_dedupe_on_subset_of_keys(self):
        records = [
            {"account_id": "a1", "name": "Alice", "note": "first"},
            {"account_id": "a1", "name": "Alicia", "note": "second"},
            {"account_id": "a1", "name": "Alice", "note": "third"},
        ]
        deduped = exact_dedupe(records, keys=["account_id"])
        assert len(deduped) == 1
        assert deduped[0] == records[0]

    def test_subset_of_keys_keeps_other_fields(self):
        records = [
            {"id": 1, "risk": "high"},
            {"id": 2, "risk": "high"},
            {"id": 3, "risk": "low"},
        ]
        deduped = exact_dedupe(records, keys=["risk"])
        assert len(deduped) == 2
        assert deduped[0] == {"id": 1, "risk": "high"}
        assert deduped[1] == {"id": 3, "risk": "low"}

    def test_key_order_does_not_matter(self):
        records = [
            {"a": 1, "b": 2},
            {"b": 2, "a": 1},
        ]
        assert exact_dedupe(records) == [{"a": 1, "b": 2}]

    def test_empty_records_list(self):
        assert exact_dedupe([]) == []


class TestNormalizeValue:
    def test_lowercases_strings(self):
        assert normalize_value("Alice") == "alice"

    def test_strips_outer_whitespace(self):
        assert normalize_value("  alice  ") == "alice"

    def test_removes_internal_spaces(self):
        assert normalize_value("John  Doe") == "johndoe"

    def test_none_becomes_empty_string(self):
        assert normalize_value(None) == ""

    def test_numbers_converted_to_strings(self):
        assert normalize_value(12345) == "12345"
        assert normalize_value(12345.5) == "12345.5"

    def test_empty_string_stays_empty(self):
        assert normalize_value("") == ""


class TestJaccardSimilarity:
    def test_identical_strings_are_one(self):
        assert jaccard_similarity("alice smith", "alice smith") == 1.0

    def test_disjoint_strings_are_zero(self):
        assert jaccard_similarity("alice smith", "bob jones") == 0.0

    def test_partial_overlap_between_zero_and_one(self):
        similarity = jaccard_similarity("alice smith", "alice jones")
        assert 0.0 < similarity < 1.0
        assert similarity == pytest.approx(1 / 3)

    def test_both_empty_are_one(self):
        assert jaccard_similarity("", "") == 1.0

    def test_empty_versus_non_empty_is_zero(self):
        assert jaccard_similarity("", "alice") == 0.0

    def test_whitespace_insensitive_tokens(self):
        assert jaccard_similarity("alice  smith", "alice smith") == 1.0


class TestFuzzyDedupe:
    def test_groups_near_identical_records(self):
        records = [
            {"name": "Alice Smith", "city": "NYC"},
            {"name": "Alice  Smith", "city": "NYC"},
            {"name": "Bob Jones", "city": "LA"},
        ]
        groups = fuzzy_dedupe(records, keys=["name"], threshold=0.8)
        assert len(groups) == 2
        alice_group = groups[0]
        assert alice_group["group"] == 0
        assert len(alice_group["records"]) == 2
        assert alice_group["records"][0] == records[0]
        assert alice_group["records"][1] == records[1]

    def test_distinct_records_are_separate_groups(self):
        records = [
            {"name": "Alice Smith"},
            {"name": "Bob Jones"},
        ]
        groups = fuzzy_dedupe(records, keys=["name"], threshold=0.8)
        assert len(groups) == 2
        assert all(len(group["records"]) == 1 for group in groups)

    def test_below_threshold_not_grouped(self):
        records = [
            {"name": "Alice Smith"},
            {"name": "Alice Jones"},
        ]
        groups = fuzzy_dedupe(records, keys=["name"], threshold=0.9)
        assert len(groups) == 2

    def test_group_ids_increment_in_record_order(self):
        records = [
            {"name": "Alpha One"},
            {"name": "Beta Two"},
            {"name": "Alpha  One"},
        ]
        groups = fuzzy_dedupe(records, keys=["name"], threshold=0.8)
        assert [g["group"] for g in groups] == [0, 1]

    def test_missing_keys_treated_as_empty(self):
        records = [
            {"name": "Alice", "email": "a@x.com"},
            {"name": "Bob", "email": None},
            {"name": None, "email": None},
        ]
        groups = fuzzy_dedupe(records, keys=["email"], threshold=0.8)
        assert len(groups) == 2
        assert len(groups[1]["records"]) == 2

    def test_empty_records_list(self):
        assert fuzzy_dedupe([], keys=["name"]) == []


class TestMergeGroup:
    def test_union_of_keys(self):
        merged = merge_group([{"a": 1}, {"b": 2}])
        assert merged == {"a": 1, "b": 2}

    def test_first_non_null_value_wins(self):
        merged = merge_group(
            [
                {"name": "Alice", "score": None, "city": "NYC"},
                {"name": None, "score": 95, "city": "LA"},
            ]
        )
        assert merged == {"name": "Alice", "score": 95, "city": "NYC"}

    def test_overlapping_keys_keep_first_record_value(self):
        merged = merge_group(
            [
                {"name": "Alice", "risk": "low"},
                {"name": "Alicia", "risk": "medium"},
            ]
        )
        assert merged == {"name": "Alice", "risk": "low"}

    def test_disjoint_keys(self):
        merged = merge_group(
            [
                {"id": 1, "name": "Alice"},
                {"id": 2, "email": "a@x.com"},
            ]
        )
        assert merged == {"id": 1, "name": "Alice", "email": "a@x.com"}

    def test_single_record_returns_itself(self):
        assert merge_group([{"a": 1}]) == {"a": 1}

    def test_none_values_are_skipped(self):
        merged = merge_group([{"a": None}, {"b": None}])
        assert merged == {}

    def test_falsy_but_not_none_values_are_kept(self):
        merged = merge_group([{"a": 0, "b": False, "c": ""}])
        assert merged == {"a": 0, "b": False, "c": ""}
