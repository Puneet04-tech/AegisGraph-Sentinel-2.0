"""Unit tests for the ID generator utilities."""

import re
import time

import pytest

from src.utils.id_generator import (
    new_id,
    readable_id,
    snowflake_id,
    timestamp_id,
    uuid4_hex,
)


class TestUuid4Hex:
    def test_length_is_32(self):
        assert len(uuid4_hex()) == 32

    def test_only_hex_chars(self):
        assert re.fullmatch(r"[0-9a-f]{32}", uuid4_hex())

    def test_unique_across_calls(self):
        assert len({uuid4_hex() for _ in range(500)}) == 500


class TestNewId:
    def test_prefix_format(self):
        value = new_id("txn")
        assert value.startswith("txn_")
        assert len(value) == len("txn_") + 16
        assert re.fullmatch(r"[0-9a-f]{16}", value[len("txn_"):])

    def test_no_prefix_returns_bare_hex(self):
        value = new_id()
        assert "_" not in value
        assert re.fullmatch(r"[0-9a-f]{16}", value)

    def test_empty_prefix_returns_bare_hex(self):
        for value in (new_id(""), new_id(None)):
            assert "_" not in value
            assert re.fullmatch(r"[0-9a-f]{16}", value)

    def test_unique_across_many_calls(self):
        values = {new_id("evt") for _ in range(1000)}
        assert len(values) == 1000
        assert all(v.startswith("evt_") for v in values)

    def test_sanitizes_prefix(self):
        assert new_id("case id#1!").startswith("caseid1_")
        assert new_id("a-b/c").startswith("abc_")
        assert "_" not in new_id("   ")
        assert new_id("__ok__").startswith("__ok___")


class TestTimestampId:
    def test_ms_format(self):
        before = int(time.time() * 1000)
        value = timestamp_id()
        after = int(time.time() * 1000)
        assert value.isdigit()
        assert before <= int(value) <= after

    def test_seconds_format(self):
        before = int(time.time())
        value = timestamp_id(use_ms=False)
        after = int(time.time())
        assert value.isdigit()
        assert before <= int(value) <= after

    def test_ms_differs_from_seconds(self):
        ms = int(timestamp_id())
        sec = int(timestamp_id(use_ms=False))
        assert ms > sec

    def test_with_prefix(self):
        value = timestamp_id("case")
        assert value.startswith("case_")
        assert int(value[len("case_"):]) > 0

    def test_prefix_sanitized(self):
        assert timestamp_id("event id").startswith("eventid_")

    def test_no_prefix(self):
        value = timestamp_id()
        assert "_" not in value
        assert value.isdigit()


class TestSnowflakeId:
    def test_returns_positive_int(self):
        value = snowflake_id()
        assert isinstance(value, int)
        assert value > 0
        assert value.bit_length() <= 64

    def test_unique_across_rapid_calls(self):
        values = {snowflake_id() for _ in range(1000)}
        assert len(values) == 1000

    def test_monotonic_increasing(self):
        previous = snowflake_id()
        for _ in range(500):
            current = snowflake_id()
            assert current > previous
            previous = current

    def test_encodes_timestamp(self):
        before = int(time.time() * 1000)
        value = snowflake_id()
        after = int(time.time() * 1000)
        encoded_ms = (value >> 22) + 1288834974657
        assert before <= encoded_ms <= after

    def test_different_worker_ids_differ(self):
        values = {snowflake_id(worker_id=i) for i in range(8)}
        assert len(values) == 8

    def test_worker_id_is_bounded(self):
        value = snowflake_id(worker_id=5000)
        assert (value >> 12) & 0x3FF == 5000 & 0x3FF

    def test_same_worker_sequence_increments(self):
        first = snowflake_id()
        second = snowflake_id()
        assert (second & 0xFFF) > (first & 0xFFF) or second > first


class TestReadableId:
    def test_default_length(self):
        assert len(readable_id()) == 8

    def test_custom_length(self):
        assert len(readable_id(length=12)) == 12

    def test_alphabet_membership(self):
        alphabet = set("abcdefghjkmnpqrstuvwxyz23456789")
        for _ in range(200):
            assert set(readable_id()) <= alphabet

    def test_no_ambiguous_chars(self):
        ambiguous = set("0O1Il")
        for _ in range(200):
            assert not (set(readable_id()) & ambiguous)

    def test_with_prefix(self):
        value = readable_id("evt")
        assert value.startswith("evt_")
        assert len(value) == len("evt_") + 8

    def test_prefix_sanitized(self):
        assert readable_id("case id#7").startswith("caseid7_")

    def test_no_prefix_no_underscore(self):
        assert "_" not in readable_id()

    def test_invalid_length_raises(self):
        with pytest.raises(ValueError):
            readable_id(length=0)
