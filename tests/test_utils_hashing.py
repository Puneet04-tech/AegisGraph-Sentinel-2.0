"""Unit tests for the hashing and checksum utilities."""

import json

import pytest

from src.utils.hashing import (
    deterministic_hash,
    fnv1a,
    hash_range,
    md5_hex,
    sha256_hex,
    stable_json_hash,
)


class TestSha256Hex:
    def test_known_vector(self):
        assert sha256_hex("hello") == (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )

    def test_bytes_matches_str(self):
        assert sha256_hex(b"hello") == sha256_hex("hello")

    def test_bytes_matches_str_unicode(self):
        assert sha256_hex("caf\xe9") == sha256_hex("caf\xe9".encode("utf-8"))

    def test_empty_string(self):
        assert sha256_hex("") == sha256_hex(b"")
        assert len(sha256_hex("")) == 64

    def test_output_is_lowercase_hex(self):
        digest = sha256_hex("hello")
        assert all(c in "0123456789abcdef" for c in digest)


class TestMd5Hex:
    def test_known_vector(self):
        assert md5_hex("hello") == "5d41402abc4b2a76b9719d911017c592"

    def test_bytes_matches_str(self):
        assert md5_hex(b"hello") == md5_hex("hello")

    def test_differs_from_sha256(self):
        assert md5_hex("hello") != sha256_hex("hello")


class TestDeterministicHash:
    def test_stable_across_calls(self):
        first = deterministic_hash("account-42", 1337, 1.5)
        second = deterministic_hash("account-42", 1337, 1.5)
        assert first == second

    def test_stable_across_process(self):
        args = ("worker-7", "txn-1001", 0.1, None)
        result = deterministic_hash(*args)
        serialized = json.dumps(args, default=repr)
        rerun = deterministic_hash(*json.loads(serialized))
        assert result == rerun

    def test_differs_when_one_part_changes(self):
        base = deterministic_hash("mule", "wallet", 500)
        assert base != deterministic_hash("mule", "wallet", 501)
        assert base != deterministic_hash("mule", "wallet2", 500)
        assert base != deterministic_hash("mule2", "wallet", 500)

    def test_part_order_matters(self):
        assert deterministic_hash("a", "b") != deterministic_hash("b", "a")

    def test_respects_length_param(self):
        full = deterministic_hash("x", "y", "z", length=64)
        short = deterministic_hash("x", "y", "z", length=12)
        assert len(short) == 12
        assert short == full[:12]

    def test_default_length_is_twelve(self):
        assert len(deterministic_hash("a", "b")) == 12

    def test_mixed_types(self):
        h = deterministic_hash("str", 42, -1.5, None)
        assert isinstance(h, str) and len(h) == 12
        assert h == deterministic_hash("str", 42, -1.5, None)

    def test_float_rounding_is_deterministic(self):
        a = deterministic_hash(0.1, length=64)
        b = deterministic_hash(float(repr(0.1)), length=64)
        assert a == b

    def test_none_and_empty_string_distinct(self):
        assert deterministic_hash(None) != deterministic_hash("")
        assert deterministic_hash("") != deterministic_hash(" ", length=64)


class TestStableJsonHash:
    def test_sorts_keys(self):
        a = {"name": "alice", "risk": 0.9, "id": 7}
        b = {"risk": 0.9, "id": 7, "name": "alice"}
        assert stable_json_hash(a) == stable_json_hash(b)

    def test_nested_dicts_sorted(self):
        a = {"outer": {"z": 1, "a": 2}, "k": 0}
        b = {"k": 0, "outer": {"a": 2, "z": 1}}
        assert stable_json_hash(a) == stable_json_hash(b)

    def test_differs_on_content(self):
        assert stable_json_hash({"a": 1}) != stable_json_hash({"a": 2})

    def test_deterministic(self):
        obj = {"list": [3, 1, 2], "flag": True, "pi": 3.14}
        assert stable_json_hash(obj) == stable_json_hash(obj)


class TestFnv1a:
    def test_returns_int(self):
        assert isinstance(fnv1a("hello"), int)
        assert isinstance(fnv1a(b"hello"), int)
        assert isinstance(fnv1a(42), int)

    def test_deterministic(self):
        assert fnv1a("hello") == fnv1a("hello")

    def test_known_vector(self):
        assert fnv1a("hello") == 0x4F9F2CAB

    def test_fits_in_32_bits(self):
        for value in ["a", "hello world", "s\xe9rial", 3.14159, None]:
            assert 0 <= fnv1a(value) <= 0xFFFFFFFF

    def test_str_matches_bytes(self):
        assert fnv1a("hello") == fnv1a(b"hello")


class TestHashRange:
    def test_returns_int_in_range(self):
        buckets = 16
        for value in ["a", "b", "c", 1, 2.5, None]:
            index = hash_range(value, buckets)
            assert isinstance(index, int)
            assert 0 <= index < buckets

    def test_same_value_same_bucket(self):
        for buckets in [2, 7, 64]:
            assert hash_range("wallet-abc", buckets) == hash_range("wallet-abc", buckets)

    def test_all_buckets_reachable(self):
        buckets = 10
        reached = {hash_range(f"key-{i}", buckets) for i in range(1000)}
        assert reached == set(range(buckets))

    def test_distributes_across_buckets(self):
        buckets = 4
        counts = [0] * buckets
        for i in range(1000):
            counts[hash_range(f"id-{i}", buckets)] += 1
        assert sum(counts) == 1000
        assert all(count > 0 for count in counts)

    def test_bucket_count_change_moves_values(self):
        assert hash_range("key-1", 10) != hash_range("key-1", 11)

    def test_invalid_bucket_count_raises(self):
        with pytest.raises(ValueError):
            hash_range("key-1", 0)
        with pytest.raises(ValueError):
            hash_range("key-1", -3)
