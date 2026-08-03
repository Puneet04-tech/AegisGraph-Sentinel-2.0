"""Dedicated unit tests for src/audit/correlation.py.

The correlation helpers hand out and propagate UUID-based trace IDs.  These
tests pin the generated-ID format, provided-ID propagation and the
generate-when-empty fallback.
"""

import uuid

import pytest

from src.audit.correlation import generate_correlation_id, get_correlation_id


def test_generate_correlation_id_is_uuid():
    assert uuid.UUID(generate_correlation_id())


def test_get_correlation_id_propagates_provided():
    assert get_correlation_id("trace-123") == "trace-123"


def test_get_correlation_id_generates_when_none():
    generated = get_correlation_id(None)
    assert uuid.UUID(generated)


def test_get_correlation_id_generates_for_empty_string():
    generated = get_correlation_id("")
    assert uuid.UUID(generated)


def test_generated_ids_are_unique():
    assert generate_correlation_id() != generate_correlation_id()
