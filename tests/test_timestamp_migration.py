from datetime import datetime, timezone, timedelta

import pytest

from database.migration_fix_timestamp import (
    TimestampMigrationError,
    TransactionTimestampFixer,
    verify_timestamp_field,
)


@pytest.fixture
def fixer():
    return TransactionTimestampFixer()


def test_identical_timestamps_across_multiple_fields_migrate_cleanly(fixer):
    transaction = {
        "transaction_id": "tx-1",
        "timestamp": 1714000000,
        "created_at": 1714000000.0,
    }

    fixed = fixer.fix_transaction(transaction)

    assert fixed["timestamp"] == 1714000000.0
    assert "_timestamp_conflicts" not in fixed
    assert fixed["transaction_id"] == "tx-1"


def test_conflicting_timestamps_are_preserved_in_metadata(fixer):
    transaction = {
        "transaction_id": "tx-2",
        "timestamp": 1714000000,
        "created_at": 1713000000,
    }

    fixed = fixer.fix_transaction(transaction)

    assert fixed["timestamp"] == 1714000000.0
    assert "_timestamp_conflicts" in fixed
    assert fixed["_timestamp_conflicts"]["canonical_field"] == "timestamp"
    assert fixed["_timestamp_conflicts"]["values"]["timestamp"]["normalized"] == 1714000000.0
    assert fixed["_timestamp_conflicts"]["values"]["created_at"]["normalized"] == 1713000000.0


def test_timestamp_normalization_handles_common_formats(fixer):
    dt = datetime(2024, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
    expected = dt.timestamp()

    assert fixer.normalize_timestamp("2024-04-25T12:00:00Z") == expected
    assert fixer.normalize_timestamp(int(expected)) == expected
    assert fixer.normalize_timestamp(int(expected * 1000)) == expected
    assert fixer.normalize_timestamp(dt) == expected


def test_invalid_timestamp_raises_safe_error(fixer):
    with pytest.raises(ValueError):
        fixer.normalize_timestamp("not-a-real-timestamp")


def test_verify_timestamp_field_missing():
    is_valid, message = verify_timestamp_field({"transaction_id": "tx-3"})
    assert not is_valid
    assert "missing" in message.lower()


def test_verify_timestamp_field_matching_duplicates():
    expected = datetime(2024, 4, 25, 12, 0, 0, tzinfo=timezone.utc).timestamp()
    is_valid, message = verify_timestamp_field(
        {"timestamp": expected, "created_at": "2024-04-25T12:00:00Z"}
    )
    assert is_valid
    assert "matching values" in message.lower()


def test_verify_timestamp_field_conflicting_duplicates():
    is_valid, message = verify_timestamp_field(
        {"timestamp": 1714000000, "created_at": 1713000000}
    )
    assert not is_valid
    assert "conflicting" in message.lower()


def test_batch_fix_handles_conflicts_and_non_conflicts(fixer):
    transactions = [
        {"transaction_id": "tx-a", "timestamp": 1714000000, "created_at": 1714000000},
        {"transaction_id": "tx-b", "timestamp": 1714000000, "created_at": 1713000000},
        {"transaction_id": "tx-c", "timestamp": "2024-04-25T12:00:00Z"},
    ]

    fixed_batch = fixer.fix_batch(transactions)

    assert len(fixed_batch) == 3
    assert fixed_batch[0]["timestamp"] == 1714000000.0
    assert "_timestamp_conflicts" not in fixed_batch[0]
    assert "_timestamp_conflicts" in fixed_batch[1]
    assert fixed_batch[2]["timestamp"] == "2024-04-25T12:00:00Z"
    assert fixer.fixed_count == 2
    assert fixer.conflict_count == 1
    assert fixer.error_count == 0


def test_fix_transaction_invalid_timestamp_surfaces_error(fixer):
    with pytest.raises(TimestampMigrationError):
        fixer.fix_transaction({"timestamp": "bad-value", "created_at": 1713000000})
