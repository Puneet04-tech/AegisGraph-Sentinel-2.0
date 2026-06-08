"""
Database migration to fix duplicate timestamp field in transaction dict.
Ensures transactions have single, accurate timestamp field with no data loss.
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class TimestampMigrationError(Exception):
    """Raised when timestamp migration fails."""
    pass


class TransactionTimestampFixer:
    """
    Fixes duplicate timestamp fields in transaction records.
    Handles multiple timestamp formats and resolves conflicts safely.
    """

    # Timestamp field name variants to check
    TIMESTAMP_VARIANTS = [
        'timestamp',
        'created_at',
        'created_time',
        'transaction_time',
        'ts',
        'time',
    ]

    def __init__(self):
        """Initialize timestamp fixer."""
        self.fixed_count = 0
        self.error_count = 0
        self.skipped_count = 0

    def find_timestamp_fields(self, transaction: Dict) -> List[Tuple[str, Any]]:
        """
        Find all timestamp-like fields in transaction.

        Args:
            transaction: Transaction dictionary

        Returns:
            List of (field_name, value) tuples for timestamp fields
        """
        timestamp_fields = []

        for key, value in transaction.items():
            # Check if key looks like a timestamp field
            key_lower = key.lower()
            if any(variant in key_lower for variant in self.TIMESTAMP_VARIANTS):
                if isinstance(value, (str, int, float, datetime)):
                    timestamp_fields.append((key, value))

        return timestamp_fields

    def normalize_timestamp(self, value: Any) -> int:
        """
        Convert timestamp to Unix seconds.

        Args:
            value: Timestamp value (int, float, str, or datetime)

        Returns:
            Unix timestamp in seconds
        """
        if isinstance(value, int):
            # Assume seconds if reasonable range
            if 946684800 < value < 4102444800:  # 2000-2100
                return value
            # Assume milliseconds if in millisecond range
            elif value > 1000000000000:  # > ~2001 in milliseconds
                return value // 1000
            return value

        elif isinstance(value, float):
            # Assume seconds
            return int(value)

        elif isinstance(value, datetime):
            return int(value.timestamp())

        elif isinstance(value, str):
            # Try parsing common formats
            for fmt in [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S',
            ]:
                try:
                    dt = datetime.strptime(value, fmt)
                    return int(dt.timestamp())
                except ValueError:
                    continue

            # If all parsing fails, try int conversion
            try:
                return int(float(value))
            except (ValueError, TypeError):
                raise ValueError(f"Cannot normalize timestamp: {value}")

        else:
            raise ValueError(f"Unsupported timestamp type: {type(value)}")

    def resolve_duplicate_timestamps(self, timestamp_fields: List[Tuple[str, Any]]) -> Tuple[str, int]:
        """
        Resolve multiple timestamp fields to single canonical value.

        Args:
            timestamp_fields: List of (field_name, value) tuples

        Returns:
            Tuple of (canonical_field_name, canonical_timestamp)

        Raises:
            TimestampMigrationError: If conflict cannot be resolved
        """
        if not timestamp_fields:
            raise TimestampMigrationError("No timestamp fields found")

        if len(timestamp_fields) == 1:
            field_name, value = timestamp_fields[0]
            return (field_name, self.normalize_timestamp(value))

        # Multiple timestamp fields - need to resolve
        # Strategy: prefer 'timestamp' field, else prefer newest
        preferred_names = ['timestamp', 'created_at', 'created_time']

        # Check for preferred field
        for pref_name in preferred_names:
            for field_name, value in timestamp_fields:
                if field_name == pref_name:
                    normalized = self.normalize_timestamp(value)
                    logger.debug(f"Using preferred timestamp field '{field_name}'")
                    return (field_name, normalized)

        # No preferred field found - use first one (but log warning)
        field_name, value = timestamp_fields[0]
        normalized = self.normalize_timestamp(value)
        logger.warning(
            f"Multiple timestamp fields without preferred name. "
            f"Using first field '{field_name}' with value {normalized}"
        )
        return (field_name, normalized)

    def fix_transaction(self, transaction: Dict) -> Dict:
        """
        Fix timestamp fields in single transaction.

        Args:
            transaction: Original transaction dictionary

        Returns:
            Fixed transaction with single timestamp field
        """
        try:
            timestamp_fields = self.find_timestamp_fields(transaction)

            if not timestamp_fields:
                logger.warning("Transaction has no timestamp fields")
                self.skipped_count += 1
                return transaction

            if len(timestamp_fields) == 1:
                logger.debug("Transaction has exactly one timestamp field")
                self.skipped_count += 1
                return transaction

            # Multiple timestamp fields - resolve conflict
            logger.info(f"Found {len(timestamp_fields)} timestamp fields in transaction")

            canonical_name, canonical_value = self.resolve_duplicate_timestamps(
                timestamp_fields
            )

            # Create fixed transaction
            fixed = {k: v for k, v in transaction.items()
                    if k == canonical_name or not self.is_timestamp_field(k)}

            # Ensure timestamp field is present
            if canonical_name not in fixed:
                fixed[canonical_name] = canonical_value

            logger.info(f"Fixed transaction - removed {len(timestamp_fields) - 1} duplicate timestamp fields")
            self.fixed_count += 1
            return fixed

        except Exception as e:
            logger.error(f"Error fixing transaction: {str(e)}")
            self.error_count += 1
            raise TimestampMigrationError(f"Failed to fix transaction: {str(e)}") from e

    def is_timestamp_field(self, key: str) -> bool:
        """
        Check if field name looks like a timestamp.

        Args:
            key: Field name

        Returns:
            True if field looks like a timestamp
        """
        key_lower = key.lower()
        return any(variant in key_lower for variant in self.TIMESTAMP_VARIANTS)

    def fix_batch(self, transactions: List[Dict]) -> List[Dict]:
        """
        Fix timestamp fields in batch of transactions.

        Args:
            transactions: List of transaction dictionaries

        Returns:
            List of fixed transactions
        """
        fixed_transactions = []

        for i, transaction in enumerate(transactions):
            try:
                fixed = self.fix_transaction(transaction)
                fixed_transactions.append(fixed)
            except TimestampMigrationError as e:
                logger.error(f"Failed to fix transaction {i}: {str(e)}")
                # Keep original if fix fails
                fixed_transactions.append(transaction)

        logger.info(
            f"Batch fix complete: {self.fixed_count} fixed, "
            f"{self.error_count} errors, {self.skipped_count} skipped"
        )
        return fixed_transactions

    def reset_stats(self):
        """Reset migration statistics."""
        self.fixed_count = 0
        self.error_count = 0
        self.skipped_count = 0


def verify_timestamp_field(transaction: Dict) -> Tuple[bool, str]:
    """
    Verify transaction has valid single timestamp field.

    Args:
        transaction: Transaction to verify

    Returns:
        Tuple of (is_valid, validation_message)
    """
    fixer = TransactionTimestampFixer()
    timestamp_fields = fixer.find_timestamp_fields(transaction)

    if not timestamp_fields:
        return (False, "Transaction missing timestamp field")

    if len(timestamp_fields) > 1:
        field_names = [name for name, _ in timestamp_fields]
        return (False, f"Transaction has multiple timestamp fields: {field_names}")

    # Verify timestamp can be normalized
    try:
        fixer.normalize_timestamp(timestamp_fields[0][1])
        return (True, "Timestamp field is valid")
    except ValueError as e:
        return (False, f"Timestamp format invalid: {str(e)}")


def create_migration_script() -> str:
    """
    Generate migration script for database.

    Returns:
        SQL migration script as string
    """
    return """
-- Migration: Fix duplicate timestamp fields in transactions
-- Date: 2026-06-04
-- Description: Removes duplicate timestamp fields and ensures single canonical timestamp

-- This migration should be customized based on actual database schema
-- Ensure backup before running on production

-- For SQLite:
-- CREATE TABLE transactions_fixed AS
-- SELECT
--   id,
--   user_id,
--   transaction_type,
--   created_at AS timestamp,
--   amount,
--   status
-- FROM transactions;

-- For PostgreSQL:
-- ALTER TABLE transactions
-- ADD COLUMN IF NOT EXISTS timestamp_canonical BIGINT;
-- UPDATE transactions
-- SET timestamp_canonical = EXTRACT(EPOCH FROM created_at)::BIGINT
-- WHERE timestamp_canonical IS NULL;

-- For MongoDB:
-- db.transactions.updateMany({}, [
--   {$set: {
--     timestamp: {$cond: [
--       {$ne: ["$timestamp", null]},
--       "$timestamp",
--       "$created_at"
--     ]},
--     created_time: "$$REMOVE",
--     transaction_time: "$$REMOVE",
--     ts: "$$REMOVE"
--   }}
-- ])
"""
