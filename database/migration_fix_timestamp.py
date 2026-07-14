"""
Database migration to fix duplicate timestamp field in transaction dict.
Ensures transactions have single, accurate timestamp field with no data loss.
"""

import logging
from typing import Dict, Any, List, Tuple, Callable, Optional
from datetime import datetime, timezone

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
        self.conflict_count = 0

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

    def normalize_timestamp(self, value: Any) -> float:
        """
        Convert timestamp to Unix seconds with fractional precision preserved.

        Args:
            value: Timestamp value (int, float, str, or datetime)

        Returns:
            Unix timestamp in seconds as a float
        """
        if isinstance(value, int):
            # Assume seconds if reasonable range
            if 946684800 < value < 4102444800:  # 2000-2100
                return float(value)
            # Assume milliseconds if in millisecond range
            elif value > 1000000000000:  # > ~2001 in milliseconds
                return float(value) / 1000.0
            return float(value)

        elif isinstance(value, float):
            # Assume seconds
            return float(value)

        elif isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return float(value.timestamp())

        elif isinstance(value, str):
            # Try parsing common formats
            candidate = value.strip()
            iso_candidate = candidate[:-1] + "+00:00" if candidate.endswith("Z") else candidate
            try:
                dt = datetime.fromisoformat(iso_candidate)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return float(dt.timestamp())
            except ValueError:
                pass

            for fmt in [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S',
            ]:
                try:
                    dt = datetime.strptime(candidate, fmt)
                    return float(dt.replace(tzinfo=timezone.utc).timestamp())
                except ValueError:
                    continue

            # If all parsing fails, try int conversion
            try:
                return float(value)
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

        normalized_fields = []
        for field_name, value in timestamp_fields:
            normalized_fields.append((field_name, value, self.normalize_timestamp(value)))

        normalized_values = {normalized for _, _, normalized in normalized_fields}
        if len(normalized_values) == 1:
            # All timestamp representations refer to the same instant.
            preferred_names = ['timestamp', 'created_at', 'created_time']
            for pref_name in preferred_names:
                for field_name, value, normalized in normalized_fields:
                    if field_name == pref_name:
                        logger.debug(
                            "Using canonical timestamp field '%s' after normalization agreement: %s",
                            field_name,
                            normalized,
                        )
                        return (field_name, normalized)

            field_name, _, normalized = normalized_fields[0]
            logger.debug(
                "Using first timestamp field '%s' after normalization agreement: %s",
                field_name,
                normalized,
            )
            return (field_name, normalized)

        if len(timestamp_fields) == 1:
            field_name, value = timestamp_fields[0]
            return (field_name, self.normalize_timestamp(value))

        # Multiple timestamp fields with conflicting values.
        # Preserve the canonical timestamp and capture the conflict for review.
        preferred_names = ['timestamp', 'created_at', 'created_time']
        canonical_name = None
        canonical_value = None
        canonical_normalized = None

        for pref_name in preferred_names:
            for field_name, value, normalized in normalized_fields:
                if field_name == pref_name:
                    canonical_name = field_name
                    canonical_value = value
                    canonical_normalized = normalized
                    break
            if canonical_name is not None:
                break

        if canonical_name is None:
            canonical_name, canonical_value, canonical_normalized = normalized_fields[0]

        conflict_map = {
            field_name: {
                "original": value,
                "normalized": normalized,
            }
            for field_name, value, normalized in normalized_fields
        }
        logger.warning(
            "Conflicting timestamp values detected; preserving canonical field '%s' and recording "
            "all normalized values for manual review: %s",
            canonical_name,
            conflict_map,
        )
        return (canonical_name, canonical_normalized)

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

            normalized_values = {
                field_name: self.normalize_timestamp(value)
                for field_name, value in timestamp_fields
            }
            unique_normalized_values = set(normalized_values.values())
            canonical_name, canonical_value = self.resolve_duplicate_timestamps(
                timestamp_fields
            )

            # Create fixed transaction
            fixed = {
                k: v for k, v in transaction.items()
                if k == canonical_name or not self.is_timestamp_field(k)
            }

            # Ensure timestamp field is present
            if canonical_name not in fixed:
                fixed[canonical_name] = canonical_value

            if len(unique_normalized_values) > 1:
                conflict_details = {
                    field_name: {
                        "original": transaction[field_name],
                        "normalized": normalized_values[field_name],
                    }
                    for field_name, _ in timestamp_fields
                }
                fixed["_timestamp_conflicts"] = {
                    "canonical_field": canonical_name,
                    "canonical_value": canonical_value,
                    "conflicting_fields": list(conflict_details.keys()),
                    "values": conflict_details,
                    "reason": "Normalized timestamp values do not match",
                }
                self.conflict_count += 1
                logger.warning(
                    "Timestamp conflict preserved for transaction; canonical=%s, fields=%s, normalized=%s",
                    canonical_name,
                    list(conflict_details.keys()),
                    {name: details["normalized"] for name, details in conflict_details.items()},
                )
                logger.info(
                    "Fixed transaction with preserved timestamp conflict metadata; kept canonical field '%s'",
                    canonical_name,
                )
            else:
                logger.info(
                    f"Fixed transaction - removed {len(timestamp_fields) - 1} duplicate timestamp fields"
                )
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

    def fix_batch(self, transactions: List[Dict], progress_callback: Optional[Callable[[int, int, float], None]] = None) -> List[Dict]:
        """
        Fix timestamp fields in batch of transactions with progress tracking.

        Args:
            transactions: List of transaction dictionaries
            progress_callback: Optional callback function taking (current, total, percentage)

        Returns:
            List of fixed transactions
        """
        fixed_transactions = []
        total_tx = len(transactions)
        
        if total_tx == 0:
            logger.info("No transactions to process in this batch.")
            return []

        # Log milestone periodically (e.g., every 10% or at least every 1000 items)
        log_interval = max(1, total_tx // 10) if total_tx < 10000 else 1000

        for i, transaction in enumerate(transactions):
            try:
                fixed = self.fix_transaction(transaction)
                fixed_transactions.append(fixed)
            except TimestampMigrationError as e:
                logger.error(f"Failed to fix transaction {i}: {str(e)}")
                # Keep original if fix fails
                fixed_transactions.append(transaction)
            
            current = i + 1
            percentage = (current / total_tx) * 100
            
            #  Log percentage completion periodically
            if current % log_interval == 0 or current == total_tx:
                logger.info(f"Migration Progress: {current}/{total_tx} ({percentage:.1f}%) complete.")
            
            #  Support optional callback functions for progress updates
            if progress_callback is not None:
                progress_callback(current, total_tx, percentage)

        #  Provide summary statistics during execution
        logger.info(
            f"Batch fix complete: {self.fixed_count} fixed, "
            f"{self.error_count} errors, {self.skipped_count} skipped, "
            f"{self.conflict_count} conflicts preserved. "
            f"Total processed: {total_tx}"
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
        normalized_values = {}
        for field_name, value in timestamp_fields:
            try:
                normalized_values[field_name] = fixer.normalize_timestamp(value)
            except ValueError as e:
                return (False, f"Timestamp format invalid for field '{field_name}': {str(e)}")

        if len(set(normalized_values.values())) > 1:
            return (
                False,
                f"Transaction has conflicting timestamp fields: {normalized_values}",
            )

        field_names = [name for name, _ in timestamp_fields]
        return (True, f"Transaction has duplicate timestamp fields with matching values: {field_names}")

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
