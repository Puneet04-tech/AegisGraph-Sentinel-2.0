# Troubleshooting Guide: Timestamp Migration Failures

## Overview

This guide helps diagnose and resolve issues encountered during timestamp migration, validation, normalization, and batch-fixing operations.

---

## Common Migration Errors

### Unsupported Timestamp Format

#### Symptoms

```text
Unsupported timestamp format
Failed to parse timestamp
Invalid datetime value
```

#### Causes

* Non-standard date formats
* Corrupted timestamp values
* Missing timezone information

#### Examples

##### Supported

```text
2026-06-08T10:30:00Z
2026-06-08T10:30:00+00:00
2026-06-08 10:30:00
```

##### Unsupported

```text
06/08/2026
June 8th 2026
invalid-date
```

#### Resolution

* Normalize timestamps before migration.
* Convert values to ISO-8601 format.
* Validate records before batch processing.

---

## Conflicting Timestamp Fields

### Symptoms

```text
Multiple timestamp candidates detected
Conflicting created_at and timestamp values
```

### Causes

* Legacy schema fields
* Duplicate timestamp columns
* Partial migrations

### Resolution

1. Identify the authoritative timestamp field.
2. Remove duplicate or deprecated values.
3. Re-run validation checks.

---

## Batch Migration Failures

### Symptoms

```text
Migration stopped unexpectedly
Batch processing aborted
```

### Causes

* Invalid records in the batch
* Resource exhaustion
* Database connectivity issues

### Resolution

* Process records in smaller batches.
* Review migration logs.
* Validate records before retrying.

---

## Invalid Transaction Records

### Symptoms

```text
Record validation failed
Timestamp missing
```

### Causes

* Null timestamps
* Incorrect data types
* Corrupted imports

### Resolution

* Identify invalid records.
* Repair or remove malformed entries.
* Re-run migration validation.

---

## Rollback Procedures

### When to Roll Back

* Large numbers of failed migrations
* Data corruption detected
* Incorrect normalization behavior

### Steps

1. Stop the migration process.
2. Restore the latest backup.
3. Verify record integrity.
4. Fix root causes.
5. Re-run migration in a staging environment.

---

## Debugging Tips

### Review Migration Statistics

Check:

* Total processed records
* Successful migrations
* Failed records
* Skipped records

### Review Logs

Look for:

```text
validation_failed
timestamp_parse_error
migration_batch_failed
normalization_error
```

### Verify Sample Records

Inspect:

```text
created_at
updated_at
timestamp
event_time
```

for unexpected formats.

---

## Recovery Checklist

* Validate timestamp formats
* Verify database connectivity
* Review migration logs
* Confirm backup availability
* Test migration on a subset of records
* Verify normalization output

---

## Best Practices

* Always back up data before migration
* Validate timestamps before batch execution
* Test migrations in staging first
* Monitor migration statistics
* Use incremental batch sizes

---

## Frequently Asked Questions

### Why are records being skipped?

Records may be skipped due to:

* Invalid timestamp formats
* Missing required fields
* Validation failures

### Why is migration slower than expected?

Possible causes:

* Large batch sizes
* Database contention
* Excessive validation failures

### Can failed records be retried?

Yes. After correcting validation issues, failed records can be reprocessed safely.

---

## Additional Resources

* Project Migration Documentation
* Validation Utilities Documentation
* Database Backup Procedures
* Contributor Guide
