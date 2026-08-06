"""ID generators for transactions, cases, events, and audit records."""

from __future__ import annotations

import re
import secrets
import threading
import time
import uuid

_SAFE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_SNOWFLAKE_SEQUENCE_MASK = 0xFFF
_SNOWFLAKE_WORKER_MASK = 0x3FF

_snowflake_lock = threading.Lock()
_snowflake_last_ms = 0
_snowflake_sequence = 0


def uuid4_hex() -> str:
    return uuid.uuid4().hex


def new_id(prefix: str | None = None) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "", prefix or "")
    suffix = uuid4_hex()[:16]
    return f"{sanitized}_{suffix}" if sanitized else suffix


def timestamp_id(prefix: str | None = None, *, use_ms: bool = True) -> str:
    ts = time.time() * 1000 if use_ms else time.time()
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "", prefix or "")
    value = str(int(ts))
    return f"{sanitized}_{value}" if sanitized else value


def snowflake_id(worker_id: int = 0, *, epoch_ms: int = 1288834974657) -> int:
    global _snowflake_last_ms, _snowflake_sequence
    worker_id &= _SNOWFLAKE_WORKER_MASK
    with _snowflake_lock:
        ts_ms = int(time.time() * 1000)
        if ts_ms < _snowflake_last_ms:
            ts_ms = _snowflake_last_ms
        if ts_ms == _snowflake_last_ms:
            _snowflake_sequence = (_snowflake_sequence + 1) & _SNOWFLAKE_SEQUENCE_MASK
            if _snowflake_sequence == 0:
                while ts_ms <= _snowflake_last_ms:
                    ts_ms = int(time.time() * 1000)
        else:
            _snowflake_sequence = 0
        _snowflake_last_ms = ts_ms
        return (
            ((ts_ms - epoch_ms) << 22)
            | (worker_id << 12)
            | _snowflake_sequence
        )


def readable_id(prefix: str | None = None, *, length: int = 8) -> str:
    if length < 1:
        raise ValueError("length must be >= 1")
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "", prefix or "")
    body = "".join(secrets.choice(_SAFE_ALPHABET) for _ in range(length))
    return f"{sanitized}_{body}" if sanitized else body
