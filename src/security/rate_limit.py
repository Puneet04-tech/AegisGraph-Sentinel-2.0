"""Distributed Redis-backed rate limiting helpers."""

from __future__ import annotations

import hashlib
import logging
import math
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from src.config.settings import get_settings
from src.exceptions.error_responses import build_rate_limit_error_payload
from src.utils.redis_client import get_redis_client

logger = logging.getLogger(__name__)

_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local ttl_seconds = tonumber(ARGV[4])

local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])

if tokens == nil then
  tokens = capacity
end
if ts == nil then
  ts = now
end

local elapsed = now - ts
if elapsed < 0 then
  elapsed = 0
end

tokens = math.min(capacity, tokens + (elapsed * refill_rate))

local allowed = 0
local retry_after = 0

if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  local deficit = 1 - tokens
  retry_after = math.max(1, math.ceil(deficit / refill_rate))
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, ttl_seconds)

return {allowed, retry_after, tokens}
"""


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int
    remaining_tokens: float


def _normalize_identity(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _parse_rate_limit(rate_limit: str) -> Tuple[int, int]:
    raw = rate_limit.strip().lower()
    if "/" not in raw:
        raise ValueError(f"Invalid rate limit format: {rate_limit!r}")
    count_text, window_text = raw.split("/", 1)
    requests = int(count_text.strip())
    window_text = window_text.strip()
    if window_text in {"s", "sec", "second", "seconds"}:
        window_seconds = 1
    elif window_text in {"m", "min", "minute", "minutes"}:
        window_seconds = 60
    elif window_text in {"h", "hr", "hour", "hours"}:
        window_seconds = 3600
    else:
        raise ValueError(f"Unsupported rate limit window: {rate_limit!r}")
    return requests, window_seconds


def _bucket_key(scope: str, identity: str) -> str:
    return f"aegis:rate_limit:{scope}:{_normalize_identity(identity)}"


def check_rate_limit(
    api_key: str,
    *,
    scope: str = "api_key",
    limit: Optional[int] = None,
    burst: Optional[int] = None,
    window_seconds: Optional[int] = None,
) -> RateLimitDecision:
    """Check a distributed token bucket and fail open if Redis is unavailable."""
    settings = get_settings()
    configured_limit, configured_window = _parse_rate_limit(settings.api.rate_limit)
    limit = int(limit or configured_limit)
    burst = int(burst or settings.api.rate_limit_burst or limit)
    window_seconds = int(window_seconds or settings.api.rate_limit_window_seconds or configured_window)

    capacity = max(1, burst)
    refill_rate = max(1e-9, float(limit) / float(window_seconds))
    ttl_seconds = max(window_seconds * 2, int(math.ceil(capacity / refill_rate)) + 60)
    key = _bucket_key(scope, api_key)

    try:
        redis_client = get_redis_client(settings.innovations.redis_url)
        result = redis_client.eval(
            _TOKEN_BUCKET_LUA,
            1,
            key,
            str(time.time()),
            str(refill_rate),
            str(capacity),
            str(ttl_seconds),
        )
        allowed = bool(int(result[0]))
        retry_after = int(result[1])
        remaining = float(result[2])
        return RateLimitDecision(
            allowed=allowed,
            retry_after_seconds=retry_after,
            remaining_tokens=remaining,
        )
    except Exception as exc:
        logger.warning("Rate limiter unavailable, allowing request: %s", exc, exc_info=True)
        return RateLimitDecision(
            allowed=True,
            retry_after_seconds=0,
            remaining_tokens=float(capacity),
        )


def build_rate_limit_response_details(
    decision: RateLimitDecision,
    limit_type: str,
) -> Dict[str, Any]:
    """Return the standardized nested error payload for 429 responses."""
    return build_rate_limit_error_payload(
        retry_after_seconds=decision.retry_after_seconds,
        limit_type=limit_type,
    )
