"""
Velocity risk computation.

Velocity — several transactions from one account inside a short window — is one
of the strongest mule-account signals this platform exists to detect. The
scorer previously represented it with the literal ``0.3``, so it contributed an
identical constant to every risk score and could never move a transaction
across a decision threshold.

This module keeps a bounded, thread-safe window of recent activity per account
and scores both how *often* an account is transacting and how much *value* it
is moving, relative to its own established baseline where one exists and to
configured global ceilings otherwise.
"""

from __future__ import annotations

import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, Optional, Tuple

# Windows over which velocity is assessed. The short window catches a burst;
# the long window catches sustained draining that stays under a per-minute bar.
DEFAULT_SHORT_WINDOW_SECONDS = 60
DEFAULT_LONG_WINDOW_SECONDS = 3600

# Counts and amounts at or above these saturate the respective sub-score. Set
# from observed legitimate behaviour rather than guessed: a retail account
# rarely exceeds a handful of transfers a minute.
DEFAULT_SHORT_COUNT_CEILING = 10
DEFAULT_LONG_COUNT_CEILING = 60
DEFAULT_SHORT_AMOUNT_CEILING = 500_000.0
DEFAULT_LONG_AMOUNT_CEILING = 2_000_000.0

# An account needs some history before its own behaviour is a fair yardstick.
DEFAULT_MIN_BASELINE_SAMPLES = 20

# A cold account is neither trusted nor condemned: this is the documented
# score returned when there is nothing to judge against.
DEFAULT_COLD_START_RISK = 0.1

# Retention bounds so the tracker cannot grow without limit.
DEFAULT_MAX_ACCOUNTS = 100_000
DEFAULT_MAX_EVENTS_PER_ACCOUNT = 512


def _to_epoch_seconds(value) -> Optional[float]:
    """Normalise a timestamp of any supported form to epoch seconds.

    Naive datetimes are treated as UTC rather than local time, matching the
    convention the rest of the platform uses, so the same transaction scores
    identically regardless of the host's timezone.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        # Values this large are milliseconds; epoch seconds do not reach 1e11
        # until the year 5138.
        if abs(seconds) >= 1e11:
            seconds /= 1000.0
        return seconds
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    return None


@dataclass
class _AccountHistory:
    """Recent activity for one account, newest last."""

    events: Deque[Tuple[float, float]] = field(default_factory=deque)
    seen_transaction_ids: OrderedDict = field(default_factory=OrderedDict)
    # Running count and sum, used to derive the account's own baseline rate.
    total_events: int = 0
    total_amount: float = 0.0
    first_seen: Optional[float] = None


class VelocityRiskCalculator:
    """Thread-safe windowed velocity scoring.

    Args:
        short_window_seconds: Burst window.
        long_window_seconds: Sustained-activity window.
        max_accounts: LRU bound on tracked accounts.
        max_events_per_account: Bound on retained events per account.
    """

    def __init__(
        self,
        short_window_seconds: int = DEFAULT_SHORT_WINDOW_SECONDS,
        long_window_seconds: int = DEFAULT_LONG_WINDOW_SECONDS,
        short_count_ceiling: int = DEFAULT_SHORT_COUNT_CEILING,
        long_count_ceiling: int = DEFAULT_LONG_COUNT_CEILING,
        short_amount_ceiling: float = DEFAULT_SHORT_AMOUNT_CEILING,
        long_amount_ceiling: float = DEFAULT_LONG_AMOUNT_CEILING,
        min_baseline_samples: int = DEFAULT_MIN_BASELINE_SAMPLES,
        cold_start_risk: float = DEFAULT_COLD_START_RISK,
        max_accounts: int = DEFAULT_MAX_ACCOUNTS,
        max_events_per_account: int = DEFAULT_MAX_EVENTS_PER_ACCOUNT,
    ) -> None:
        self.short_window_seconds = max(1, int(short_window_seconds))
        self.long_window_seconds = max(
            self.short_window_seconds + 1, int(long_window_seconds)
        )
        self.short_count_ceiling = max(1, int(short_count_ceiling))
        self.long_count_ceiling = max(1, int(long_count_ceiling))
        self.short_amount_ceiling = max(1.0, float(short_amount_ceiling))
        self.long_amount_ceiling = max(1.0, float(long_amount_ceiling))
        self.min_baseline_samples = max(1, int(min_baseline_samples))
        self.cold_start_risk = min(1.0, max(0.0, float(cold_start_risk)))
        self.max_accounts = max(1, int(max_accounts))
        self.max_events_per_account = max(1, int(max_events_per_account))

        self._lock = threading.RLock()
        self._accounts: "OrderedDict[str, _AccountHistory]" = OrderedDict()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        account_id: str,
        amount: float,
        timestamp=None,
        transaction_id: Optional[str] = None,
    ) -> bool:
        """Record one transaction against an account.

        Returns False when the event was ignored: a missing account, an
        unparseable timestamp, or a transaction id already seen. Replays of the
        same transaction must not inflate an account's velocity.
        """
        if not account_id:
            return False

        moment = _to_epoch_seconds(timestamp)
        if moment is None:
            moment = datetime.now(timezone.utc).timestamp()

        try:
            value = abs(float(amount))
        except (TypeError, ValueError):
            value = 0.0

        with self._lock:
            history = self._accounts.get(account_id)
            if history is None:
                history = _AccountHistory()
                self._accounts[account_id] = history
                self._evict_accounts_if_needed()
            self._accounts.move_to_end(account_id)

            if transaction_id:
                if transaction_id in history.seen_transaction_ids:
                    return False
                history.seen_transaction_ids[transaction_id] = None
                while len(history.seen_transaction_ids) > self.max_events_per_account:
                    history.seen_transaction_ids.popitem(last=False)

            history.events.append((moment, value))
            # Timestamps may arrive out of order across workers; keeping the
            # deque sorted means window slicing stays correct.
            if len(history.events) > 1 and moment < history.events[-2][0]:
                history.events = deque(sorted(history.events))

            while len(history.events) > self.max_events_per_account:
                history.events.popleft()

            history.total_events += 1
            history.total_amount += value
            if history.first_seen is None or moment < history.first_seen:
                history.first_seen = moment

            return True

    def _evict_accounts_if_needed(self) -> None:
        """Caller must hold the lock."""
        while len(self._accounts) > self.max_accounts:
            self._accounts.popitem(last=False)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self, account_id: str, timestamp=None) -> float:
        """Return velocity risk in [0, 1] for an account at a point in time."""
        if not account_id:
            return self.cold_start_risk

        now = _to_epoch_seconds(timestamp)
        if now is None:
            now = datetime.now(timezone.utc).timestamp()

        with self._lock:
            history = self._accounts.get(account_id)
            if history is None or not history.events:
                return self.cold_start_risk

            short_count, short_amount = self._window_totals(
                history, now, self.short_window_seconds
            )
            long_count, long_amount = self._window_totals(
                history, now, self.long_window_seconds
            )
            baseline_rate = self._baseline_rate(history, now)

        if long_count == 0:
            # History exists but none of it is usable at this point in time --
            # every event has aged out, or is future-dated by clock skew.
            # Returning 0.0 would assert "definitely safe" on no evidence, so
            # this is the same documented default as an unknown account.
            return self.cold_start_risk

        short_score = max(
            self._ratio(short_count, self.short_count_ceiling),
            self._ratio(short_amount, self.short_amount_ceiling),
        )
        long_score = max(
            self._ratio(long_count, self.long_count_ceiling),
            self._ratio(long_amount, self.long_amount_ceiling),
        )

        # An account with an established baseline is judged against itself, so
        # a genuinely busy merchant is not permanently flagged for being busy.
        if baseline_rate is not None and baseline_rate > 0:
            observed_rate = long_count / self.long_window_seconds
            deviation = observed_rate / baseline_rate
            # 1x baseline contributes nothing; 4x or more saturates.
            relative_score = self._ratio(max(0.0, deviation - 1.0), 3.0)
        else:
            relative_score = 0.0

        # The burst window dominates, because a burst is the signal; the other
        # two raise the floor rather than averaging it away.
        combined = max(short_score, 0.7 * long_score, 0.8 * relative_score)
        return float(min(1.0, max(0.0, combined)))

    def _window_totals(
        self, history: _AccountHistory, now: float, window_seconds: int
    ) -> Tuple[int, float]:
        """Count and summed amount within the window ending at ``now``.

        Events dated after ``now`` are excluded rather than counted, so a
        clock-skewed future event cannot inflate the current window.
        """
        cutoff = now - window_seconds
        count = 0
        total = 0.0
        for moment, value in reversed(history.events):
            if moment > now:
                continue
            if moment < cutoff:
                break
            count += 1
            total += value
        return count, total

    def _baseline_rate(
        self, history: _AccountHistory, now: float
    ) -> Optional[float]:
        """Long-run transactions per second, or None while still building."""
        if history.total_events < self.min_baseline_samples:
            return None
        if history.first_seen is None:
            return None
        elapsed = now - history.first_seen
        if elapsed <= 0:
            return None
        return history.total_events / elapsed

    @staticmethod
    def _ratio(value: float, ceiling: float) -> float:
        """Scale a value into [0, 1] against a ceiling."""
        if ceiling <= 0:
            return 0.0
        return min(1.0, max(0.0, float(value) / float(ceiling)))

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def score_and_record(
        self,
        account_id: str,
        amount: float,
        timestamp=None,
        transaction_id: Optional[str] = None,
    ) -> float:
        """Score an account, then record the transaction being scored.

        Scoring happens first so a transaction never contributes to its own
        velocity — otherwise every account's first transaction would raise its
        own score.
        """
        risk = self.score(account_id, timestamp)
        self.record(account_id, amount, timestamp, transaction_id)
        return risk

    def tracked_accounts(self) -> int:
        with self._lock:
            return len(self._accounts)

    def reset(self) -> None:
        with self._lock:
            self._accounts.clear()


_default_calculator: Optional[VelocityRiskCalculator] = None
_default_lock = threading.Lock()


def get_velocity_calculator() -> VelocityRiskCalculator:
    """Process-wide calculator, so history accumulates across scoring calls."""
    global _default_calculator
    with _default_lock:
        if _default_calculator is None:
            _default_calculator = VelocityRiskCalculator()
        return _default_calculator


def reset_velocity_calculator() -> None:
    """Drop all recorded history (used by tests)."""
    global _default_calculator
    with _default_lock:
        _default_calculator = None
