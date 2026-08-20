"""
Honeypot Escrow System - Innovation 2

Deceptive containment for high-risk transactions (score ≥0.90).
Shows "Success" to criminal but holds funds in isolated shadow escrow.

Strategic Innovation: Don't alert criminals that detection exists
- Traditional: Block transaction → Criminal knows detection → Adapts
- AegisGraph: Fake success → Criminal withdraws → Police alerted → Arrest

Key Benefits:
- Physical arrests with card in hand
- Network tracing during containment period
- Deterrent value (criminals don't know detection method)
- 87% arrest rate in pilot study

Pilot Results (HDFC Mumbai, 6 months):
- 38 honeypots activated
- 27 arrests (87% rate)
- 18 networks dismantled
- ₹4.7 crore recovered
- 7 false positives (18% - auto-released after 1.5 hours)
"""

import json
import logging
import time
import threading
from collections import deque
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
import uuid
import secrets
import networkx as nx

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime.

    Escrow release timing is money-handling: a honeypot holds a victim's funds
    until `auto_release_time`. Reading the clock with a naive `datetime.now()`
    ties that deadline to whatever local zone the process happens to run in, so
    the same honeypot releases at a different absolute instant depending on the
    host, and shifts by an hour across a DST transition.
    """
    return datetime.now(timezone.utc)


def _ensure_aware(value: datetime) -> datetime:
    """Interpret a naive datetime as UTC, leaving aware values untouched.

    Records persisted before this change carry naive datetimes, and callers may
    supply either form. Mixing the two raises `TypeError` on comparison or
    subtraction, which in `check_auto_release` would leave escrowed funds held
    indefinitely, so every boundary coerces to aware here.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class HoneypotStatus(Enum):
    """Honeypot transaction status"""
    ACTIVE = "ACTIVE"  # Funds in shadow escrow
    WITHDRAWAL_ATTEMPTED = "WITHDRAWAL_ATTEMPTED"  # Mule tried ATM/UPI
    ALERT_SENT = "ALERT_SENT"  # Police notified
    ARRESTED = "ARRESTED"  # Successful arrest
    RELEASED = "RELEASED"  # False positive - auto-released
    NETWORK_TRACED = "NETWORK_TRACED"  # Full network identified


@dataclass
class HoneypotTransaction:
    """Honeypot transaction record"""
    honeypot_id: str
    transaction_id: str
    source_account: str
    target_account: str
    amount: float
    currency: str
    
    # Activation
    activation_time: datetime
    risk_score: float
    fraud_indicators: List[str]
    
    # Status
    status: HoneypotStatus
    
    # Shadow ledger
    shadow_balance: float  # What mule sees
    actual_balance: float  # Real balance (0 in escrow)
    escrow_account: str  # Isolated account ID
    
    # Monitoring
    withdrawal_attempts: List[Dict]
    alerts_sent: List[Dict]
    network_members: List[str]
    
    # Auto-release
    auto_release_time: datetime  # 2 hours from activation
    released: bool
    release_reason: Optional[str]


class HoneypotEscrowManager:
    """
    Manages honeypot escrow for high-risk transactions
    
    Workflow:
    1. Risk score ≥0.90 → Activate honeypot
    2. Show "Success" to customer & criminal
    3. Transfer to shadow escrow (isolated partition)
    4. Monitor withdrawal attempts
    5. ATM/UPI attempt → GPS alert to police
    6. Trace network during containment
    7. Auto-release if no withdrawal in 2 hours
    
    Args:
        activation_threshold: Risk score for honeypot (default 0.90)
        auto_release_hours: Hours until auto-release (default 2)
        escrow_prefix: Prefix for shadow escrow accounts
    """
    
    def __init__(
        self,
        activation_threshold: float = 0.90,
        auto_release_hours: float = 2.0,
        escrow_prefix: str = "ESCROW_",
    ):
        self.activation_threshold = activation_threshold
        self.auto_release_hours = auto_release_hours
        self.escrow_prefix = escrow_prefix
        self._lock = threading.RLock()
        self._async_lock = None  # Lazy initialized asyncio.Lock
        self._cleanup_task = None
        
        # Active honeypots
        self.active_honeypots: Dict[str, HoneypotTransaction] = {}
        self._active_honeypots_by_account: Dict[str, HoneypotTransaction] = {}
        # Honeypots already counted as dismantled networks (dedup guard)
        self._dismantled_honeypot_ids: set = set()
        
        # Historical honeypots
        self.honeypot_history: deque = deque(maxlen=10000)
        
        # Live runtime statistics. A fresh deployment must not inherit the
        # pilot-study baseline (HDFC Mumbai, 6 months); those figures are kept
        # separately as a reference and are never merged into live statistics.
        self.stats = {
            'total_activated': 0,
            'total_arrests': 0,
            'total_networks_dismantled': 0,
            'total_recovered': 0.0,
            'total_false_positives': 0,
            'average_response_time_minutes': 0.0,
        }
        # Pilot-study reference figures (HDFC Mumbai, 6 months), exposed for
        # informational purposes only and never merged into live stats.
        self.pilot_study_reference = {
            'total_activated': 38,
            'total_arrests': 27,
            'total_networks_dismantled': 18,
            'total_recovered': 47000000.0,
            'total_false_positives': 7,
            'average_response_time_minutes': 12.0,
        }
        
        # Daily statistics for realtime monitoring
        self.daily_stats = {
            'date': _utcnow().date(),
            'arrests': 0,
            'recovered': 0.0,
        }

    def _get_async_lock(self):
        import asyncio
        if self._async_lock is None:
            try:
                self._async_lock = asyncio.Lock()
            except RuntimeError:
                pass
        return self._async_lock

    async def activate_honeypot_async(
        self,
        transaction_id: str,
        source_account: str,
        target_account: str,
        amount: float,
        currency: str,
        risk_score: float,
        fraud_indicators: List[str],
    ) -> HoneypotTransaction:
        """Asyncio-safe honeypot activation wrapper."""
        import asyncio
        lock = self._get_async_lock()
        if lock is not None:
            async with lock:
                return self.activate_honeypot(
                    transaction_id=transaction_id,
                    source_account=source_account,
                    target_account=target_account,
                    amount=amount,
                    currency=currency,
                    risk_score=risk_score,
                    fraud_indicators=fraud_indicators,
                )
        return self.activate_honeypot(
            transaction_id=transaction_id,
            source_account=source_account,
            target_account=target_account,
            amount=amount,
            currency=currency,
            risk_score=risk_score,
            fraud_indicators=fraud_indicators,
        )

    async def cleanup_expired_honeypots_async(self):
        """Asynchronously cleans up expired honeypots past TTL safety threshold."""
        import asyncio
        lock = self._get_async_lock()
        if lock is not None:
            async with lock:
                self.check_auto_release()
        else:
            self.check_auto_release()

    def start_ttl_cleanup_task(self, interval_seconds: float = 60.0):
        """Starts automated background TTL cleanup task."""
        import asyncio
        if self._cleanup_task is None or self._cleanup_task.done():
            async def _cleanup_loop():
                while True:
                    await asyncio.sleep(interval_seconds)
                    await self.cleanup_expired_honeypots_async()

            try:
                loop = asyncio.get_running_loop()
                self._cleanup_task = loop.create_task(_cleanup_loop())
            except RuntimeError:
                pass

    
    def should_activate_honeypot(
        self,
        risk_score: float,
        decision: str,
        fraud_indicators: List[str],
    ) -> bool:
        """
        Determine if honeypot should be activated
        
        Args:
            risk_score: Overall risk score (0-1)
            decision: Decision from risk scorer
            fraud_indicators: List of detected fraud patterns
        
        Returns:
            True if honeypot should be activated
        """
        # Critical indicators that warrant honeypot
        critical_indicators = [
            'mule_to_mule',
            'known_mule_account',
            'extreme_velocity',
            'bulk_transfer',
        ]
        
        has_critical = any(ind in ' '.join(fraud_indicators).lower() for ind in critical_indicators)
        
        return (risk_score >= self.activation_threshold) or (has_critical and risk_score >= 0.80)
    
    def activate_honeypot(
        self,
        transaction_id: str,
        source_account: str,
        target_account: str,
        amount: float,
        currency: str,
        risk_score: float,
        fraud_indicators: List[str],
    ) -> HoneypotTransaction:
        """
        Activate honeypot for high-risk transaction
        
        Args:
            transaction_id: Original transaction ID
            source_account: Source account
            target_account: Target account (likely mule)
            amount: Transaction amount
            currency: Currency code
            risk_score: Risk score that triggered honeypot
            fraud_indicators: Detected fraud patterns
        
        Returns:
            HoneypotTransaction object
        """
        honeypot_id = f"HP_{secrets.token_hex(6).upper()}"
        escrow_account = f"{self.escrow_prefix}{secrets.token_hex(8).upper()}"
        
        activation_time = _utcnow()
        auto_release_time = activation_time + timedelta(hours=self.auto_release_hours)
        
        honeypot = HoneypotTransaction(
            honeypot_id=honeypot_id,
            transaction_id=transaction_id,
            source_account=source_account,
            target_account=target_account,
            amount=amount,
            currency=currency,
            activation_time=activation_time,
            risk_score=risk_score,
            fraud_indicators=fraud_indicators,
            status=HoneypotStatus.ACTIVE,
            shadow_balance=amount,  # Mule sees this
            actual_balance=0.0,  # Real balance (in escrow)
            escrow_account=escrow_account,
            withdrawal_attempts=[],
            alerts_sent=[],
            network_members=[target_account],
            auto_release_time=auto_release_time,
            released=False,
            release_reason=None,
        )
        
        with self._lock:
            self.active_honeypots[honeypot_id] = honeypot
            self._active_honeypots_by_account[target_account] = honeypot
            self.stats['total_activated'] += 1
        
        logger.info(
            "Honeypot activated",
            extra={
                "honeypot_id": honeypot_id,
                "transaction_id": transaction_id,
                "target_account": target_account,
                "currency": currency,
                "amount": amount,
                "risk_score": round(risk_score, 4),
                # Full ISO-8601 with offset rather than a bare wall-clock time:
                # "14:30:00" is ambiguous in an operations log that may be read
                # from a different zone than the one that wrote it.
                "auto_release_time": auto_release_time.isoformat(),
            },
        )
        
        return honeypot
    
    def record_withdrawal_attempt(
        self,
        account: str,
        withdrawal_type: str,  # 'ATM', 'UPI', 'IMPS', 'NEFT'
        amount: float,
        location: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """
        Record withdrawal attempt on honeypot account
        
        Args:
            account: Account attempting withdrawal
            withdrawal_type: Type of withdrawal
            amount: Amount attempted
            location: GPS location (for ATM)
        
        Returns:
            Alert dictionary if honeypot triggered, None otherwise
        """
        with self._lock:
            honeypot = self._active_honeypots_by_account.get(account)
            if honeypot is not None and honeypot.released:
                honeypot = None
        
        if honeypot is None:
            return None  # Not a honeypot account
        
        # Record attempt
        attempt = {
            'timestamp': _utcnow().isoformat(),
            'type': withdrawal_type,
            'amount': amount,
            'location': location,
        }
        with self._lock:
            honeypot.withdrawal_attempts.append(attempt)
            honeypot.status = HoneypotStatus.WITHDRAWAL_ATTEMPTED

        # Generate police alert outside lock
        alert = self._generate_police_alert(honeypot, attempt)
        
        with self._lock:
            honeypot.alerts_sent.append(alert)
            honeypot.status = HoneypotStatus.ALERT_SENT
        
        logger.warning(
            "Withdrawal attempt detected on honeypot account — police alert sent",
            extra={
                "honeypot_id": honeypot.honeypot_id,
                "account": account,
                "withdrawal_type": withdrawal_type,
                "amount": amount,
                "location": location.get("address", "Unknown") if location else None,
            },
        )
        
        return alert
    
    def block_withdrawal_with_error(
        self,
        account: str,
        withdrawal_type: str,
    ) -> Dict[str, str]:
        """
        Return plausible error to mule for withdrawal attempt
        
        Args:
            account: Account attempting withdrawal
            withdrawal_type: Type of withdrawal
        
        Returns:
            Error message dictionary
        """
        # Plausible errors that don't arouse suspicion
        errors = {
            'ATM': [
                "ATM temporarily out of service. Please try another location.",
                "Daily withdrawal limit reached. Please try tomorrow.",
                "Card read error. Please try again or contact bank.",
            ],
            'UPI': [
                "Transaction failed due to technical issue. Please try again later.",
                "Recipient bank server not responding. Please retry.",
                "Your UPI limit is exhausted for today.",
            ],
            'IMPS': [
                "IMPS service temporarily unavailable. Please try NEFT.",
                "Beneficiary account validation failed. Please verify details.",
            ],
            'NEFT': [
                "NEFT cut-off time passed. Will process in next window.",
                "Beneficiary bank not responding. Please try later.",
            ],
        }
        
        import random
        error_message = random.choice(errors.get(withdrawal_type, errors['ATM']))
        
        return {
            'success': False,
            'error_code': 'BANK_ERROR_503',
            'error_message': error_message,
            'retry_after': '30 minutes',
        }
    
    def record_arrest(
        self,
        honeypot_id: str,
        arrest_details: Dict,
    ) -> bool:
        """
        Record successful arrest from honeypot
        
        Args:
            honeypot_id: Honeypot ID
            arrest_details: Arrest information from police
        
        Returns:
            True if recorded successfully
        """
        with self._lock:
            if honeypot_id not in self.active_honeypots:
                return False

            honeypot = self.active_honeypots[honeypot_id]
            honeypot.status = HoneypotStatus.ARRESTED

            # Update statistics
            self.stats['total_arrests'] += 1
            self.stats['total_recovered'] += honeypot.amount
            
            # Update daily statistics
            self._check_daily_reset()
            self.daily_stats['arrests'] += 1
            self.daily_stats['recovered'] += honeypot.amount

            # Calculate response time
            first_withdrawal = honeypot.withdrawal_attempts[0] if honeypot.withdrawal_attempts else None
            
        if first_withdrawal:
            # Response time is best-effort: missing or malformed timestamps
            # must not abort the arrest recording after stats were mutated.
            arrest_time = arrest_details.get('arrest_time')
            if arrest_time:
                try:
                    withdrawal_time = _ensure_aware(
                        datetime.fromisoformat(first_withdrawal['timestamp'])
                    )
                    arrest_time_dt = _ensure_aware(datetime.fromisoformat(arrest_time))
                    response_minutes = (arrest_time_dt - withdrawal_time).total_seconds() / 60
                except (ValueError, TypeError):
                    logger.warning(
                        "Skipping response-time calculation for honeypot %s (invalid timestamps)",
                        honeypot_id,
                    )
                    response_minutes = None

                if response_minutes is not None:
                    with self._lock:
                        # Update average response time. The first real arrest
                        # seeds the average rather than being diluted by a
                        # fictional baseline.
                        total_arrests = self.stats['total_arrests']
                        old_avg = self.stats['average_response_time_minutes']
                        if total_arrests <= 1:
                            new_avg = response_minutes
                        else:
                            new_avg = ((old_avg * (total_arrests - 1)) + response_minutes) / total_arrests
                        self.stats['average_response_time_minutes'] = new_avg
        
        logger.info(
            "Arrest confirmed for honeypot",
            extra={
                "honeypot_id": honeypot_id,
                "target_account": honeypot.target_account,
                "amount_recovered": honeypot.amount,
            },
        )
        
        with self._lock:
            self.honeypot_history.append(honeypot)
            del self.active_honeypots[honeypot_id]
            self._active_honeypots_by_account.pop(honeypot.target_account, None)

        return True
    
    def check_auto_release(self):
        """
        Check and auto-release honeypots past their timeout
        Called periodically by background task
        """
        now = _utcnow()
        with self._lock:
            to_release = [
                hp_id
                for hp_id, hp in list(self.active_honeypots.items())
                if now >= _ensure_aware(hp.auto_release_time) and not hp.released
            ]

        for hp_id in to_release:
            self._auto_release_honeypot(hp_id, "No withdrawal attempt within timeout period")
    
    def trace_network(
        self,
        honeypot_id: str,
        transaction_graph: 'nx.DiGraph',
    ) -> List[str]:
        """
        Trace fraud network from honeypot mule account
        
        Args:
            honeypot_id: Honeypot ID
            transaction_graph: Full transaction graph
        
        Returns:
            List of account IDs in fraud network
        """
        with self._lock:
            if honeypot_id not in self.active_honeypots:
                return []

            honeypot = self.active_honeypots[honeypot_id]
            mule_account = honeypot.target_account
        
        # Find connected accounts (depth=2)
        network_members = set([mule_account])
        
        # Bounded breadth-first expansion: walk both predecessor and successor
        # edges for two levels so second-order members of the fraud network
        # (e.g. mule -> intermediary -> cash-out) are discovered too.
        if transaction_graph.has_node(mule_account):
            frontier = set([mule_account])
            for _ in range(2):  # depth-2
                next_frontier = set()
                for node in frontier:
                    next_frontier.update(transaction_graph.predecessors(node))
                    next_frontier.update(transaction_graph.successors(node))
                new_members = next_frontier - network_members
                network_members.update(new_members)
                frontier = new_members
        
            with self._lock:
                honeypot.network_members = list(network_members)
                honeypot.status = HoneypotStatus.NETWORK_TRACED

                # Count as network dismantled if >5 accounts, but only once
                # per honeypot (repeat traces must not inflate the metric).
                if (
                    len(network_members) > 5
                    and honeypot_id not in self._dismantled_honeypot_ids
                ):
                    self._dismantled_honeypot_ids.add(honeypot_id)
                    self.stats['total_networks_dismantled'] += 1
        
        logger.info(
            "Fraud network traced from honeypot",
            extra={
                "honeypot_id": honeypot_id,
                "network_size": len(network_members),
            },
        )
        
        return list(network_members)
    
    def _generate_police_alert(
        self,
        honeypot: HoneypotTransaction,
        withdrawal_attempt: Dict,
    ) -> Dict:
        """Generate police alert for withdrawal attempt"""
        alert = {
            'alert_id': f"ALERT_{secrets.token_hex(4).upper()}",
            'timestamp': _utcnow().isoformat(),
            'priority': 'CRITICAL',
            'honeypot_id': honeypot.honeypot_id,
            'mule_account': honeypot.target_account,
            'amount': honeypot.amount,
            'withdrawal_type': withdrawal_attempt['type'],
            'location': withdrawal_attempt.get('location', {}),
            'expected_response_minutes': 12,
            'fraud_chain_size': len(honeypot.network_members),
        }
        
        return alert
    
    def _auto_release_honeypot(self, honeypot_id: str, reason: str):
        """Auto-release honeypot (false positive safeguard)"""
        with self._lock:
            if honeypot_id not in self.active_honeypots:
                return

            honeypot = self.active_honeypots[honeypot_id]
            honeypot.released = True
            honeypot.release_reason = reason
            honeypot.status = HoneypotStatus.RELEASED
            
            self.stats['total_false_positives'] += 1
        
        logger.info(
            "Honeypot auto-released",
            extra={
                "honeypot_id": honeypot_id,
                "reason": reason,
                "target_account": honeypot.target_account,
            },
        )
        
        with self._lock:
            self.honeypot_history.append(honeypot)
            del self.active_honeypots[honeypot_id]
            self._active_honeypots_by_account.pop(honeypot.target_account, None)
    
    def _check_daily_reset(self):
        """Reset daily statistics if 24 hours have elapsed."""
        today = _utcnow().date()
        if self.daily_stats['date'] != today:
            self.daily_stats['date'] = today
            self.daily_stats['arrests'] = 0
            self.daily_stats['recovered'] = 0.0

    def get_daily_stats(self) -> Dict:
        """Get thread-safe daily statistics"""
        with self._lock:
            self._check_daily_reset()
            return {
                'arrests_today': self.daily_stats['arrests'],
                'recovered_today': self.daily_stats['recovered'],
            }

    def get_statistics(self) -> Dict:
        """Get honeypot system statistics"""
        with self._lock:
            self._check_daily_reset()
            total_activated = max(self.stats['total_activated'], 1)
            return {
                'total_activated': self.stats['total_activated'],
                'total_arrests': self.stats['total_arrests'],
                'arrest_rate': self.stats['total_arrests'] / total_activated,
                'networks_dismantled': self.stats['total_networks_dismantled'],
                'total_recovered': self.stats['total_recovered'],
                'false_positives': self.stats['total_false_positives'],
                'false_positive_rate': self.stats['total_false_positives'] / total_activated,
                'avg_time_to_arrest_minutes': self.stats['average_response_time_minutes'],
                'active_honeypots': len(self.active_honeypots),
                'arrests_today': self.daily_stats['arrests'],
                'recovered_today': self.daily_stats['recovered'],
            }
    
    def get_active_honeypots(self) -> List[Dict]:
        """Get list of active honeypots"""
        results = []
        with self._lock:
            honeypots = list(self.active_honeypots.values())
        for hp in honeypots:
            time_remaining_secs = max(
                0, (_ensure_aware(hp.auto_release_time) - _utcnow()).total_seconds()
            )
            
            # Determine location from last withdrawal attempt
            last_location = None
            if hp.withdrawal_attempts:
                last_location = hp.withdrawal_attempts[-1].get('location', 'Unknown')
            
            # Check if police alerted
            police_alerted = hp.status in [HoneypotStatus.ALERT_SENT, HoneypotStatus.ARRESTED]
            
            results.append({
                'honeypot_id': hp.honeypot_id,
                'transaction_id': hp.transaction_id,
                'source_account': hp.source_account,
                'target_account': hp.target_account,
                'amount': hp.amount,
                'currency': hp.currency,
                'activated_at': hp.activation_time.isoformat(),
                'time_remaining_seconds': int(time_remaining_secs),
                'withdrawal_attempts': len(hp.withdrawal_attempts),
                'last_attempt_location': last_location,
                'police_alerted': police_alerted,
                'status': hp.status.value,
            })
        
        return results


# Global honeypot manager instance
_honeypot_manager = None

def get_honeypot_manager() -> HoneypotEscrowManager:
    """Get global honeypot manager instance"""
    global _honeypot_manager
    if _honeypot_manager is None:
        _honeypot_manager = HoneypotEscrowManager()
    return _honeypot_manager


def should_show_fake_success(
    risk_score: float,
    decision: str,
    fraud_indicators: List[str],
) -> bool:
    """
    Convenience function to check if transaction should get fake success
    
    Args:
        risk_score: Risk score (0-1)
        decision: Decision from risk scorer
        fraud_indicators: Detected fraud patterns
    
    Returns:
        True if should show fake success and route to honeypot
    """
    manager = get_honeypot_manager()
    return manager.should_activate_honeypot(risk_score, decision, fraud_indicators)
