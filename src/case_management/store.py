"""Thread-safe in-memory store for Fraud Case Management.

Uses the project's LRUCache pattern (from src.api.main) extended with
a per-store threading.RLock for concurrent write safety.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections import Counter, OrderedDict
from itertools import islice
from typing import Dict, List, Optional, Set

from .models import (
    CaseAuditEvent,
    CaseComment,
    CaseEvidence,
    CasePriority,
    CaseStatus,
    FraudCase,
    EvidenceType,
    validate_status_transition,
)

logger = logging.getLogger(__name__)


class _LRUDict(OrderedDict):
    """Bounded LRU dictionary — same pattern as main.py's LRUCache.

    ``on_evict`` is called with the evicted key so the owner can reclaim
    anything keyed off it.  Without that hook the case map stayed bounded
    while the audit, comment, and evidence records belonging to evicted cases
    accumulated forever.
    """

    def __init__(self, maxsize: int = 50_000, on_evict=None):
        self.maxsize = maxsize
        self._on_evict = on_evict
        super().__init__()

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        while len(self) > self.maxsize:
            evicted_key, evicted_value = self.popitem(last=False)
            if self._on_evict is not None:
                self._on_evict(evicted_key, evicted_value)

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self.move_to_end(key)
        return value


class CaseStore:
    """Singleton in-memory store for all case management entities."""

    # Cap on audit events retained per case, so one pathological case cannot
    # grow without bound. Oldest events are dropped first.
    MAX_AUDIT_EVENTS_PER_CASE = 1_000

    def __init__(self):
        self._lock = threading.RLock()
        self._cases: _LRUDict = _LRUDict(maxsize=50_000, on_evict=self._on_case_evicted)
        self._comments: _LRUDict = _LRUDict(maxsize=200_000)
        self._evidence: _LRUDict = _LRUDict(maxsize=200_000)
        self._audit: Dict[str, List[CaseAuditEvent]] = {}  # case_id → list (append-only)

        # Secondary indexes. Listing with a filter reads the matching id set
        # instead of scanning every stored case.
        self._by_status: Dict[CaseStatus, Set[str]] = {s: set() for s in CaseStatus}
        self._by_priority: Dict[CasePriority, Set[str]] = {p: set() for p in CasePriority}
        self._by_analyst: Dict[Optional[str], Set[str]] = {}

        # Dashboard counters maintained on write. get_dashboard_stats() used to
        # recount every case on each poll, which is the same O(N) cost as the
        # list endpoint but applied continuously by auto-refresh.
        self._status_counts: Counter = Counter()
        self._priority_counts: Counter = Counter()

        from src.integrations.syslog.client import SyslogClient
        self.syslog_client = SyslogClient()

        # Syslog emission runs on a worker thread. It used to happen inline in
        # _append_audit() while self._lock was held, so every concurrent case
        # mutation serialised behind a socket setup and a DNS lookup — on the
        # event loop thread, since the route handlers are async.
        self._syslog_queue: "queue.Queue[dict]" = queue.Queue(maxsize=10_000)
        self._syslog_dropped = 0
        self._syslog_failures = 0
        self._syslog_worker = threading.Thread(
            target=self._drain_syslog_queue,
            name="case-store-syslog",
            daemon=True,
        )
        self._syslog_worker.start()

    # ------------------------------------------------------------------
    # Index and counter maintenance
    # ------------------------------------------------------------------

    def _index_case(self, case: FraudCase) -> None:
        """Add *case* to every secondary index. Caller must hold self._lock."""
        self._by_status[case.status].add(case.case_id)
        self._by_priority[case.priority].add(case.case_id)
        self._by_analyst.setdefault(case.assigned_analyst, set()).add(case.case_id)
        self._status_counts[case.status] += 1
        self._priority_counts[case.priority] += 1

    def _reindex_status(self, case_id: str, old: CaseStatus, new: CaseStatus) -> None:
        if old == new:
            return
        self._by_status[old].discard(case_id)
        self._by_status[new].add(case_id)
        self._status_counts[old] -= 1
        self._status_counts[new] += 1

    def _reindex_priority(self, case_id: str, old: CasePriority, new: CasePriority) -> None:
        if old == new:
            return
        self._by_priority[old].discard(case_id)
        self._by_priority[new].add(case_id)
        self._priority_counts[old] -= 1
        self._priority_counts[new] += 1

    def _reindex_analyst(
        self, case_id: str, old: Optional[str], new: Optional[str]
    ) -> None:
        if old == new:
            return
        bucket = self._by_analyst.get(old)
        if bucket is not None:
            bucket.discard(case_id)
            if not bucket:
                # Drop empty buckets, otherwise the map grows by one entry per
                # analyst id ever seen and never shrinks.
                del self._by_analyst[old]
        self._by_analyst.setdefault(new, set()).add(case_id)

    def _on_case_evicted(self, case_id: str, case: FraudCase) -> None:
        """Reclaim everything keyed off an evicted case.

        Called by _LRUDict when the case map is at capacity. The audit trail is
        described as append-only, which is true per case — but the cases it is
        keyed by are LRU-evicted, so without this the audit map grew with the
        total number of cases ever created rather than the number retained.
        """
        self._audit.pop(case_id, None)

        for comment_id in case.comment_ids:
            self._comments.pop(comment_id, None)
        for evidence_id in case.evidence_ids:
            self._evidence.pop(evidence_id, None)

        self._by_status[case.status].discard(case_id)
        self._by_priority[case.priority].discard(case_id)
        analyst_bucket = self._by_analyst.get(case.assigned_analyst)
        if analyst_bucket is not None:
            analyst_bucket.discard(case_id)
            if not analyst_bucket:
                del self._by_analyst[case.assigned_analyst]

        self._status_counts[case.status] -= 1
        self._priority_counts[case.priority] -= 1

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def create_case(
        self,
        transaction_id: str,
        risk_score: float,
        decision: str,
        analyst_id: str,
        priority: CasePriority = CasePriority.MEDIUM,
        tags: Optional[List[str]] = None,
        tenant_id: str = "default",
        workspace_id: Optional[str] = None,
    ) -> FraudCase:
        with self._lock:
            case = FraudCase(
                transaction_id=transaction_id,
                risk_score=risk_score,
                decision=decision,
                priority=priority,
                tags=tags or [],
                tenant_id=tenant_id,
                workspace_id=workspace_id,
            )
            self._cases[case.case_id] = case
            self._index_case(case)
            self._audit[case.case_id] = []
            self._append_audit(
                case_id=case.case_id,
                analyst_id=analyst_id,
                action="CASE_CREATED",
                new_value=f"priority={priority.value}, decision={decision}",
            )
            return case

    def get_case(self, case_id: str) -> Optional[FraudCase]:
        with self._lock:
            return self._cases.get(case_id)

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        priority: Optional[CasePriority] = None,
        assigned_analyst: Optional[str] = None,
        tenant_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[List[FraudCase], int]:
        """Return a paginated, filtered slice of cases.

        Returns (cases_page, total_count).

        Cases are stored in creation order, so "newest first" needs no sort —
        the store is walked backwards and stopped once the requested page is
        filled.  Filters resolve through the secondary indexes, so ``total`` is
        a set-size calculation rather than a scan.
        """
        with self._lock:
            candidate_ids = self._candidate_ids(status, priority, assigned_analyst)
            if tenant_id is not None:
                tenant_cases = {case_id for case_id, case in self._cases.items() if case.tenant_id == tenant_id}
                candidate_ids = tenant_cases if candidate_ids is None else candidate_ids & tenant_cases
            total = len(self._cases) if candidate_ids is None else len(candidate_ids)

            start = (page - 1) * page_size
            if start >= total:
                return [], total

            page_items = list(
                islice(self._iter_newest_first(candidate_ids), start, start + page_size)
            )
        return page_items, total

    def _candidate_ids(
        self,
        status: Optional[CaseStatus],
        priority: Optional[CasePriority],
        assigned_analyst: Optional[str],
    ) -> Optional[Set[str]]:
        """Intersect the requested filters into a candidate id set.

        Returns ``None`` when no filter was supplied, meaning "every case" —
        distinct from an empty set, which means "no case matches".
        Caller must hold ``self._lock``.
        """
        buckets: List[Set[str]] = []
        if status is not None:
            buckets.append(self._by_status.get(status, set()))
        if priority is not None:
            buckets.append(self._by_priority.get(priority, set()))
        if assigned_analyst is not None:
            buckets.append(self._by_analyst.get(assigned_analyst, set()))

        if not buckets:
            return None
        # Intersect smallest-first so the work is bounded by the most selective
        # filter rather than the largest one.
        buckets.sort(key=len)
        result = set(buckets[0])
        for bucket in buckets[1:]:
            result &= bucket
        return result

    def _iter_newest_first(self, candidate_ids: Optional[Set[str]]):
        """Yield cases newest-first, lazily.

        Cases are stored in creation order, so walking the map backwards is
        already "newest first" and needs no sort. Iteration is lazy, so a
        caller taking one page stops after that page.

        Ordering note: ``created_at`` has one-second resolution (see
        ``models._utcnow``), so cases created in the same second are tied. The
        previous implementation sorted descending with Python's stable sort,
        which left a tie group in *ascending* insertion order — so a burst of
        cases created in one second came back oldest-first within that second.
        This yields them newest-first instead, which is both what the endpoint
        claims to return and the only ordering that can be produced without
        buffering the whole tie group. Ordering across different seconds is
        unchanged.

        Caller must hold ``self._lock``.
        """
        for case_id in reversed(self._cases):
            if candidate_ids is not None and case_id not in candidate_ids:
                continue
            # OrderedDict.__getitem__ is used directly because _LRUDict
            # overrides __getitem__ to move_to_end, which would reorder the
            # store as a side effect of reading it.
            yield OrderedDict.__getitem__(self._cases, case_id)

    def update_status(
        self,
        case_id: str,
        new_status: CaseStatus,
        analyst_id: str,
    ) -> FraudCase:
        with self._lock:
            case = self._get_or_raise(case_id)
            validate_status_transition(case.status, new_status)
            old = case.status.value
            self._reindex_status(case_id, case.status, new_status)
            case.status = new_status
            case.touch()
            self._append_audit(case_id, analyst_id, "STATUS_CHANGED", old, new_status.value)
            return case

    def assign_analyst(
        self,
        case_id: str,
        analyst_id: str,
        assigning_analyst_id: str,
    ) -> FraudCase:
        with self._lock:
            case = self._get_or_raise(case_id)
            old = case.assigned_analyst or "unassigned"
            self._reindex_analyst(case_id, case.assigned_analyst, analyst_id)
            case.assigned_analyst = analyst_id
            if case.status == CaseStatus.OPEN:
                self._reindex_status(case_id, CaseStatus.OPEN, CaseStatus.IN_PROGRESS)
                case.status = CaseStatus.IN_PROGRESS
            case.touch()
            self._append_audit(
                case_id, assigning_analyst_id, "ANALYST_ASSIGNED", old, analyst_id
            )
            return case

    def claim_case(self, case_id: str, analyst_id: str) -> FraudCase:
        """Analyst claims an unassigned case for themselves."""
        with self._lock:
            case = self._get_or_raise(case_id)
            if case.assigned_analyst and case.assigned_analyst != analyst_id:
                raise ValueError(
                    f"Case {case_id} is already assigned to analyst '{case.assigned_analyst}'."
                )
            return self.assign_analyst(case_id, analyst_id, analyst_id)

    def update_priority(
        self,
        case_id: str,
        new_priority: CasePriority,
        analyst_id: str,
    ) -> FraudCase:
        with self._lock:
            case = self._get_or_raise(case_id)
            old = case.priority.value
            self._reindex_priority(case_id, case.priority, new_priority)
            case.priority = new_priority
            case.touch()
            self._append_audit(case_id, analyst_id, "PRIORITY_CHANGED", old, new_priority.value)
            return case

    # ------------------------------------------------------------------
    # Comments
    # ------------------------------------------------------------------

    def add_comment(
        self, case_id: str, analyst_id: str, text: str
    ) -> CaseComment:
        with self._lock:
            case = self._get_or_raise(case_id)
            comment = CaseComment(case_id=case_id, analyst_id=analyst_id, text=text)
            self._comments[comment.comment_id] = comment
            case.comment_ids.append(comment.comment_id)
            case.touch()
            self._append_audit(case_id, analyst_id, "COMMENT_ADDED", new_value=comment.comment_id)
            return comment

    def get_comments(self, case_id: str) -> List[CaseComment]:
        with self._lock:
            case = self._get_or_raise(case_id)
            return [self._comments[cid] for cid in case.comment_ids if cid in self._comments]

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def add_evidence(
        self,
        case_id: str,
        analyst_id: str,
        evidence_type: EvidenceType,
        description: str,
        reference_id: Optional[str] = None,
    ) -> CaseEvidence:
        with self._lock:
            case = self._get_or_raise(case_id)
            evidence = CaseEvidence(
                case_id=case_id,
                analyst_id=analyst_id,
                evidence_type=evidence_type,
                description=description,
                reference_id=reference_id,
            )
            self._evidence[evidence.evidence_id] = evidence
            case.evidence_ids.append(evidence.evidence_id)
            case.touch()
            self._append_audit(
                case_id, analyst_id, "EVIDENCE_ADDED",
                new_value=f"{evidence_type.value}:{evidence.evidence_id}",
            )
            return evidence

    def get_evidence(self, case_id: str) -> List[CaseEvidence]:
        with self._lock:
            case = self._get_or_raise(case_id)
            return [self._evidence[eid] for eid in case.evidence_ids if eid in self._evidence]

    # ------------------------------------------------------------------
    # Audit timeline
    # ------------------------------------------------------------------

    def get_timeline(self, case_id: str) -> List[CaseAuditEvent]:
        """Return the immutable chronological audit trail for a case."""
        with self._lock:
            self._get_or_raise(case_id)  # validate existence
            return list(self._audit.get(case_id, []))

    # ------------------------------------------------------------------
    # Dashboard metrics
    # ------------------------------------------------------------------

    def get_dashboard_stats(self) -> dict:
        """Return aggregate counts in O(1).

        Counters are maintained on write rather than recomputed here, because
        this endpoint is typically auto-refreshed and previously re-scanned
        every stored case on each poll.
        """
        with self._lock:
            total = len(self._cases)
            by_status = {s.value: self._status_counts.get(s, 0) for s in CaseStatus}
            by_priority = {
                p.value: self._priority_counts.get(p, 0) for p in CasePriority
            }
        return {
            "total_cases": total,
            "by_status": by_status,
            "by_priority": by_priority,
            "open_cases": by_status[CaseStatus.OPEN.value],
            "in_progress_cases": by_status[CaseStatus.IN_PROGRESS.value],
            "escalated_cases": by_status[CaseStatus.ESCALATED.value],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_raise(self, case_id: str) -> FraudCase:
        case = self._cases.get(case_id)
        if case is None:
            raise KeyError(f"Case '{case_id}' not found.")
        return case

    def _append_audit(
        self,
        case_id: str,
        analyst_id: str,
        action: str,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
    ) -> None:
        """Append an immutable audit event. Caller must hold self._lock."""
        event = CaseAuditEvent(
            case_id=case_id,
            analyst_id=analyst_id,
            action=action,
            old_value=old_value,
            new_value=new_value,
        )
        events = self._audit.setdefault(case_id, [])
        events.append(event)
        if len(events) > self.MAX_AUDIT_EVENTS_PER_CASE:
            # Drop oldest first so a single pathological case cannot grow
            # without bound while every other case is capped.
            del events[: len(events) - self.MAX_AUDIT_EVENTS_PER_CASE]

        # Classify severity from the action AND the affected values.
        # Checking the action name alone misses escalations/blocked
        # decisions carried in old_value/new_value (e.g. a STATUS_CHANGED
        # to ESCALATED or a decision of BLOCK) which then silently ship to
        # the compliance server as informational instead of warning.
        risk_marker = " ".join(part for part in (action, old_value, new_value) if part)
        severity = (
            4
            if any(
                kw in risk_marker
                for kw in ("FAILED", "REJECTED", "ESCALATED", "BLOCK", "BLOCKED")
            )
            else 6
        )

        # Hand the emission to the worker thread. Sending inline here would run
        # a socket setup and a DNS resolution while self._lock is held, on the
        # event loop thread, serialising every concurrent case mutation behind
        # it.
        self._enqueue_syslog(
            {
                "msg_id": action,
                "message": f"Case {case_id} audit event by analyst {analyst_id}",
                "severity": severity,
                "metadata": {
                    "case_id": case_id,
                    "analyst_id": analyst_id,
                    "action": action,
                    "old_value": old_value or "",
                    "new_value": new_value or "",
                },
            }
        )

    def _enqueue_syslog(self, payload: dict) -> None:
        """Queue a syslog emission, dropping the oldest entry when full.

        Dropping is preferable to blocking: a slow or unreachable syslog host
        must never make a case mutation wait.
        """
        try:
            self._syslog_queue.put_nowait(payload)
        except queue.Full:
            try:
                self._syslog_queue.get_nowait()
                self._syslog_queue.put_nowait(payload)
            except queue.Empty:  # pragma: no cover - racing drain
                pass
            self._syslog_dropped += 1
            if self._syslog_dropped % 100 == 1:
                # Rate-limited so a sustained outage does not itself flood the
                # log, but never fully silent — the previous bare `except:
                # pass` meant compliance logging could be entirely broken with
                # no signal at all.
                logger.warning(
                    "Syslog queue full; dropped %d audit events so far",
                    self._syslog_dropped,
                )

    def _drain_syslog_queue(self) -> None:
        """Worker loop emitting queued audit events off the request path."""
        while True:
            payload = self._syslog_queue.get()
            try:
                self.syslog_client.log_event(**payload)
            except Exception as exc:
                self._syslog_failures += 1
                if self._syslog_failures % 100 == 1:
                    logger.warning(
                        "Syslog emission failed (%d failures so far): %s",
                        self._syslog_failures,
                        exc,
                    )
            finally:
                self._syslog_queue.task_done()

    def flush_syslog(self, timeout: float = 5.0) -> bool:
        """Block until queued audit events have been emitted.

        Intended for tests and for graceful shutdown, so pending compliance
        events are not lost when the process exits.
        """
        deadline = threading.Event()
        waiter = threading.Thread(target=lambda: (self._syslog_queue.join(), deadline.set()))
        waiter.daemon = True
        waiter.start()
        return deadline.wait(timeout)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------
_store_instance: Optional[CaseStore] = None
_store_lock = threading.Lock()


def get_case_store() -> CaseStore:
    """Return the application-wide singleton CaseStore."""
    global _store_instance
    if _store_instance is None:
        with _store_lock:
            if _store_instance is None:
                _store_instance = CaseStore()
    return _store_instance

store_update_lock = False

