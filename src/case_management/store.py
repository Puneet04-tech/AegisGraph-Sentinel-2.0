"""Thread-safe in-memory store for Fraud Case Management.

Uses the project's LRUCache pattern (from src.api.main) extended with
a per-store threading.RLock for concurrent write safety.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Dict, List, Optional

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


class _LRUDict(OrderedDict):
    """Bounded LRU dictionary — same pattern as main.py's LRUCache."""

    def __init__(self, maxsize: int = 50_000):
        self.maxsize = maxsize
        super().__init__()

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self.maxsize:
            self.popitem(last=False)

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self.move_to_end(key)
        return value


class CaseStore:
    """Singleton in-memory store for all case management entities."""

    def __init__(self):
        self._lock = threading.RLock()
        self._cases: _LRUDict = _LRUDict(maxsize=50_000)
        self._comments: _LRUDict = _LRUDict(maxsize=200_000)
        self._evidence: _LRUDict = _LRUDict(maxsize=200_000)
        self._audit: Dict[str, List[CaseAuditEvent]] = {}  # case_id → list (append-only)

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
    ) -> FraudCase:
        with self._lock:
            case = FraudCase(
                transaction_id=transaction_id,
                risk_score=risk_score,
                decision=decision,
                priority=priority,
                tags=tags or [],
            )
            self._cases[case.case_id] = case
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
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[List[FraudCase], int]:
        """Return a paginated, filtered slice of cases.

        Returns (cases_page, total_count).
        """
        with self._lock:
            all_cases = list(self._cases.values())

        # Apply filters
        if status:
            all_cases = [c for c in all_cases if c.status == status]
        if priority:
            all_cases = [c for c in all_cases if c.priority == priority]
        if assigned_analyst is not None:
            all_cases = [c for c in all_cases if c.assigned_analyst == assigned_analyst]

        # Sort newest first
        all_cases.sort(key=lambda c: c.created_at, reverse=True)

        total = len(all_cases)
        start = (page - 1) * page_size
        end = start + page_size
        return all_cases[start:end], total

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
            case.assigned_analyst = analyst_id
            if case.status == CaseStatus.OPEN:
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
        with self._lock:
            cases = list(self._cases.values())
        total = len(cases)
        by_status = {s.value: 0 for s in CaseStatus}
        by_priority = {p.value: 0 for p in CasePriority}
        for c in cases:
            by_status[c.status.value] += 1
            by_priority[c.priority.value] += 1
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
        if case_id not in self._audit:
            self._audit[case_id] = []
        self._audit[case_id].append(event)


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
