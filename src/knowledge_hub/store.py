"""
Fraud Investigation Knowledge Hub Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from .models import (
    InvestigationTemplate,
    InvestigationRecord,
    KnowledgeEntry,
    EntityKnowledge,
    SearchResult,
    InvestigationType,
    EntityType,
)


class KnowledgeHubStore:
    """Thread-safe storage for knowledge hub data."""

    def __init__(self):
        self._lock = Lock()
        self._templates: Dict[str, InvestigationTemplate] = {}
        self._records: Dict[str, InvestigationRecord] = {}
        self._knowledge: Dict[str, KnowledgeEntry] = {}
        self._entities: Dict[str, EntityKnowledge] = {}
        self._search_results: Dict[str, SearchResult] = {}

    def store_template(
        self, template: InvestigationTemplate
    ) -> InvestigationTemplate:
        with self._lock:
            self._templates[template.template_id] = template
        return template

    def get_template(self, template_id: str) -> Optional[InvestigationTemplate]:
        return self._templates.get(template_id)

    def get_templates_by_type(
        self, investigation_type: InvestigationType
    ) -> List[InvestigationTemplate]:
        return [
            t for t in self._templates.values()
            if t.investigation_type == investigation_type
        ]

    def get_all_templates(self) -> List[InvestigationTemplate]:
        return list(self._templates.values())

    def store_record(
        self, record: InvestigationRecord
    ) -> InvestigationRecord:
        with self._lock:
            self._records[record.record_id] = record
        return record

    def get_record(self, record_id: str) -> Optional[InvestigationRecord]:
        return self._records.get(record_id)

    def get_records_by_type(
        self, investigation_type: InvestigationType
    ) -> List[InvestigationRecord]:
        return [
            r for r in self._records.values()
            if r.investigation_type == investigation_type
        ]

    def get_all_records(self) -> List[InvestigationRecord]:
        return list(self._records.values())

    def store_knowledge(
        self, entry: KnowledgeEntry
    ) -> KnowledgeEntry:
        with self._lock:
            self._knowledge[entry.entry_id] = entry
        return entry

    def get_knowledge(self, entry_id: str) -> Optional[KnowledgeEntry]:
        return self._knowledge.get(entry_id)

    def search_knowledge(self, query: str) -> List[KnowledgeEntry]:
        results = []
        query_lower = query.lower()
        for entry in self._knowledge.values():
            if query_lower in entry.title.lower() or query_lower in entry.content.lower():
                results.append(entry)
        return results

    def get_all_knowledge(self) -> List[KnowledgeEntry]:
        return list(self._knowledge.values())

    def store_entity(
        self, entity: EntityKnowledge
    ) -> EntityKnowledge:
        with self._lock:
            self._entities[entity.entity_id] = entity
        return entity

    def get_entity(self, entity_id: str) -> Optional[EntityKnowledge]:
        return self._entities.get(entity_id)

    def get_entities_by_type(
        self, entity_type: EntityType
    ) -> List[EntityKnowledge]:
        return [
            e for e in self._entities.values()
            if e.entity_type == entity_type
        ]

    def get_all_entities(self) -> List[EntityKnowledge]:
        return list(self._entities.values())

    def store_search_result(
        self, result: SearchResult
    ) -> SearchResult:
        with self._lock:
            self._search_results[result.result_id] = result
        return result

    def get_metrics(self) -> Dict[str, Any]:
        records = list(self._records.values())
        type_counts: Dict[str, int] = {}

        for r in records:
            type_counts[r.investigation_type.value] = (
                type_counts.get(r.investigation_type.value, 0) + 1
            )

        return {
            "total_records": len(records),
            "total_templates": len(self._templates),
            "total_entities": len(self._entities),
            "total_knowledge_entries": len(self._knowledge),
            "records_by_type": type_counts,
        }


_knowledge_hub_store: Optional[KnowledgeHubStore] = None
_store_lock = Lock()


def get_knowledge_hub_store() -> KnowledgeHubStore:
    global _knowledge_hub_store
    with _store_lock:
        if _knowledge_hub_store is None:
            _knowledge_hub_store = KnowledgeHubStore()
        return _knowledge_hub_store


def reset_knowledge_hub_store() -> None:
    global _knowledge_hub_store
    with _store_lock:
        _knowledge_hub_store = KnowledgeHubStore()
