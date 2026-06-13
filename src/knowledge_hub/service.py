"""
Fraud Investigation Knowledge Hub Service - Core business logic
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import (
    InvestigationTemplate,
    InvestigationRecord,
    KnowledgeEntry,
    EntityKnowledge,
    SearchResult,
    KnowledgeMetrics,
    InvestigationType,
    EntityType,
)
from .store import get_knowledge_hub_store, KnowledgeHubStore, reset_knowledge_hub_store


class KnowledgeHubService:
    """Core knowledge hub service."""

    def __init__(self, store: Optional[KnowledgeHubStore] = None):
        self._store = store or get_knowledge_hub_store()

    def create_template(
        self,
        name: str,
        description: str,
        investigation_type: InvestigationType,
        steps: List[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> InvestigationTemplate:
        """Create an investigation template."""
        template = InvestigationTemplate(
            name=name,
            description=description,
            investigation_type=investigation_type,
            steps=steps or [],
            **kwargs,
        )
        self._store.store_template(template)
        return template

    def get_template(self, template_id: str) -> Optional[InvestigationTemplate]:
        """Get template by ID."""
        return self._store.get_template(template_id)

    def get_templates(
        self, investigation_type: Optional[InvestigationType] = None
    ) -> List[InvestigationTemplate]:
        """Get templates."""
        if investigation_type:
            return self._store.get_templates_by_type(investigation_type)
        return self._store.get_all_templates()

    def create_investigation(
        self,
        title: str,
        description: str,
        investigation_type: InvestigationType,
        priority: str = "MEDIUM",
        **kwargs: Any,
    ) -> InvestigationRecord:
        """Create an investigation record."""
        record = InvestigationRecord(
            title=title,
            description=description,
            investigation_type=investigation_type,
            priority=priority,
            **kwargs,
        )
        self._store.store_record(record)
        return record

    def get_investigation(
        self, record_id: str
    ) -> Optional[InvestigationRecord]:
        """Get investigation by ID."""
        return self._store.get_record(record_id)

    def get_investigations(
        self,
        investigation_type: Optional[InvestigationType] = None,
    ) -> List[InvestigationRecord]:
        """Get investigations."""
        if investigation_type:
            return self._store.get_records_by_type(investigation_type)
        return self._store.get_all_records()

    def add_finding(
        self,
        record_id: str,
        finding: str,
    ) -> Optional[InvestigationRecord]:
        """Add a finding to an investigation."""
        record = self._store.get_record(record_id)
        if record:
            record.findings.append(finding)
            record.updated_at = None
            self._store.store_record(record)
        return record

    def link_investigation(
        self,
        record_id: str,
        linked_record_id: str,
    ) -> Optional[InvestigationRecord]:
        """Link two investigations."""
        record = self._store.get_record(record_id)
        if record:
            if linked_record_id not in record.linked_investigations:
                record.linked_investigations.append(linked_record_id)
            self._store.store_record(record)
        return record

    def add_knowledge(
        self,
        title: str,
        content: str,
        entity_type: EntityType,
        tags: List[str] = None,
        **kwargs: Any,
    ) -> KnowledgeEntry:
        """Add a knowledge entry."""
        entry = KnowledgeEntry(
            title=title,
            content=content,
            entity_type=entity_type,
            tags=tags or [],
            **kwargs,
        )
        self._store.store_knowledge(entry)
        return entry

    def get_knowledge(self, entry_id: str) -> Optional[KnowledgeEntry]:
        """Get knowledge entry by ID."""
        return self._store.get_knowledge(entry_id)

    def search_knowledge(
        self,
        query: str,
        entity_type: Optional[EntityType] = None,
    ) -> List[SearchResult]:
        """Search knowledge base."""
        results = self._store.search_knowledge(query)
        search_results = []

        for entry in results:
            if entity_type and entry.entity_type != entity_type:
                continue
            search_results.append(SearchResult(
                query=query,
                result_type="knowledge",
                title=entry.title,
                snippet=entry.content[:200],
                relevance_score=0.8,
                entity_id=entry.entry_id,
            ))
            self._store.store_search_result(search_results[-1])

        return search_results

    def add_entity(
        self,
        entity_type: EntityType,
        entity_value: str,
        attributes: Dict[str, Any] = None,
        **kwargs: Any,
    ) -> EntityKnowledge:
        """Add an entity to the knowledge graph."""
        entity = EntityKnowledge(
            entity_type=entity_type,
            entity_value=entity_value,
            attributes=attributes or {},
            **kwargs,
        )
        self._store.store_entity(entity)
        return entity

    def get_entity(self, entity_id: str) -> Optional[EntityKnowledge]:
        """Get entity by ID."""
        return self._store.get_entity(entity_id)

    def get_entities(
        self, entity_type: Optional[EntityType] = None
    ) -> List[EntityKnowledge]:
        """Get entities."""
        if entity_type:
            return self._store.get_entities_by_type(entity_type)
        return self._store.get_all_entities()

    def add_relationship(
        self,
        entity_id: str,
        related_entity_id: str,
        relationship_type: str,
    ) -> Optional[EntityKnowledge]:
        """Add a relationship between entities."""
        entity = self._store.get_entity(entity_id)
        if entity:
            entity.relationships.append({
                "related_entity_id": related_entity_id,
                "relationship_type": relationship_type,
            })
            self._store.store_entity(entity)
        return entity

    def get_metrics(self) -> KnowledgeMetrics:
        """Get knowledge hub metrics."""
        metrics_dict = self._store.get_metrics()

        records = self._store.get_all_records()
        recent = sorted(records, key=lambda x: x.updated_at, reverse=True)[:10]
        recent_activity = [
            {
                "record_id": r.record_id,
                "title": r.title,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in recent
        ]

        return KnowledgeMetrics(
            total_records=metrics_dict["total_records"],
            total_templates=metrics_dict["total_templates"],
            total_entities=metrics_dict["total_entities"],
            total_knowledge_entries=metrics_dict["total_knowledge_entries"],
            records_by_type=metrics_dict["records_by_type"],
            recent_activity=recent_activity,
        )

    def clear(self) -> None:
        """Clear all data."""
        reset_knowledge_hub_store()


_knowledge_hub_service: Optional[KnowledgeHubService] = None


def get_knowledge_hub_service() -> KnowledgeHubService:
    global _knowledge_hub_service
    if _knowledge_hub_service is None:
        _knowledge_hub_service = KnowledgeHubService()
    return _knowledge_hub_service


def reset_knowledge_hub_service() -> None:
    global _knowledge_hub_service
    _knowledge_hub_service = None
    reset_knowledge_hub_store()
