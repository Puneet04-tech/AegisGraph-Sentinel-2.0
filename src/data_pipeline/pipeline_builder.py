"""
Pipeline Builder Module.

Pipeline construction, stage configuration, and template management.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    Pipeline,
    PipelineStatus,
    DataTransformation,
    TransformType,
)
from .store import PipelineStore, get_pipeline_store

logger = logging.getLogger(__name__)


class PipelineBuilder:
    """Pipeline Builder for constructing data pipelines.
    
    Provides:
        - Pipeline creation
        - Stage configuration
        - Template management
        - Connection management
    """
    
    def __init__(self, store: Optional[PipelineStore] = None):
        """Initialize the pipeline builder."""
        self._store = store or get_pipeline_store()
        self._module_id = "pipeline_builder"
    
    def create_pipeline(
        self,
        name: str,
        description: str,
        stages: List[Dict[str, Any]] = None,
        schedule: str = None,
        tags: List[str] = None,
    ) -> Pipeline:
        """Create a new pipeline."""
        logger.info(f"Creating pipeline: {name}")
        
        pipeline = Pipeline(
            name=name,
            description=description,
            stages=stages or [],
            schedule=schedule,
            tags=tags or [],
        )
        
        self._store.store_pipeline(pipeline)
        return pipeline
    
    def add_stage(
        self,
        pipeline_id: str,
        stage_type: str,
        config: Dict[str, Any],
        order: int = None,
    ) -> Pipeline:
        """Add a stage to a pipeline."""
        pipeline = self._store.get_pipeline(pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline {pipeline_id} not found")
        
        stage = {
            "type": stage_type,
            "config": config,
            "order": order or len(pipeline.stages),
        }
        
        pipeline.stages.append(stage)
        pipeline.updated_at = datetime.now(timezone.utc)
        self._store.store_pipeline(pipeline)
        
        return pipeline
    
    def remove_stage(
        self,
        pipeline_id: str,
        stage_order: int,
    ) -> Pipeline:
        """Remove a stage from a pipeline."""
        pipeline = self._store.get_pipeline(pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline {pipeline_id} not found")
        
        pipeline.stages = [s for s in pipeline.stages if s.get("order") != stage_order]
        pipeline.updated_at = datetime.now(timezone.utc)
        self._store.store_pipeline(pipeline)
        
        return pipeline
    
    def update_pipeline_status(
        self,
        pipeline_id: str,
        status: PipelineStatus,
    ) -> Pipeline:
        """Update pipeline status."""
        pipeline = self._store.get_pipeline(pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline {pipeline_id} not found")
        
        pipeline.status = status
        pipeline.updated_at = datetime.now(timezone.utc)
        self._store.store_pipeline(pipeline)
        
        return pipeline
    
    def get_pipeline(self, pipeline_id: str) -> Optional[Pipeline]:
        """Get pipeline by ID."""
        return self._store.get_pipeline(pipeline_id)
    
    def list_pipelines(
        self,
        status: PipelineStatus = None,
        tags: List[str] = None,
    ) -> List[Pipeline]:
        """List pipelines with filters."""
        pipelines = self._store.get_all_pipelines()
        
        if status:
            pipelines = [p for p in pipelines if p.status == status]
        if tags:
            pipelines = [p for p in pipelines if any(tag in p.tags for tag in tags)]
        
        return pipelines
    
    def clone_pipeline(
        self,
        pipeline_id: str,
        new_name: str,
    ) -> Pipeline:
        """Clone an existing pipeline."""
        pipeline = self._store.get_pipeline(pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline {pipeline_id} not found")
        
        new_pipeline = Pipeline(
            name=new_name,
            description=pipeline.description,
            stages=pipeline.stages.copy(),
            schedule=pipeline.schedule,
            timeout_seconds=pipeline.timeout_seconds,
            retry_count=pipeline.retry_count,
            tags=pipeline.tags.copy(),
        )
        
        self._store.store_pipeline(new_pipeline)
        return new_pipeline
    
    def get_pipeline_templates(self) -> List[Dict[str, Any]]:
        """Get pipeline templates."""
        return [
            {
                "id": "etl_basic",
                "name": "Basic ETL",
                "description": "Extract, Transform, Load basic pipeline",
                "stages": [
                    {"type": "source", "config": {"type": "database"}},
                    {"type": "transform", "config": {"type": "map"}},
                    {"type": "load", "config": {"type": "database"}},
                ],
            },
            {
                "id": "etl_full",
                "name": "Full ETL with Validation",
                "description": "Complete ETL pipeline with validation",
                "stages": [
                    {"type": "source", "config": {"type": "database"}},
                    {"type": "validate", "config": {"strict": True}},
                    {"type": "transform", "config": {"type": "map"}},
                    {"type": "transform", "config": {"type": "filter"}},
                    {"type": "load", "config": {"type": "database"}},
                ],
            },
            {
                "id": "api_ingest",
                "name": "API Data Ingestion",
                "description": "Ingest data from API sources",
                "stages": [
                    {"type": "source", "config": {"type": "api"}},
                    {"type": "transform", "config": {"type": "map"}},
                    {"type": "load", "config": {"type": "database"}},
                ],
            },
        ]


# Global singleton
_pipeline_builder: Optional[PipelineBuilder] = None


def get_pipeline_builder(store: Optional[PipelineStore] = None) -> PipelineBuilder:
    """Get or create the singleton PipelineBuilder instance."""
    global _pipeline_builder
    
    if _pipeline_builder is None:
        _pipeline_builder = PipelineBuilder(store=store)
    return _pipeline_builder