"""
Model Registry Module.

Model versioning, metadata management, and lineage tracking.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    MLModel,
    ModelType,
    ModelStatus,
)
from .store import MLModelStore, get_ml_store

logger = logging.getLogger(__name__)


class ModelRegistry:
    """Model Registry for version control and metadata management.
    
    Provides:
        - Model registration
        - Version management
        - Metadata tracking
        - Lineage tracking
    """
    
    def __init__(self, store: Optional[MLModelStore] = None):
        """Initialize the model registry."""
        self._store = store or get_ml_store()
        self._module_id = "model_registry"
    
    def register_model(
        self,
        name: str,
        version: str,
        model_type: ModelType,
        description: str,
        framework: str,
        parameters: Dict[str, Any] = None,
        metrics: Dict[str, float] = None,
        tags: List[str] = None,
        parent_model_id: str = None,
    ) -> MLModel:
        """Register a new model."""
        logger.info(f"Registering model: {name} v{version}")
        
        model = MLModel(
            name=name,
            version=version,
            model_type=model_type,
            description=description,
            framework=framework,
            parameters=parameters or {},
            metrics=metrics or {},
            status=ModelStatus.REGISTERED,
            tags=tags or [],
            parent_model_id=parent_model_id,
        )
        
        self._store.store_model(model)
        return model
    
    def get_model(self, model_id: str) -> Optional[MLModel]:
        """Get model by ID."""
        return self._store.get_model(model_id)
    
    def list_models(
        self,
        model_type: ModelType = None,
        status: ModelStatus = None,
        tags: List[str] = None,
    ) -> List[MLModel]:
        """List models with filters."""
        models = self._store.get_all_models()
        
        if model_type:
            models = [m for m in models if m.model_type == model_type]
        if status:
            models = [m for m in models if m.status == status]
        if tags:
            models = [m for m in models if any(tag in m.tags for tag in tags)]
        
        return models
    
    def update_model_metrics(
        self,
        model_id: str,
        metrics: Dict[str, float],
    ) -> MLModel:
        """Update model metrics."""
        model = self._store.get_model(model_id)
        if not model:
            raise ValueError(f"Model {model_id} not found")
        
        model.metrics.update(metrics)
        model.updated_at = datetime.now(timezone.utc)
        self._store.store_model(model)
        
        return model
    
    def update_model_status(
        self,
        model_id: str,
        status: ModelStatus,
    ) -> MLModel:
        """Update model status."""
        model = self._store.get_model(model_id)
        if not model:
            raise ValueError(f"Model {model_id} not found")
        
        model.status = status
        model.updated_at = datetime.now(timezone.utc)
        self._store.store_model(model)
        
        return model
    
    def get_model_lineage(self, model_id: str) -> Dict[str, Any]:
        """Get model lineage (ancestors and descendants)."""
        model = self._store.get_model(model_id)
        if not model:
            return {"error": "Model not found"}
        
        # Get ancestors
        ancestors = []
        current = model
        while current.parent_model_id:
            parent = self._store.get_model(current.parent_model_id)
            if parent:
                ancestors.append({
                    "model_id": parent.model_id,
                    "name": parent.name,
                    "version": parent.version,
                })
                current = parent
            else:
                break
        
        # Get descendants
        descendants = []
        for m in self._store.get_all_models():
            if m.parent_model_id == model_id:
                descendants.append({
                    "model_id": m.model_id,
                    "name": m.name,
                    "version": m.version,
                })
        
        return {
            "model_id": model_id,
            "name": model.name,
            "version": model.version,
            "ancestors": ancestors,
            "descendants": descendants,
        }
    
    def compare_models(
        self,
        model_a_id: str,
        model_b_id: str,
    ) -> Dict[str, Any]:
        """Compare two models."""
        model_a = self._store.get_model(model_a_id)
        model_b = self._store.get_model(model_b_id)
        
        if not model_a or not model_b:
            return {"error": "Model not found"}
        
        # Compare metrics
        all_metrics = set(model_a.metrics.keys()) | set(model_b.metrics.keys())
        metric_comparison = {}
        
        for metric in all_metrics:
            val_a = model_a.metrics.get(metric, 0)
            val_b = model_b.metrics.get(metric, 0)
            diff = val_b - val_a
            metric_comparison[metric] = {
                "model_a": val_a,
                "model_b": val_b,
                "difference": diff,
                "winner": "A" if diff < 0 else "B" if diff > 0 else "TIE",
            }
        
        return {
            "model_a": {"id": model_a.model_id, "name": model_a.name, "version": model_a.version},
            "model_b": {"id": model_b.model_id, "name": model_b.name, "version": model_b.version},
            "metric_comparison": metric_comparison,
        }


# Global singleton
_model_registry: Optional[ModelRegistry] = None


def get_model_registry(store: Optional[MLModelStore] = None) -> ModelRegistry:
    """Get or create the singleton ModelRegistry instance."""
    global _model_registry
    
    if _model_registry is None:
        _model_registry = ModelRegistry(store=store)
    return _model_registry