"""
Model Registry
Central registry for AI models with versioning and governance.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .models import Model, ModelStatus, ModelRisk


class ModelRegistry:
    """Registry for managing AI models."""
    
    def __init__(self):
        self.models: Dict[str, Model] = {}
        self.versions: Dict[str, List[str]] = {}
    
    def register_model(
        self,
        name: str,
        version: str,
        model_type: str,
        framework: str = "",
        owner: str = "",
        description: str = "",
        risk_level: ModelRisk = ModelRisk.MEDIUM,
    ) -> str:
        """Register a new model."""
        model_id = str(uuid4())
        
        model = Model(
            model_id=model_id,
            name=name,
            version=version,
            model_type=model_type,
            framework=framework,
            owner=owner,
            description=description,
            risk_level=risk_level,
        )
        
        self.models[model_id] = model
        
        if name not in self.versions:
            self.versions[name] = []
        self.versions[name].append(model_id)
        
        return model_id
    
    def get_model(self, model_id: str) -> Optional[Model]:
        """Get a model by ID."""
        return self.models.get(model_id)
    
    def get_model_by_name(self, name: str, version: Optional[str] = None) -> Optional[Model]:
        """Get a model by name and optionally version."""
        model_ids = self.versions.get(name, [])
        
        if not model_ids:
            return None
        
        if version:
            for mid in model_ids:
                model = self.models.get(mid)
                if model and model.version == version:
                    return model
            return None
        
        return self.models.get(model_ids[-1])
    
    def update_model(
        self,
        model_id: str,
        status: Optional[ModelStatus] = None,
        metrics: Optional[Dict[str, float]] = None,
    ) -> bool:
        """Update a model."""
        model = self.models.get(model_id)
        if not model:
            return False
        
        if status:
            model.status = status
            if status == ModelStatus.PRODUCTION and not model.deployed_at:
                model.deployed_at = datetime.now(timezone.utc)
        
        if metrics:
            model.metrics.update(metrics)
        
        return True
    
    def deprecate_model(self, model_id: str) -> bool:
        """Deprecate a model."""
        model = self.models.get(model_id)
        if not model:
            return False
        
        model.status = ModelStatus.DEPRECATED
        return True
    
    def list_models(
        self,
        status: Optional[ModelStatus] = None,
        risk_level: Optional[ModelRisk] = None,
    ) -> List[Model]:
        """List models with optional filters."""
        models = list(self.models.values())
        
        if status:
            models = [m for m in models if m.status == status]
        
        if risk_level:
            models = [m for m in models if m.risk_level == risk_level]
        
        return models
    
    def get_model_versions(self, name: str) -> List[Model]:
        """Get all versions of a model."""
        model_ids = self.versions.get(name, [])
        return [self.models[mid] for mid in model_ids if mid in self.models]
    
    def get_production_models(self) -> List[Model]:
        """Get all production models."""
        return self.list_models(status=ModelStatus.PRODUCTION)
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        status_counts = {}
        for model in self.models.values():
            status_counts[model.status.value] = status_counts.get(model.status.value, 0) + 1
        
        return {
            "total_models": len(self.models),
            "total_unique_names": len(self.versions),
            "by_status": status_counts,
            "production_count": len(self.get_production_models()),
        }


def get_model_registry() -> ModelRegistry:
    """Get the global model registry instance."""
    global _model_registry
    if _model_registry is None:
        _model_registry = ModelRegistry()
    return _model_registry


_model_registry: Optional[ModelRegistry] = None