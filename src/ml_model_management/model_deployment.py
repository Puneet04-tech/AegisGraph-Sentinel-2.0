"""
Model Deployment Module.

Model deployment management, rollbacks, and monitoring.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    ModelDeployment,
    DeploymentStatus,
    ModelStatus,
)
from .store import MLModelStore, get_ml_store

logger = logging.getLogger(__name__)


class ModelDeploymentManager:
    """Model Deployment Manager for deployment lifecycle.
    
    Provides:
        - Deployment creation
        - Deployment execution
        - Rollback capabilities
        - Deployment monitoring
    """
    
    def __init__(self, store: Optional[MLModelStore] = None):
        """Initialize the deployment manager."""
        self._store = store or get_ml_store()
        self._module_id = "model_deployment"
    
    def create_deployment(
        self,
        model_id: str,
        environment: str,
        traffic_percentage: float = 100.0,
        config: Dict[str, Any] = None,
    ) -> ModelDeployment:
        """Create a new deployment."""
        logger.info(f"Creating deployment for model {model_id}")
        
        deployment = ModelDeployment(
            model_id=model_id,
            environment=environment,
            traffic_percentage=traffic_percentage,
            config=config or {},
        )
        
        self._store.store_deployment(deployment)
        return deployment
    
    def deploy(self, deployment_id: str) -> ModelDeployment:
        """Execute deployment."""
        deployment = self._store.get_deployment(deployment_id)
        if not deployment:
            raise ValueError(f"Deployment {deployment_id} not found")
        
        logger.info(f"Deploying {deployment_id}")
        
        # Update status
        deployment.status = DeploymentStatus.DEPLOYING
        self._store.store_deployment(deployment)
        
        # Simulate deployment (in reality, this would trigger actual deployment)
        success = random.random() > 0.05  # 95% success rate
        
        if success:
            deployment.status = DeploymentStatus.DEPLOYED
            deployment.deployed_at = datetime.now(timezone.utc)
            
            # Update model status
            model = self._store.get_model(deployment.model_id)
            if model:
                model.status = ModelStatus.PRODUCTION
                self._store.store_model(model)
        else:
            deployment.status = DeploymentStatus.FAILED
        
        self._store.store_deployment(deployment)
        return deployment
    
    def rollback(self, deployment_id: str) -> ModelDeployment:
        """Rollback a deployment."""
        deployment = self._store.get_deployment(deployment_id)
        if not deployment:
            raise ValueError(f"Deployment {deployment_id} not found")
        
        logger.info(f"Rolling back {deployment_id}")
        
        deployment.status = DeploymentStatus.ROLLING_BACK
        self._store.store_deployment(deployment)
        
        # Simulate rollback
        deployment.status = DeploymentStatus.DEPLOYED  # Previous state
        deployment.rolled_back_at = datetime.now(timezone.utc)
        self._store.store_deployment(deployment)
        
        return deployment
    
    def get_deployment(self, deployment_id: str) -> Optional[ModelDeployment]:
        """Get deployment by ID."""
        return self._store.get_deployment(deployment_id)
    
    def get_model_deployments(self, model_id: str) -> List[ModelDeployment]:
        """Get all deployments for a model."""
        return self._store.get_model_deployments(model_id)
    
    def get_active_deployments(self) -> List[ModelDeployment]:
        """Get all active deployments."""
        return self._store.get_active_deployments()
    
    def update_traffic(
        self,
        deployment_id: str,
        traffic_percentage: float,
    ) -> ModelDeployment:
        """Update deployment traffic percentage."""
        deployment = self._store.get_deployment(deployment_id)
        if not deployment:
            raise ValueError(f"Deployment {deployment_id} not found")
        
        deployment.traffic_percentage = traffic_percentage
        self._store.store_deployment(deployment)
        
        return deployment
    
    def canary_deploy(
        self,
        model_id: str,
        canary_percentage: float = 10.0,
    ) -> ModelDeployment:
        """Create a canary deployment."""
        logger.info(f"Creating canary deployment for {model_id} at {canary_percentage}%")
        
        deployment = self.create_deployment(
            model_id=model_id,
            environment="production",
            traffic_percentage=canary_percentage,
            config={"strategy": "canary"},
        )
        
        return self.deploy(deployment.deployment_id)


# Global singleton
_deployment_manager: Optional[ModelDeploymentManager] = None


def get_deployment_manager(store: Optional[MLModelStore] = None) -> ModelDeploymentManager:
    """Get or create the singleton ModelDeploymentManager instance."""
    global _deployment_manager
    
    if _deployment_manager is None:
        _deployment_manager = ModelDeploymentManager(store=store)
    return _deployment_manager