"""
Scenario Builder Engine.

Builds fraud simulation scenarios from various inputs.
"""

import random
from typing import Dict, List, Optional, Any
import logging

from .models import (
    SimulationScenario,
    SimulationType,
)
from .store import PredictiveStore, get_predictive_store

logger = logging.getLogger(__name__)


class ScenarioBuilder:
    """Scenario builder for creating fraud simulation scenarios.
    
    Provides:
        - Automated scenario generation
        - Custom scenario creation
        - Scenario templates
        - Parameter optimization
    """
    
    def __init__(self, store: Optional[PredictiveStore] = None):
        """Initialize the scenario builder.
        
        Args:
            store: Optional predictive store
        """
        self._store = store or get_predictive_store()
        
        # Scenario templates
        self._templates = self._load_templates()
    
    def _load_templates(self) -> Dict[SimulationType, Dict[str, Any]]:
        """Load scenario templates."""
        return {
            SimulationType.ACCOUNT_TAKEOVER: {
                "base_risk": 0.6,
                "compromised_rate": 0.35,
                "typical_entities": 10,
                "description": "Account takeover simulation",
            },
            SimulationType.FRAUD_RING_EXPANSION: {
                "expansion_rate": 0.25,
                "ring_size": 8,
                "typical_entities": 5,
                "description": "Fraud ring expansion simulation",
            },
            SimulationType.SYNTHETIC_IDENTITY: {
                "synthetic_rate": 0.2,
                "typical_entities": 15,
                "description": "Synthetic identity fraud simulation",
            },
            SimulationType.WALLET_LAUNDERING: {
                "hop_count": 5,
                "volume": 100000,
                "typical_entities": 6,
                "description": "Wallet laundering chain simulation",
            },
            SimulationType.CAMPAIGN_SPREAD: {
                "spread_rate": 0.3,
                "typical_entities": 20,
                "description": "Campaign spread simulation",
            },
            SimulationType.MULE_ACCOUNT_CREATION: {
                "creation_rate": 0.25,
                "typical_entities": 12,
                "description": "Mule account creation simulation",
            },
            SimulationType.NETWORK_INFILTRATION: {
                "infiltration_depth": 4,
                "typical_entities": 8,
                "description": "Network infiltration simulation",
            },
        }
    
    def build_scenario(
        self,
        simulation_type: SimulationType,
        source_entity_ids: List[str] = None,
        parameters: Dict[str, Any] = None,
        use_template: bool = True,
        created_by: str = "system",
    ) -> SimulationScenario:
        """Build a simulation scenario.
        
        Args:
            simulation_type: Type of fraud simulation
            source_entity_ids: Entities involved
            parameters: Custom parameters
            use_template: Whether to use template defaults
            created_by: Who created the scenario
            
        Returns:
            SimulationScenario ready for execution
        """
        # Get template defaults
        if use_template and simulation_type in self._templates:
            template = self._templates[simulation_type]
            default_params = template.copy()
            default_params.pop("description", None)
            default_params.pop("typical_entities", None)
        else:
            default_params = {}
        
        # Merge with custom parameters
        if parameters:
            default_params.update(parameters)
        
        # Generate entity IDs if not provided
        if not source_entity_ids:
            template = self._templates.get(simulation_type, {})
            entity_count = template.get("typical_entities", 5)
            source_entity_ids = [f"entity_{i}" for i in range(entity_count)]
        
        scenario = SimulationScenario(
            simulation_type=simulation_type,
            source_entity_ids=source_entity_ids,
            parameters=default_params,
            created_by=created_by,
            metadata={"use_template": use_template},
        )
        
        # Store scenario
        self._store.store_scenario(scenario)
        
        logger.info(f"Built scenario {scenario.scenario_id} of type {simulation_type.value}")
        return scenario
    
    def build_account_takeover_scenario(
        self,
        entity_ids: List[str],
        compromised_rate: float = 0.35,
        created_by: str = "system",
    ) -> SimulationScenario:
        """Build an account takeover scenario.
        
        Args:
            entity_ids: Entities to simulate
            compromised_rate: Expected compromise rate
            created_by: Who created the scenario
            
        Returns:
            SimulationScenario for account takeover
        """
        return self.build_scenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=entity_ids,
            parameters={"compromised_rate": compromised_rate, "base_risk": 0.6},
            created_by=created_by,
        )
    
    def build_fraud_ring_expansion_scenario(
        self,
        ring_entity_ids: List[str],
        expansion_rate: float = 0.25,
        ring_size: int = 8,
        created_by: str = "system",
    ) -> SimulationScenario:
        """Build a fraud ring expansion scenario.
        
        Args:
            ring_entity_ids: Existing ring members
            expansion_rate: Expected expansion rate
            ring_size: Target ring size
            created_by: Who created the scenario
            
        Returns:
            SimulationScenario for fraud ring expansion
        """
        return self.build_scenario(
            simulation_type=SimulationType.FRAUD_RING_EXPANSION,
            source_entity_ids=ring_entity_ids,
            parameters={"expansion_rate": expansion_rate, "ring_size": ring_size},
            created_by=created_by,
        )
    
    def build_synthetic_identity_scenario(
        self,
        entity_ids: List[str],
        synthetic_rate: float = 0.2,
        created_by: str = "system",
    ) -> SimulationScenario:
        """Build a synthetic identity fraud scenario."""
        return self.build_scenario(
            simulation_type=SimulationType.SYNTHETIC_IDENTITY,
            source_entity_ids=entity_ids,
            parameters={"synthetic_rate": synthetic_rate},
            created_by=created_by,
        )
    
    def build_wallet_laundering_scenario(
        self,
        wallet_ids: List[str],
        hop_count: int = 5,
        volume: float = 100000,
        created_by: str = "system",
    ) -> SimulationScenario:
        """Build a wallet laundering scenario."""
        return self.build_scenario(
            simulation_type=SimulationType.WALLET_LAUNDERING,
            source_entity_ids=wallet_ids,
            parameters={"hop_count": hop_count, "volume": volume},
            created_by=created_by,
        )
    
    def build_campaign_spread_scenario(
        self,
        campaign_entity_ids: List[str],
        spread_rate: float = 0.3,
        created_by: str = "system",
    ) -> SimulationScenario:
        """Build a campaign spread scenario."""
        return self.build_scenario(
            simulation_type=SimulationType.CAMPAIGN_SPREAD,
            source_entity_ids=campaign_entity_ids,
            parameters={"spread_rate": spread_rate},
            created_by=created_by,
        )
    
    def build_mule_account_scenario(
        self,
        entity_ids: List[str],
        creation_rate: float = 0.25,
        created_by: str = "system",
    ) -> SimulationScenario:
        """Build a mule account creation scenario."""
        return self.build_scenario(
            simulation_type=SimulationType.MULE_ACCOUNT_CREATION,
            source_entity_ids=entity_ids,
            parameters={"creation_rate": creation_rate},
            created_by=created_by,
        )
    
    def build_network_infiltration_scenario(
        self,
        entry_point_ids: List[str],
        infiltration_depth: int = 4,
        created_by: str = "system",
    ) -> SimulationScenario:
        """Build a network infiltration scenario."""
        return self.build_scenario(
            simulation_type=SimulationType.NETWORK_INFILTRATION,
            source_entity_ids=entry_point_ids,
            parameters={"infiltration_depth": infiltration_depth},
            created_by=created_by,
        )
    
    def get_available_types(self) -> List[SimulationType]:
        """Get all available simulation types."""
        return list(SimulationType)
    
    def get_template(self, simulation_type: SimulationType) -> Optional[Dict[str, Any]]:
        """Get the template for a simulation type."""
        return self._templates.get(simulation_type)


# Global singleton
_scenario_builder: Optional[ScenarioBuilder] = None


def get_scenario_builder(store: Optional[PredictiveStore] = None) -> ScenarioBuilder:
    """Get or create the singleton ScenarioBuilder instance."""
    global _scenario_builder
    
    if _scenario_builder is None:
        _scenario_builder = ScenarioBuilder(store=store)
    return _scenario_builder