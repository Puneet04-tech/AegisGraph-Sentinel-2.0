"""
AegisGraph Sentinel Omega Platform Module

The ultimate enterprise security operating system that unifies all
intelligence, security, fraud, compliance, governance, simulation,
prediction, and autonomous defense capabilities.

Unified Components:
    OmegaPlatform - Central orchestrator for all intelligence layers
    OmegaComponent - Platform component status
    OmegaDashboard - Unified dashboard data
    UnifiedIntelligence - Cross-layer intelligence
    CrossLayerAnalysis - Multi-layer analysis results

Intelligence Layers:
    FRAUD - Real-time fraud detection and prevention
    THREAT - Threat actor and campaign intelligence
    COMPLIANCE - Regulatory compliance monitoring
    DEFENSE - Autonomous defense and self-healing
    PREDICTIVE - Fraud forecasting and risk prediction
    REGULATORY - Regulatory change tracking
    GOVERNANCE - Executive oversight and reporting
    DIGITAL_TWIN - Environment simulation and testing

Usage:
    from src.omega_platform import (
        get_omega_platform,
        initialize_omega,
    )
    
    # Initialize the platform
    init_result = initialize_omega()
    
    # Get the platform instance
    omega = get_omega_platform()
    
    # Get unified dashboard
    dashboard = omega.get_unified_dashboard()
    
    # Perform cross-layer analysis
    analysis = omega.analyze_cross_layer("entity_123")
"""

from .omega_platform import (
    # Enums
    OmegaStatus,
    IntelligenceLayer,
    # Models
    OmegaComponent,
    OmegaDashboard,
    UnifiedIntelligence,
    CrossLayerAnalysis,
    # Platform
    OmegaPlatform,
    get_omega_platform,
    initialize_omega,
)


__all__ = [
    # Enums
    "OmegaStatus",
    "IntelligenceLayer",
    # Models
    "OmegaComponent",
    "OmegaDashboard",
    "UnifiedIntelligence",
    "CrossLayerAnalysis",
    # Platform
    "OmegaPlatform",
    "get_omega_platform",
    "initialize_omega",
]