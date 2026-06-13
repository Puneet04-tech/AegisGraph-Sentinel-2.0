"""
Security Exposure Management Platform

Enterprise-wide security exposure management for AegisGraph Sentinel 2.0.
Discovers, prioritizes, and monitors security exposures across the enterprise.
"""

from .models import (
    Exposure,
    AssetInventory,
    AttackSurface,
    RemediationTask,
    SecurityPosture,
    ExposureMetrics,
    ExposureSeverity,
    ExposureStatus,
    ExposureCategory,
    AssetType,
)
from .store import ExposureStore, get_exposure_store, reset_exposure_store
from .service import ExposureService, get_exposure_service, reset_exposure_service

__all__ = [
    "Exposure",
    "AssetInventory",
    "AttackSurface",
    "RemediationTask",
    "SecurityPosture",
    "ExposureMetrics",
    "ExposureSeverity",
    "ExposureStatus",
    "ExposureCategory",
    "AssetType",
    "ExposureStore",
    "get_exposure_store",
    "reset_exposure_store",
    "ExposureService",
    "get_exposure_service",
    "reset_exposure_service",
]
