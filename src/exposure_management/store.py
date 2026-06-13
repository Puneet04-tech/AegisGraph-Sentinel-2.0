"""
Security Exposure Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Dict, List, Optional, Any

from .models import (
    Exposure,
    AssetInventory,
    AttackSurface,
    RemediationTask,
    SecurityPosture,
    ExposureSeverity,
    ExposureStatus,
)


class ExposureStore:
    """Thread-safe storage for exposure data."""

    def __init__(self):
        self._lock = Lock()
        self._exposures: Dict[str, Exposure] = {}
        self._assets: Dict[str, AssetInventory] = {}
        self._attack_surfaces: Dict[str, AttackSurface] = {}
        self._remediation_tasks: Dict[str, RemediationTask] = {}
        self._postures: Dict[str, SecurityPosture] = {}

    def store_exposure(self, exposure: Exposure) -> Exposure:
        with self._lock:
            self._exposures[exposure.exposure_id] = exposure
        return exposure

    def get_exposure(self, exposure_id: str) -> Optional[Exposure]:
        return self._exposures.get(exposure_id)

    def get_exposures_by_severity(
        self, severity: ExposureSeverity
    ) -> List[Exposure]:
        return [
            e for e in self._exposures.values()
            if e.severity == severity
        ]

    def get_exposures_by_status(
        self, status: ExposureStatus
    ) -> List[Exposure]:
        return [
            e for e in self._exposures.values()
            if e.status == status
        ]

    def get_exposures_by_asset(self, asset_id: str) -> List[Exposure]:
        return [
            e for e in self._exposures.values()
            if e.asset_id == asset_id or asset_id in e.affected_assets
        ]

    def get_all_exposures(self) -> List[Exposure]:
        return list(self._exposures.values())

    def update_exposure_status(
        self, exposure_id: str, status: ExposureStatus
    ) -> Optional[Exposure]:
        with self._lock:
            if exposure_id in self._exposures:
                self._exposures[exposure_id].status = status
                return self._exposures[exposure_id]
        return None

    def store_asset(self, asset: AssetInventory) -> AssetInventory:
        with self._lock:
            self._assets[asset.asset_id] = asset
        return asset

    def get_asset(self, asset_id: str) -> Optional[AssetInventory]:
        return self._assets.get(asset_id)

    def get_all_assets(self) -> List[AssetInventory]:
        return list(self._assets.values())

    def store_attack_surface(self, surface: AttackSurface) -> AttackSurface:
        with self._lock:
            self._attack_surfaces[surface.surface_id] = surface
        return surface

    def get_attack_surface(self, asset_id: str) -> Optional[AttackSurface]:
        for surface in self._attack_surfaces.values():
            if surface.asset_id == asset_id:
                return surface
        return None

    def store_remediation_task(
        self, task: RemediationTask
    ) -> RemediationTask:
        with self._lock:
            self._remediation_tasks[task.task_id] = task
        return task

    def get_remediation_task(
        self, task_id: str
    ) -> Optional[RemediationTask]:
        return self._remediation_tasks.get(task_id)

    def get_tasks_by_exposure(
        self, exposure_id: str
    ) -> List[RemediationTask]:
        return [
            t for t in self._remediation_tasks.values()
            if t.exposure_id == exposure_id
        ]

    def get_pending_tasks(self) -> List[RemediationTask]:
        return [
            t for t in self._remediation_tasks.values()
            if t.status == "PENDING"
        ]

    def store_posture(self, posture: SecurityPosture) -> SecurityPosture:
        with self._lock:
            self._postures[posture.posture_id] = posture
        return posture

    def get_latest_posture(self) -> Optional[SecurityPosture]:
        if self._postures:
            return list(self._postures.values())[-1]
        return None

    def get_metrics(self) -> Dict[str, Any]:
        exposures = list(self._exposures.values())
        return {
            "total_exposures": len(exposures),
            "critical_exposures": len([
                e for e in exposures if e.severity == ExposureSeverity.CRITICAL
            ]),
            "high_exposures": len([
                e for e in exposures if e.severity == ExposureSeverity.HIGH
            ]),
            "medium_exposures": len([
                e for e in exposures if e.severity == ExposureSeverity.MEDIUM
            ]),
            "low_exposures": len([
                e for e in exposures if e.severity == ExposureSeverity.LOW
            ]),
            "remediated_exposures": len([
                e for e in exposures if e.status == ExposureStatus.REMEDIATED
            ]),
            "open_exposures": len([
                e for e in exposures if e.status == ExposureStatus.OPEN
            ]),
            "total_assets": len(self._assets),
            "total_tasks": len(self._remediation_tasks),
        }


_exposure_store: Optional[ExposureStore] = None
_store_lock = Lock()


def get_exposure_store() -> ExposureStore:
    global _exposure_store
    with _store_lock:
        if _exposure_store is None:
            _exposure_store = ExposureStore()
        return _exposure_store


def reset_exposure_store() -> None:
    global _exposure_store
    with _store_lock:
        _exposure_store = ExposureStore()
