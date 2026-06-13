"""
Security Exposure Service - Core business logic
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

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
from .store import get_exposure_store, ExposureStore, reset_exposure_store


class ExposureService:
    """Core exposure management service."""

    def __init__(self, store: Optional[ExposureStore] = None):
        self._store = store or get_exposure_store()

    def discover_exposure(
        self,
        title: str,
        description: str,
        severity: ExposureSeverity,
        category: ExposureCategory,
        asset_id: str,
        asset_type: AssetType,
        **kwargs: Any,
    ) -> Exposure:
        """Discover and register a new exposure."""
        exposure = Exposure(
            title=title,
            description=description,
            severity=severity,
            category=category,
            asset_id=asset_id,
            asset_type=asset_type,
            exposure_score=self._calculate_exposure_score(severity, kwargs),
            **kwargs,
        )
        self._store.store_exposure(exposure)
        return exposure

    def _calculate_exposure_score(
        self,
        severity: ExposureSeverity,
        risk_factors: Dict[str, Any],
    ) -> float:
        """Calculate overall exposure score."""
        base_scores = {
            ExposureSeverity.CRITICAL: 1.0,
            ExposureSeverity.HIGH: 0.75,
            ExposureSeverity.MEDIUM: 0.5,
            ExposureSeverity.LOW: 0.25,
            ExposureSeverity.INFORMATIONAL: 0.1,
        }
        base_score = base_scores.get(severity, 0.5)
        return min(base_score + (len(risk_factors) * 0.05), 1.0)

    def get_exposure(self, exposure_id: str) -> Optional[Exposure]:
        """Get exposure by ID."""
        return self._store.get_exposure(exposure_id)

    def get_exposures_by_severity(
        self, severity: ExposureSeverity
    ) -> List[Exposure]:
        """Get exposures by severity level."""
        return self._store.get_exposures_by_severity(severity)

    def get_exposures_by_status(
        self, status: ExposureStatus
    ) -> List[Exposure]:
        """Get exposures by status."""
        return self._store.get_exposures_by_status(status)

    def get_exposures_by_asset(self, asset_id: str) -> List[Exposure]:
        """Get exposures for an asset."""
        return self._store.get_exposures_by_asset(asset_id)

    def update_exposure_status(
        self,
        exposure_id: str,
        status: ExposureStatus,
    ) -> Optional[Exposure]:
        """Update exposure status."""
        return self._store.update_exposure_status(exposure_id, status)

    def create_remediation_task(
        self,
        exposure_id: str,
        title: str,
        description: str,
        assigned_to: Optional[str] = None,
        priority: ExposureSeverity = ExposureSeverity.HIGH,
        **kwargs: Any,
    ) -> RemediationTask:
        """Create remediation task for an exposure."""
        task = RemediationTask(
            exposure_id=exposure_id,
            title=title,
            description=description,
            assigned_to=assigned_to,
            priority=priority,
            **kwargs,
        )
        self._store.store_remediation_task(task)
        return task

    def get_remediation_tasks(
        self, exposure_id: Optional[str] = None
    ) -> List[RemediationTask]:
        """Get remediation tasks."""
        if exposure_id:
            return self._store.get_tasks_by_exposure(exposure_id)
        return self._store.get_pending_tasks()

    def register_asset(
        self,
        name: str,
        asset_type: AssetType,
        owner: str,
        department: str,
        **kwargs: Any,
    ) -> AssetInventory:
        """Register an asset in the inventory."""
        asset = AssetInventory(
            name=name,
            asset_type=asset_type,
            owner=owner,
            department=department,
            **kwargs,
        )
        self._store.store_asset(asset)
        return asset

    def get_asset(self, asset_id: str) -> Optional[AssetInventory]:
        """Get asset by ID."""
        return self._store.get_asset(asset_id)

    def get_all_assets(self) -> List[AssetInventory]:
        """Get all assets."""
        return self._store.get_all_assets()

    def analyze_attack_surface(self, asset_id: str) -> AttackSurface:
        """Analyze attack surface for an asset."""
        exposures = self._store.get_exposures_by_asset(asset_id)

        entry_points = []
        exposed_services = []
        open_ports = []

        for exp in exposures:
            if exp.category in [
                ExposureCategory.NETWORK_EXPOSURE,
                ExposureCategory.API_EXPOSURE,
            ]:
                entry_points.append({
                    "exposure_id": exp.exposure_id,
                    "category": exp.category.value,
                    "severity": exp.severity.value,
                })
                exposed_services.append(exp.title)

        attack_vector_score = len(exposures) * 0.1
        blast_radius = sum(
            e.exposure_score for e in exposures
        ) / max(len(exposures), 1)

        surface = AttackSurface(
            asset_id=asset_id,
            entry_points=entry_points,
            exposed_services=exposed_services,
            open_ports=open_ports,
            attack_vector_score=min(attack_vector_score, 1.0),
            exposure_pathways=[],
            blast_radius=min(blast_radius, 1.0),
        )
        self._store.store_attack_surface(surface)
        return surface

    def assess_security_posture(self) -> SecurityPosture:
        """Assess overall security posture."""
        exposures = self._store.get_all_exposures()
        severity_counts: Dict[str, int] = {}

        for severity in ExposureSeverity:
            severity_counts[severity.value] = len([
                e for e in exposures if e.severity == severity
            ])

        remediated = len([
            e for e in exposures if e.status == ExposureStatus.REMEDIATED
        ])

        overall_score = 1.0 - (
            (severity_counts.get(ExposureSeverity.CRITICAL.value, 0) * 0.4 +
             severity_counts.get(ExposureSeverity.HIGH.value, 0) * 0.25 +
             severity_counts.get(ExposureSeverity.MEDIUM.value, 0) * 0.1) /
            max(len(exposures), 1)
        )

        posture = SecurityPosture(
            overall_score=max(0, min(overall_score, 1.0)),
            exposure_count_by_severity=severity_counts,
            total_exposures=len(exposures),
            remediated_exposures=remediated,
            exposure_trend="STABLE",
            risk_distribution={},
            compliance_score=0.85,
            recommendations=self._generate_recommendations(severity_counts),
        )
        self._store.store_posture(posture)
        return posture

    def _generate_recommendations(
        self, severity_counts: Dict[str, int]
    ) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        if severity_counts.get(ExposureSeverity.CRITICAL.value, 0) > 0:
            recommendations.append(
                "Immediate action required: Critical exposures detected"
            )
        if severity_counts.get(ExposureSeverity.HIGH.value, 0) > 5:
            recommendations.append(
                "Prioritize remediation of high-severity exposures"
            )
        if sum(severity_counts.values()) > 50:
            recommendations.append(
                "Consider implementing automated remediation workflows"
            )

        recommendations.append(
            "Regularly scan and update asset inventory"
        )
        recommendations.append(
            "Review and update exposure acceptance criteria"
        )

        return recommendations

    def get_metrics(self) -> ExposureMetrics:
        """Get exposure metrics."""
        exposures = self._store.get_all_exposures()
        severity_counts: Dict[str, int] = {}

        for severity in ExposureSeverity:
            severity_counts[severity.value] = len([
                e for e in exposures if e.severity == severity
            ])

        category_counts: Dict[str, int] = {}
        for exp in exposures:
            category_counts[exp.category.value] = (
                category_counts.get(exp.category.value, 0) + 1
            )

        top_assets = []
        top_categories = [
            {"category": k, "count": v}
            for k, v in sorted(
                category_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
        ]

        return ExposureMetrics(
            total_exposures=len(exposures),
            critical_exposures=severity_counts.get(ExposureSeverity.CRITICAL.value, 0),
            high_exposures=severity_counts.get(ExposureSeverity.HIGH.value, 0),
            medium_exposures=severity_counts.get(ExposureSeverity.MEDIUM.value, 0),
            low_exposures=severity_counts.get(ExposureSeverity.LOW.value, 0),
            remediated_exposures=severity_counts.get(ExposureStatus.REMEDIATED.value, 0),
            mtt_remediation_hours=24.0,
            mean_exposure_score=sum(
                e.exposure_score for e in exposures
            ) / max(len(exposures), 1),
            top_exposed_assets=top_assets,
            top_exposure_categories=top_categories,
            exposure_trend=[],
        )

    def clear(self) -> None:
        """Clear all data."""
        reset_exposure_store()


_exposure_service: Optional[ExposureService] = None
_service_lock = object()


def get_exposure_service() -> ExposureService:
    global _exposure_service
    if _exposure_service is None:
        _exposure_service = ExposureService()
    return _exposure_service


def reset_exposure_service() -> None:
    global _exposure_service
    _exposure_service = None
    reset_exposure_store()
