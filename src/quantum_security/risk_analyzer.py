"""
Quantum Risk Analyzer.

Analyzes cryptographic assets for quantum vulnerability.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import CryptoAlgorithm, CryptoAsset, QuantumRiskAssessment, RiskLevel
from .store import QuantumSecurityStore, get_quantum_store


class RiskAnalyzer:
    """Engine for quantum risk analysis."""

    def __init__(self, store: Optional[QuantumSecurityStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_quantum_store()
        self._quantum_resistant_algorithms = {
            CryptoAlgorithm.CRYSTALS_KYBER,
            CryptoAlgorithm.CRYSTALS_DILITHIUM,
            CryptoAlgorithm.FALCON,
            CryptoAlgorithm.SPHINCS_PLUS,
            CryptoAlgorithm.AES_256,
        }

    def assess_asset(self, asset_id: str) -> QuantumRiskAssessment:
        """Assess quantum risk for an asset."""
        asset = self.store.get_asset(asset_id)
        if not asset:
            raise ValueError(f"Asset not found: {asset_id}")
        
        is_vulnerable = not self._is_quantum_resistant(asset.algorithm)
        risk_score = self._calculate_risk_score(asset, is_vulnerable)
        risk_level = self._score_to_level(risk_score)
        
        assessment = QuantumRiskAssessment(
            assessment_id=str(uuid.uuid4()),
            asset_id=asset_id,
            algorithm=asset.algorithm,
            quantum_vulnerable=is_vulnerable,
            time_to_crack_hours=self._estimate_crack_time(asset) if is_vulnerable else None,
            risk_score=risk_score,
            risk_level=risk_level,
            recommended_action=self._get_recommendation(asset, is_vulnerable),
            estimated_migration_effort=self._estimate_migration_effort(asset),
        )
        
        self.store.store_assessment(assessment)
        
        self.store.log_audit(
            user_id="system",
            action="risk_assessed",
            resource_type="risk_assessment",
            resource_id=assessment.assessment_id,
            details={"asset_id": asset_id, "risk_level": risk_level.value},
        )
        
        return assessment

    def _is_quantum_resistant(self, algorithm: CryptoAlgorithm) -> bool:
        """Check if algorithm is quantum resistant."""
        return algorithm in self._quantum_resistant_algorithms

    def _calculate_risk_score(self, asset: CryptoAsset, is_vulnerable: bool) -> float:
        """Calculate risk score."""
        if not is_vulnerable:
            return 0.0
        
        base_score = 0.5
        
        if asset.algorithm in [CryptoAlgorithm.RSA_2048, CryptoAlgorithm.ECC_P256]:
            base_score += 0.2
        elif asset.algorithm in [CryptoAlgorithm.RSA_4096, CryptoAlgorithm.ECC_P384]:
            base_score += 0.15
        
        if asset.key_size < 2048:
            base_score += 0.15
        elif asset.key_size > 4096:
            base_score -= 0.1
        
        usage_risk = {
            "encryption": 0.15,
            "signing": 0.1,
            "authentication": 0.1,
            "key_exchange": 0.2,
        }
        base_score += usage_risk.get(asset.usage.lower(), 0.1)
        
        return min(1.0, base_score)

    def _estimate_crack_time(self, asset: CryptoAsset) -> float:
        """Estimate time to crack in hours (quantum computer)."""
        if asset.algorithm == CryptoAlgorithm.RSA_2048:
            return 8.0
        elif asset.algorithm == CryptoAlgorithm.RSA_4096:
            return 72.0
        elif asset.algorithm == CryptoAlgorithm.ECC_P256:
            return 4.0
        elif asset.algorithm == CryptoAlgorithm.ECC_P384:
            return 24.0
        return 24.0

    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert score to risk level."""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _get_recommendation(self, asset: CryptoAsset, is_vulnerable: bool) -> str:
        """Get recommendation for asset."""
        if not is_vulnerable:
            return "Continue using current algorithm - quantum resistant"
        
        recommendations = {
            CryptoAlgorithm.RSA_2048: "Migrate to CRYSTALS-Kyber for key encapsulation",
            CryptoAlgorithm.RSA_4096: "Migrate to CRYSTALS-Kyber for key encapsulation",
            CryptoAlgorithm.ECC_P256: "Migrate to CRYSTALS-Dilithium for signatures",
            CryptoAlgorithm.ECC_P384: "Migrate to Falcon for signatures",
        }
        
        return recommendations.get(
            asset.algorithm,
            "Plan migration to post-quantum algorithm",
        )

    def _estimate_migration_effort(self, asset: CryptoAsset) -> str:
        """Estimate migration effort."""
        if asset.algorithm in [CryptoAlgorithm.RSA_2048, CryptoAlgorithm.RSA_4096]:
            return "medium"
        elif asset.algorithm in [CryptoAlgorithm.ECC_P256, CryptoAlgorithm.ECC_P384]:
            return "low"
        return "high"

    def get_assessment(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get assessment for an asset."""
        assessment = self.store.get_assessment(asset_id)
        if not assessment:
            return None
        
        return {
            "assessment_id": assessment.assessment_id,
            "asset_id": assessment.asset_id,
            "algorithm": assessment.algorithm.value,
            "quantum_vulnerable": assessment.quantum_vulnerable,
            "time_to_crack_hours": assessment.time_to_crack_hours,
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level.value,
            "recommended_action": assessment.recommended_action,
            "estimated_migration_effort": assessment.estimated_migration_effort,
        }

    def get_high_risk_assets(self) -> List[Dict[str, Any]]:
        """Get high-risk assets."""
        assessments = self.store.get_high_risk_assessments()
        return [
            {
                "asset_id": a.asset_id,
                "algorithm": a.algorithm.value,
                "risk_level": a.risk_level.value,
                "risk_score": a.risk_score,
            }
            for a in assessments
        ]


# Singleton instance
_engine: Optional[RiskAnalyzer] = None


def get_risk_analyzer() -> RiskAnalyzer:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = RiskAnalyzer()
    return _engine


def reset_risk_analyzer() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None