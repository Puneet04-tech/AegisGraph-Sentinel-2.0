"""
Quantum Security Service.

Main service for quantum-safe cryptography platform.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AuditEvent,
    CryptoAlgorithm,
)
from .store import (
    QuantumSecurityStore,
    get_quantum_store,
    reset_quantum_store,
)
from .crypto_inventory import (
    CryptoInventoryEngine,
    get_crypto_inventory_engine,
    reset_crypto_inventory_engine,
)
from .risk_analyzer import (
    RiskAnalyzer,
    get_risk_analyzer,
    reset_risk_analyzer,
)
from .key_manager import (
    KeyLifecycleManager,
    get_key_manager,
    reset_key_manager,
)
from .certificate_engine import (
    CertificateIntelligenceEngine,
    get_certificate_engine,
    reset_certificate_engine,
)
from .governance import (
    GovernanceEngine,
    get_governance_engine,
    reset_governance_engine,
)
from .compliance import (
    ComplianceEngine,
    get_compliance_engine,
    reset_compliance_engine,
)


class QuantumSecurityService:
    """Main service for quantum security."""

    def __init__(self, store: Optional[QuantumSecurityStore] = None) -> None:
        """Initialize the service."""
        self.store = store or get_quantum_store()
        self.inventory = get_crypto_inventory_engine()
        self.risk = get_risk_analyzer()
        self.keys = get_key_manager()
        self.certificates = get_certificate_engine()
        self.governance = get_governance_engine()
        self.compliance = get_compliance_engine()

    async def register_asset(
        self,
        name: str,
        algorithm: str,
        crypto_type: str,
        key_size: int,
        usage: str,
        system: str,
        location: str,
        owner: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a crypto asset."""
        quantum_resistant = CryptoAlgorithm(algorithm) in {
            CryptoAlgorithm.CRYSTALS_KYBER,
            CryptoAlgorithm.CRYSTALS_DILITHIUM,
            CryptoAlgorithm.FALCON,
            CryptoAlgorithm.SPHINCS_PLUS,
            CryptoAlgorithm.AES_256,
        }
        
        asset = self.inventory.register_asset(
            name=name,
            algorithm=algorithm,
            crypto_type=crypto_type,
            key_size=key_size,
            usage=usage,
            system=system,
            location=location,
            owner=owner,
            quantum_resistant=quantum_resistant,
        )
        
        return {
            "asset_id": asset.asset_id,
            "status": "registered",
            "quantum_resistant": quantum_resistant,
        }

    async def get_risk_assessment(self, asset_id: str) -> Dict[str, Any]:
        """Get risk assessment for an asset."""
        assessment = self.risk.assess_asset(asset_id)
        return self.risk.get_assessment(asset_id)

    async def get_risks(self) -> List[Dict[str, Any]]:
        """Get high-risk assets."""
        return self.risk.get_high_risk_assets()

    async def get_certificates(
        self,
        expiring_within_days: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Get certificates."""
        if expiring_within_days:
            return self.certificates.get_expiring_certificates(expiring_within_days)
        return self.certificates.get_all_certificates()

    async def register_certificate(
        self,
        subject: str,
        issuer: str,
        serial_number: str,
        algorithm: str,
        key_size: int,
        public_key_fingerprint: str,
        valid_from: datetime,
        valid_until: datetime,
    ) -> Dict[str, Any]:
        """Register a certificate."""
        cert = self.certificates.register_certificate(
            subject=subject,
            issuer=issuer,
            serial_number=serial_number,
            algorithm=algorithm,
            key_size=key_size,
            public_key_fingerprint=public_key_fingerprint,
            valid_from=valid_from,
            valid_until=valid_until,
        )
        
        return {
            "cert_id": cert.cert_id,
            "status": "registered",
            "quantum_resistant": cert.quantum_resistant,
        }

    async def get_compliance(self, framework: str) -> Dict[str, Any]:
        """Get compliance report."""
        report = self.compliance.generate_report(framework)
        return self.compliance.get_latest_report(framework)

    async def create_policy(
        self,
        name: str,
        description: str,
        rules: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Create a governance policy."""
        policy = self.governance.create_policy(
            name=name,
            description=description,
            rules=rules,
        )
        
        return {
            "policy_id": policy.policy_id,
            "name": policy.name,
            "status": "created",
        }

    async def get_governance(self) -> Dict[str, Any]:
        """Get governance status."""
        return self.governance.get_governance_status()

    async def get_dashboard(self) -> Dict[str, Any]:
        """Get executive dashboard."""
        metrics = self.store.get_dashboard_metrics()
        summary = self.inventory.get_inventory_summary()
        cert_summary = self.certificates.get_certificate_summary()
        
        return {
            **metrics,
            "inventory_summary": summary,
            "certificate_summary": cert_summary,
        }

    async def get_audit(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "user_id": e.user_id,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "success": e.success,
            }
            for e in events
        ]


# Singleton instance
_service: Optional[QuantumSecurityService] = None


def get_quantum_security_service() -> QuantumSecurityService:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = QuantumSecurityService()
    return _service


def reset_quantum_security_service() -> None:
    """Reset the global service."""
    global _service
    _service = None
    reset_quantum_store()
    reset_crypto_inventory_engine()
    reset_risk_analyzer()
    reset_key_manager()
    reset_certificate_engine()
    reset_governance_engine()
    reset_compliance_engine()