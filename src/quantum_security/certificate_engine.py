"""
Certificate Intelligence Engine.

Manages digital certificates and their lifecycle.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import Certificate, CryptoAlgorithm
from .store import QuantumSecurityStore, get_quantum_store


class CertificateIntelligenceEngine:
    """Engine for certificate intelligence."""

    def __init__(self, store: Optional[QuantumSecurityStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_quantum_store()
        self._quantum_resistant_algorithms = {
            CryptoAlgorithm.CRYSTALS_DILITHIUM,
            CryptoAlgorithm.FALCON,
            CryptoAlgorithm.SPHINCS_PLUS,
        }

    def register_certificate(
        self,
        subject: str,
        issuer: str,
        serial_number: str,
        algorithm: str,
        key_size: int,
        public_key_fingerprint: str,
        valid_from: datetime,
        valid_until: datetime,
        san: Optional[List[str]] = None,
    ) -> Certificate:
        """Register a certificate."""
        cert_id = f"cert-{uuid.uuid4().hex[:12]}"
        
        quantum_resistant = CryptoAlgorithm(algorithm) in self._quantum_resistant_algorithms
        
        cert = Certificate(
            cert_id=cert_id,
            subject=subject,
            issuer=issuer,
            serial_number=serial_number,
            algorithm=CryptoAlgorithm(algorithm),
            key_size=key_size,
            public_key_fingerprint=public_key_fingerprint,
            valid_from=valid_from,
            valid_until=valid_until,
            san=san or [],
            quantum_resistant=quantum_resistant,
        )
        
        self.store.add_certificate(cert)
        
        self.store.log_audit(
            user_id="system",
            action="certificate_registered",
            resource_type="certificate",
            resource_id=cert_id,
            details={"subject": subject, "issuer": issuer},
        )
        
        return cert

    def get_certificate(self, cert_id: str) -> Optional[Dict[str, Any]]:
        """Get certificate details."""
        cert = self.store.get_certificate(cert_id)
        if not cert:
            return None
        
        return self._cert_to_dict(cert)

    def _cert_to_dict(self, cert: Certificate) -> Dict[str, Any]:
        """Convert certificate to dictionary."""
        return {
            "cert_id": cert.cert_id,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "serial_number": cert.serial_number,
            "algorithm": cert.algorithm.value,
            "key_size": cert.key_size,
            "valid_from": cert.valid_from.isoformat(),
            "valid_until": cert.valid_until.isoformat(),
            "san": cert.san,
            "status": cert.status,
            "quantum_resistant": cert.quantum_resistant,
        }

    def get_expiring_certificates(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get expiring certificates."""
        certs = self.store.get_expiring_certificates(days)
        return [self._cert_to_dict(c) for c in certs]

    def get_all_certificates(self) -> List[Dict[str, Any]]:
        """Get all certificates."""
        certs = list(self.store._certificates.values())
        return [self._cert_to_dict(c) for c in certs]

    def revoke_certificate(self, cert_id: str) -> bool:
        """Revoke a certificate."""
        cert = self.store.get_certificate(cert_id)
        if not cert:
            return False
        
        cert.status = "revoked"
        return True

    def get_certificate_summary(self) -> Dict[str, Any]:
        """Get certificate summary."""
        certs = list(self.store._certificates.values())
        
        return {
            "total_certificates": len(certs),
            "valid": len([c for c in certs if c.status == "valid"]),
            "expired": len([c for c in certs if c.status == "expired"]),
            "revoked": len([c for c in certs if c.status == "revoked"]),
            "quantum_resistant": len([c for c in certs if c.quantum_resistant]),
            "vulnerable": len([c for c in certs if not c.quantum_resistant]),
            "expiring_soon": len(self.store.get_expiring_certificates(30)),
        }


# Singleton instance
_engine: Optional[CertificateIntelligenceEngine] = None


def get_certificate_engine() -> CertificateIntelligenceEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = CertificateIntelligenceEngine()
    return _engine


def reset_certificate_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None