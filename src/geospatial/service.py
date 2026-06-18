"""
Services for Issue #1021 - Geospatial Encryption.
"""

import hmac
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.geospatial.models import LocationUpdate, Asset

logger = logging.getLogger("geospatial")

class GeospatialCryptor:
    """Handles field-level encryption for location coordinates using AES-256-GCM."""
    def __init__(self, master_key: str = "aegis_geospatial_master_secure_key_32bytes"):
        self.master_key = master_key.ljust(32)[:32].encode("utf-8")

    def get_tenant_key(self, tenant_id: str) -> bytes:
        """Derive a tenant-specific key."""
        return hmac.new(self.master_key, tenant_id.encode("utf-8"), "sha256").digest()

    def encrypt_coordinate(self, coord: float, tenant_key: bytes) -> bytes:
        """Encrypt float coordinate."""
        aesgcm = AESGCM(tenant_key)
        nonce = os.urandom(12)
        data = bytearray(struct_pack_double(coord))
        ciphertext = aesgcm.encrypt(nonce, bytes(data), None)
        return nonce + ciphertext

    def decrypt_coordinate(self, encrypted_coord: bytes, tenant_key: bytes) -> float:
        """Decrypt coordinate."""
        nonce = encrypted_coord[:12]
        ciphertext = encrypted_coord[12:]
        aesgcm = AESGCM(tenant_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return struct_unpack_double(decrypted_data)


def struct_pack_double(val: float) -> bytes:
    import struct
    return struct.pack("!d", val)

def struct_unpack_double(data: bytes) -> float:
    import struct
    return struct.unpack("!d", data)[0]


class AccessAuditLogger:
    """Logs access to sensitive coordinates for GDPR compliance."""
    @staticmethod
    def log_access(user_id: str, action: str, asset_id: str, tenant_id: str):
        logger.info(
            f"[AUDIT] GDPR Location Access: User '{user_id}' performed '{action}' "
            f"on Asset '{asset_id}' under Tenant '{tenant_id}' at {datetime.now(timezone.utc).isoformat()}"
        )


class GeospatialTrackingService:
    """Basic tracking service with coordinates encryption and access checks."""
    def __init__(self, cryptor: GeospatialCryptor, audit_logger: AccessAuditLogger):
        self.cryptor = cryptor
        self.audit_logger = audit_logger
        self.assets: Dict[str, Asset] = {}

    def process_location_update(self, asset_id: str, lat: float, lon: float, accuracy: float):
        tenant_id = "default_tenant"
        tenant_key = self.cryptor.get_tenant_key(tenant_id)

        if asset_id not in self.assets:
            self.assets[asset_id] = Asset(asset_id=asset_id, name=f"Asset-{asset_id}")

        asset = self.assets[asset_id]
        
        # Audit logging
        self.audit_logger.log_access("system", "write_update", asset_id, tenant_id)

        # Encrypt
        asset.encrypted_last_lat = self.cryptor.encrypt_coordinate(lat, tenant_key)
        asset.encrypted_last_lon = self.cryptor.encrypt_coordinate(lon, tenant_key)
        asset.last_updated = datetime.now(timezone.utc)
        asset.accuracy = accuracy
