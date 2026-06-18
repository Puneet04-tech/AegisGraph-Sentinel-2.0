"""
Services for Issue #1022 - Real-Time Update Pipeline.
"""

import asyncio
import hmac
import json
import logging
import math
import os
import zlib
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Any, Set

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
    """Tracking service with coordinates encryption, async queue batching, delta filtering, and WebSocket push."""
    def __init__(self, cryptor: GeospatialCryptor, audit_logger: AccessAuditLogger):
        self.cryptor = cryptor
        self.audit_logger = audit_logger
        self.assets: Dict[str, Asset] = {}
        
        # Async Queue & Batching
        self.update_queue = asyncio.Queue()
        self._batch_processor_task = None
        self.batch_processing_active = False

        # Active websocket connections
        self.websocket_listeners: Set[Any] = set()

    def start_batch_processing(self):
        """Start background queue batch processing loop."""
        if not self.batch_processing_active:
            self.batch_processing_active = True
            try:
                self._batch_processor_task = asyncio.create_task(self._process_queue_loop())
            except RuntimeError:
                self.batch_processing_active = False

    async def stop_batch_processing(self):
        """Stop queue processing."""
        self.batch_processing_active = False
        if self._batch_processor_task:
            self._batch_processor_task.cancel()
            try:
                await self._batch_processor_task
            except asyncio.CancelledError:
                pass

    async def add_update_to_queue(self, asset_id: str, lat: float, lon: float, accuracy: float):
        """Enqueue update for non-blocking processing."""
        self.start_batch_processing()
        await self.update_queue.put((asset_id, lat, lon, accuracy))

    async def _process_queue_loop(self):
        """Processes incoming location updates in batches asynchronously."""
        while self.batch_processing_active:
            try:
                updates = []
                # Fetch first item
                item = await self.update_queue.get()
                updates.append(item)
                self.update_queue.task_done()

                # Coalesce additional items in queue up to a limit
                while not self.update_queue.empty() and len(updates) < 50:
                    item = self.update_queue.get_nowait()
                    updates.append(item)
                    self.update_queue.task_done()

                # Process batch of updates
                for asset_id, lat, lon, accuracy in updates:
                    await self._process_location_update(asset_id, lat, lon, accuracy)

                # Delay slightly to allow batching
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in queue processing loop: {e}")
                await asyncio.sleep(1)

    async def _process_location_update(self, asset_id: str, lat: float, lon: float, accuracy: float):
        """Directly processes location update with delta filtering."""
        tenant_id = "default_tenant"
        tenant_key = self.cryptor.get_tenant_key(tenant_id)

        if asset_id not in self.assets:
            self.assets[asset_id] = Asset(asset_id=asset_id, name=f"Asset-{asset_id}")

        asset = self.assets[asset_id]
        
        # Audit logging
        self.audit_logger.log_access("system", "write_update", asset_id, tenant_id)

        # Delta Filtering
        last_lat, last_lon = None, None
        if asset.encrypted_last_lat and asset.encrypted_last_lon:
            try:
                last_lat = self.cryptor.decrypt_coordinate(asset.encrypted_last_lat, tenant_key)
                last_lon = self.cryptor.decrypt_coordinate(asset.encrypted_last_lon, tenant_key)
            except Exception:
                pass

        should_push = True
        if last_lat is not None and last_lon is not None:
            dist = self.calculate_distance(last_lat, last_lon, lat, lon)
            if dist < 1.5:  # Filter out minor updates < 1.5m
                should_push = False

        # Update
        asset.encrypted_last_lat = self.cryptor.encrypt_coordinate(lat, tenant_key)
        asset.encrypted_last_lon = self.cryptor.encrypt_coordinate(lon, tenant_key)
        asset.last_updated = datetime.now(timezone.utc)
        asset.accuracy = accuracy

        # Real-time WebSocket Push
        if should_push:
            await self._broadcast_update(asset_id, lat, lon, accuracy)

    async def _broadcast_update(self, asset_id: str, lat: float, lon: float, accuracy: float):
        payload = {
            "type": "LOCATION_UPDATE",
            "asset_id": asset_id,
            "latitude": lat,
            "longitude": lon,
            "accuracy": accuracy,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await self._send_compressed_websocket(payload)

    async def _send_compressed_websocket(self, payload: dict):
        """Compress WebSocket payloads using zlib."""
        json_str = json.dumps(payload)
        compressed_bytes = zlib.compress(json_str.encode("utf-8"))
        for ws in list(self.websocket_listeners):
            try:
                await ws.send_bytes(compressed_bytes)
            except Exception:
                self.websocket_listeners.remove(ws)

    @staticmethod
    def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate the Haversine distance in meters between two points."""
        R = 6371000.0
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        d_phi = math.radians(lat2 - lat1)
        d_lambda = math.radians(lon2 - lon1)

        a = math.sin(d_phi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c
