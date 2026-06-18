"""
Services for Issue #1023 - Geofencing and Webhooks.
"""

import asyncio
import hmac
import json
import logging
import math
import os
import zlib
import httpx
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Any, Set, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.geospatial.models import LocationUpdate, Asset, Geofence, GeofenceBreach

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

    def encrypt_string(self, text: str, tenant_key: bytes) -> bytes:
        """Encrypt string data."""
        aesgcm = AESGCM(tenant_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, text.encode("utf-8"), None)
        return nonce + ciphertext

    def decrypt_string(self, encrypted_data: bytes, tenant_key: bytes) -> str:
        """Decrypt string data."""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(tenant_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data.decode("utf-8")


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
    """Tracking service with coordinates encryption, queue batching, and geofencing."""
    def __init__(self, cryptor: GeospatialCryptor, audit_logger: AccessAuditLogger):
        self.cryptor = cryptor
        self.audit_logger = audit_logger
        self.assets: Dict[str, Asset] = {}
        self.geofences: Dict[str, Geofence] = {}
        self.breach_history: List[GeofenceBreach] = []
        self.geofence_states: Dict[str, Dict[str, bool]] = {}  # asset_id -> {geofence_id: is_inside}
        
        # Async Queue & Batching
        self.update_queue = asyncio.Queue()
        self._batch_processor_task = None
        self.batch_processing_active = False

        # WebSockets listeners
        self.websocket_listeners: Set[Any] = set()

        # Webhook endpoints
        self.webhook_urls: List[str] = []

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
                item = await self.update_queue.get()
                updates.append(item)
                self.update_queue.task_done()

                while not self.update_queue.empty() and len(updates) < 50:
                    item = self.update_queue.get_nowait()
                    updates.append(item)
                    self.update_queue.task_done()

                for asset_id, lat, lon, accuracy in updates:
                    await self._process_location_update(asset_id, lat, lon, accuracy)

                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in queue processing loop: {e}")
                await asyncio.sleep(1)

    async def _process_location_update(self, asset_id: str, lat: float, lon: float, accuracy: float):
        """Directly processes location update with delta filtering and geofence checks."""
        tenant_id = "default_tenant"
        tenant_key = self.cryptor.get_tenant_key(tenant_id)

        if asset_id not in self.assets:
            self.assets[asset_id] = Asset(asset_id=asset_id, name=f"Asset-{asset_id}")

        asset = self.assets[asset_id]
        
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
            if dist < 1.5:
                should_push = False

        # Update
        asset.encrypted_last_lat = self.cryptor.encrypt_coordinate(lat, tenant_key)
        asset.encrypted_last_lon = self.cryptor.encrypt_coordinate(lon, tenant_key)
        asset.last_updated = datetime.now(timezone.utc)
        asset.accuracy = accuracy

        # Geofence evaluation
        await self._evaluate_geofences_for_asset(asset_id, lat, lon, tenant_key)

        # Real-time WebSocket Push
        if should_push:
            await self._broadcast_update(asset_id, lat, lon, accuracy)

    async def _evaluate_geofences_for_asset(self, asset_id: str, lat: float, lon: float, tenant_key: bytes):
        """Evaluate geofence status for an asset and trigger entry/exit transition breach events."""
        if asset_id not in self.geofence_states:
            self.geofence_states[asset_id] = {}

        states = self.geofence_states[asset_id]

        for fence_id, fence in self.geofences.items():
            is_inside = False
            if fence.boundary_type == "circle":
                c_lat = self.cryptor.decrypt_coordinate(fence.encrypted_center_lat, tenant_key)
                c_lon = self.cryptor.decrypt_coordinate(fence.encrypted_center_lon, tenant_key)
                dist = self.calculate_distance(lat, lon, c_lat, c_lon)
                is_inside = (dist <= fence.radius_meters)
            elif fence.boundary_type == "polygon":
                coord_str = self.cryptor.decrypt_string(fence.encrypted_coordinates, tenant_key)
                poly_pts = json.loads(coord_str)
                is_inside = self.point_in_polygon(lat, lon, poly_pts)

            was_inside = states.get(fence_id, None)
            states[fence_id] = is_inside

            if was_inside is not None and was_inside != is_inside:
                # Transition detected!
                breach_type = "EXIT" if was_inside and not is_inside else "ENTER"
                breach = GeofenceBreach(
                    alert_id=f"B_{int(time_timestamp_ms())}",
                    asset_id=asset_id,
                    geofence_id=fence_id,
                    breach_type=breach_type,
                    encrypted_lat=self.cryptor.encrypt_coordinate(lat, tenant_key),
                    encrypted_lon=self.cryptor.encrypt_coordinate(lon, tenant_key)
                )
                self.breach_history.append(breach)
                
                # Webhook & WebSocket notification
                await self._trigger_webhook(breach, lat, lon)
                await self._broadcast_breach(breach, lat, lon)

    def register_geofence(self, fence: Geofence):
        self.geofences[fence.geofence_id] = fence

    def register_webhook(self, url: str):
        self.webhook_urls.append(url)

    async def _trigger_webhook(self, breach: GeofenceBreach, lat: float, lon: float):
        payload = {
            "alert_id": breach.alert_id,
            "asset_id": breach.asset_id,
            "geofence_id": breach.geofence_id,
            "breach_type": breach.breach_type,
            "timestamp": breach.timestamp.isoformat(),
            "latitude": lat,
            "longitude": lon
        }
        async with httpx.AsyncClient() as client:
            for url in self.webhook_urls:
                try:
                    await client.post(url, json=payload, timeout=2.0)
                except Exception as e:
                    logger.warning(f"Failed to post webhook to {url}: {e}")

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

    async def _broadcast_breach(self, breach: GeofenceBreach, lat: float, lon: float):
        payload = {
            "type": "GEOFENCE_BREACH",
            "alert_id": breach.alert_id,
            "asset_id": breach.asset_id,
            "geofence_id": breach.geofence_id,
            "breach_type": breach.breach_type,
            "latitude": lat,
            "longitude": lon,
            "timestamp": breach.timestamp.isoformat()
        }
        await self._send_compressed_websocket(payload)

    async def _send_compressed_websocket(self, payload: dict):
        json_str = json.dumps(payload)
        compressed_bytes = zlib.compress(json_str.encode("utf-8"))
        for ws in list(self.websocket_listeners):
            try:
                await ws.send_bytes(compressed_bytes)
            except Exception:
                self.websocket_listeners.remove(ws)

    @staticmethod
    def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371000.0
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        d_phi = math.radians(lat2 - lat1)
        d_lambda = math.radians(lon2 - lon1)

        a = math.sin(d_phi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    @staticmethod
    def point_in_polygon(x: float, y: float, poly: List[List[float]]) -> bool:
        num = len(poly)
        i = 0
        j = num - 1
        c = False
        for i in range(num):
            if ((poly[i][1] > y) != (poly[j][1] > y)) and \
                    (x < (poly[j][0] - poly[i][0]) * (y - poly[i][1]) / (poly[j][1] - poly[i][1]) + poly[i][0]):
                c = not c
            j = i
        return c


def time_timestamp_ms() -> int:
    import time
    return int(time.time() * 1000)
