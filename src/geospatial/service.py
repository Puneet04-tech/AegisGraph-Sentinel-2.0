"""
Geospatial tracking services, encryption, batching, geofencing, and route planning.
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
from typing import Dict, List, Tuple, Optional, Any, Set
import numpy as np
import networkx as nx

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.geospatial.models import LocationUpdate, Asset, Geofence, GeofenceBreach, Route

logger = logging.getLogger("geospatial")

class GeospatialCryptor:
    """Handles field-level encryption for location coordinates using AES-256-GCM."""
    def __init__(self, master_key: str = "aegis_geospatial_master_secure_key_32bytes"):
        # Ensure key is 32 bytes for AES-256
        self.master_key = master_key.ljust(32)[:32].encode("utf-8")

    def get_tenant_key(self, tenant_id: str) -> bytes:
        """Derive a tenant-specific key from the master key."""
        # Simple key derivation using HMAC-SHA256
        return hmac.new(self.master_key, tenant_id.encode("utf-8"), "sha256").digest()

    def encrypt_coordinate(self, coord: float, tenant_key: bytes) -> bytes:
        """Encrypt a single latitude/longitude float coordinate."""
        aesgcm = AESGCM(tenant_key)
        nonce = os.urandom(12)
        data = bytearray(struct_pack_double(coord))
        ciphertext = aesgcm.encrypt(nonce, bytes(data), None)
        return nonce + ciphertext

    def decrypt_coordinate(self, encrypted_coord: bytes, tenant_key: bytes) -> float:
        """Decrypt an encrypted coordinate back to float."""
        nonce = encrypted_coord[:12]
        ciphertext = encrypted_coord[12:]
        aesgcm = AESGCM(tenant_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return struct_unpack_double(decrypted_data)

    def encrypt_string(self, text: str, tenant_key: bytes) -> bytes:
        """Encrypt string data (e.g. coordinates list for polygon)."""
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
    """Logs access to sensitive geospatial coordinates to satisfy GDPR compliance."""
    @staticmethod
    def log_access(user_id: str, action: str, asset_id: str, tenant_id: str):
        logger.info(
            f"[AUDIT] GDPR Location Access: User '{user_id}' performed '{action}' "
            f"on Asset '{asset_id}' under Tenant '{tenant_id}' at {datetime.now(timezone.utc).isoformat()}"
        )


class KalmanTracker:
    """Kalman filter for tracking 2D positions (lat/lon) and velocities."""
    def __init__(self, initial_lat: float, initial_lon: float):
        # State vector: [lat, lon, vel_lat, vel_lon]^T
        self.x = np.array([initial_lat, initial_lon, 0.0, 0.0], dtype=float)
        
        # State covariance matrix P
        self.P = np.eye(4, dtype=float) * 10.0
        
        # Process noise covariance Q
        self.Q = np.eye(4, dtype=float) * 0.0001
        self.Q[2, 2] = 0.001
        self.Q[3, 3] = 0.001
        
        self.last_update_time = datetime.now(timezone.utc)

    def update(self, observed_lat: float, observed_lon: float, accuracy: float, signal_strength: float):
        now = datetime.now(timezone.utc)
        dt = (now - self.last_update_time).total_seconds()
        self.last_update_time = now

        if dt <= 0:
            dt = 0.1

        # 1. Prediction Step
        # F matrix: State transition
        F = np.array([
            [1.0, 0.0, dt,  0.0],
            [0.0, 1.0, 0.0, dt ],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0]
        ])
        
        self.x = F.dot(self.x)
        self.P = F.dot(self.P).dot(F.T) + self.Q

        # 2. Measurement Update Step
        # H matrix: Measurement matrix
        H = np.array([
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0]
        ])

        # Measurement noise covariance R based on accuracy and signal quality
        # Lower signal_strength (SNR) or higher accuracy parameter means higher noise
        noise_factor = (accuracy / max(0.1, signal_strength)) * 0.00001
        R = np.eye(2, dtype=float) * noise_factor

        z = np.array([observed_lat, observed_lon])
        
        # Innovation/residual
        y = z - H.dot(self.x)
        
        # Innovation covariance
        S = H.dot(self.P).dot(H.T) + R
        
        # Kalman gain
        K = self.P.dot(H.T).dot(np.linalg.inv(S))
        
        # New state and covariance
        self.x = self.x + K.dot(y)
        self.P = (np.eye(4) - K.dot(H)).dot(self.P)

    def get_position(self) -> Tuple[float, float]:
        return self.x[0], self.x[1]

    def get_velocity(self) -> Tuple[float, float]:
        return self.x[2], self.x[3]


class GeospatialTrackingService:
    """Manages real-time geospatial asset locations, geofencing, webhooks, and routing."""
    def __init__(self, cryptor: GeospatialCryptor, audit_logger: AccessAuditLogger):
        self.cryptor = cryptor
        self.audit_logger = audit_logger
        
        # In-memory storage for assets and active states
        self.assets: Dict[str, Asset] = {}
        self.active_trackers: Dict[str, KalmanTracker] = {}
        self.geofences: Dict[str, Geofence] = {}
        self.breach_history: List[GeofenceBreach] = []
        
        # Last known states of assets inside/outside geofences
        self.geofence_states: Dict[str, Dict[str, bool]] = {}  # asset_id -> {geofence_id: is_inside}
        
        # Queue for batch processing updates
        self.update_queue = asyncio.Queue()
        self._batch_processor_task = None
        self.batch_processing_active = False

        # Active websocket connections
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

    async def add_update_to_queue(self, asset_id: str, lat: float, lon: float, accuracy: float, signal_strength: float):
        """Enqueue update for non-blocking processing."""
        self.start_batch_processing()
        await self.update_queue.put((asset_id, lat, lon, accuracy, signal_strength))

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
                for asset_id, lat, lon, accuracy, signal_strength in updates:
                    await self._process_location_update(asset_id, lat, lon, accuracy, signal_strength)

                # Delay slightly to allow batching
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in queue processing loop: {e}")
                await asyncio.sleep(1)

    async def _process_location_update(self, asset_id: str, lat: float, lon: float, accuracy: float, signal_strength: float):
        """Directly processes a location update (encrypts, calibrates, filters, checks geofences, predicts)."""
        tenant_id = "default_tenant"
        tenant_key = self.cryptor.get_tenant_key(tenant_id)

        # 1. Load or initialize asset
        if asset_id not in self.assets:
            self.assets[asset_id] = Asset(
                asset_id=asset_id,
                name=f"Asset-{asset_id}",
                calibration_bias_lat=0.0,
                calibration_bias_lon=0.0
            )

        asset = self.assets[asset_id]

        # 2. Calibration / Drift Correction
        calibrated_lat = lat - asset.calibration_bias_lat
        calibrated_lon = lon - asset.calibration_bias_lon

        # 3. Kalman Filter state estimation
        if asset_id not in self.active_trackers:
            self.active_trackers[asset_id] = KalmanTracker(calibrated_lat, calibrated_lon)
        
        tracker = self.active_trackers[asset_id]
        tracker.update(calibrated_lat, calibrated_lon, accuracy, signal_strength)
        est_lat, est_lon = tracker.get_position()

        # 4. Access audit log
        self.audit_logger.log_access("system", "write_update", asset_id, tenant_id)

        # 5. Check if update represents a significant movement (Delta filtering)
        last_lat, last_lon = None, None
        if asset.encrypted_last_lat and asset.encrypted_last_lon:
            try:
                last_lat = self.cryptor.decrypt_coordinate(asset.encrypted_last_lat, tenant_key)
                last_lon = self.cryptor.decrypt_coordinate(asset.encrypted_last_lon, tenant_key)
            except Exception:
                pass

        should_push = True
        if last_lat is not None and last_lon is not None:
            dist = self.calculate_distance(last_lat, last_lon, est_lat, est_lon)
            if dist < 1.5:  # Less than 1.5 meters movement - ignore delta push to optimize bandwidth
                should_push = False

        # 6. Update Asset Record
        asset.encrypted_last_lat = self.cryptor.encrypt_coordinate(est_lat, tenant_key)
        asset.encrypted_last_lon = self.cryptor.encrypt_coordinate(est_lon, tenant_key)
        asset.last_updated = datetime.now(timezone.utc)
        asset.accuracy = accuracy

        # 7. Geofence evaluation
        await self._evaluate_geofences_for_asset(asset_id, est_lat, est_lon, tenant_key)

        # 8. Real-time push via websocket
        if should_push:
            await self._broadcast_update(asset_id, est_lat, est_lon, accuracy)

    async def _evaluate_geofences_for_asset(self, asset_id: str, lat: float, lon: float, tenant_key: bytes):
        """Evaluate geofence status for an asset and trigger entry/exit transition breach events."""
        if asset_id not in self.geofence_states:
            self.geofence_states[asset_id] = {}

        states = self.geofence_states[asset_id]

        for fence_id, fence in self.geofences.items():
            is_inside = False
            if fence.boundary_type == "circle":
                # Decrypt circular center
                c_lat = self.cryptor.decrypt_coordinate(fence.encrypted_center_lat, tenant_key)
                c_lon = self.cryptor.decrypt_coordinate(fence.encrypted_center_lon, tenant_key)
                dist = self.calculate_distance(lat, lon, c_lat, c_lon)
                is_inside = (dist <= fence.radius_meters)
            elif fence.boundary_type == "polygon":
                # Decrypt polygon coordinates
                coord_str = self.cryptor.decrypt_string(fence.encrypted_coordinates, tenant_key)
                poly_pts = json.loads(coord_str)  # list of [lat, lon]
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
                
                # Fire webhook
                await self._trigger_webhook(breach, lat, lon)
                
                # Push breach via websocket
                await self._broadcast_breach(breach, lat, lon)

    def register_geofence(self, fence: Geofence):
        self.geofences[fence.geofence_id] = fence

    def register_webhook(self, url: str):
        self.webhook_urls.append(url)

    async def _trigger_webhook(self, breach: GeofenceBreach, lat: float, lon: float):
        """Asynchronously trigger webhooks on geofence breach."""
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
        """Compress payload using zlib before sending to connected clients."""
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
        R = 6371000.0  # Earth radius in meters
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        d_phi = math.radians(lat2 - lat1)
        d_lambda = math.radians(lon2 - lon1)

        a = math.sin(d_phi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    @staticmethod
    def point_in_polygon(x: float, y: float, poly: List[List[float]]) -> bool:
        """Ray-casting algorithm to detect point in polygon."""
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


class RouteOptimizationEngine:
    """Provides grid routing, A* route optimization, traffic simulation, and route anomaly checking."""
    def __init__(self):
        # Create a basic routing grid using NetworkX
        # Grid covers a hypothetical urban area: 100x100 nodes
        self.graph = nx.grid_2d_graph(20, 20)
        
        # Mapping from (x,y) to hypothetical lat/lon
        self.node_positions = {}
        for node in self.graph.nodes:
            # Center coordinates around Mumbai: 19.076, 72.877
            self.node_positions[node] = (19.076 + node[0]*0.001, 72.877 + node[1]*0.001)

        # Set default weights on all edges
        for u, v in self.graph.edges:
            self.graph[u][v]["weight"] = 1.0  # Standard traversal cost
            self.graph[u][v]["traffic_multiplier"] = 1.0

    def set_traffic_multiplier(self, u: Tuple[int, int], v: Tuple[int, int], multiplier: float):
        """Set a congestion cost multiplier on a specific route segment."""
        if self.graph.has_edge(u, v):
            self.graph[u][v]["traffic_multiplier"] = multiplier

    def optimize_route(self, asset_id: str, source: Tuple[int, int], target: Tuple[int, int]) -> Route:
        """Find the most optimal path using A* taking traffic multipliers into account."""
        def heuristic(a, b):
            return math.sqrt((a[0] - b[0])**2 + (a[1] - b[1])**2)

        def weight_func(u, v, d):
            return d["weight"] * d["traffic_multiplier"]

        path = nx.astar_path(self.graph, source, target, heuristic=heuristic, weight=weight_func)
        
        # Map back to lat/lon coordinates
        coords = [self.node_positions[node] for node in path]
        
        # Calculate ETA (based on standard traversal time and traffic multipliers)
        total_cost = 0.0
        for i in range(len(path) - 1):
            edge_data = self.graph[path[i]][path[i+1]]
            total_cost += edge_data["weight"] * edge_data["traffic_multiplier"]

        eta = total_cost * 1.5  # Estimate 1.5 minutes per unit of cost

        return Route(
            route_id=f"R_{int(time_timestamp_ms())}",
            asset_id=asset_id,
            points=coords,
            optimized_points=coords,
            eta_minutes=eta
        )

    def predict_next_location(self, tracker: KalmanTracker, dt: float = 10.0) -> Tuple[float, float]:
        """Predict the next location based on current estimated state velocity vector."""
        lat, lon = tracker.get_position()
        v_lat, v_lon = tracker.get_velocity()
        return lat + v_lat * dt, lon + v_lon * dt

    def detect_route_deviation(self, current_lat: float, current_lon: float, route: Route, threshold_meters: float = 100.0) -> bool:
        """Calculate closest perpendicular distance to route and alert if deviation exceeds threshold."""
        if not route.points:
            return False

        min_dist = float("inf")
        for i in range(len(route.points) - 1):
            p1 = route.points[i]
            p2 = route.points[i+1]
            dist = self._point_to_segment_distance(current_lat, current_lon, p1[0], p1[1], p2[0], p2[1])
            if dist < min_dist:
                min_dist = dist

        return min_dist > threshold_meters

    def _point_to_segment_distance(self, px, py, x1, y1, x2, y2) -> float:
        """Calculates distance in meters from point (px, py) to segment (x1, y1) - (x2, y2)."""
        # Linear projection factor
        dx = x2 - x1
        dy = y2 - y1
        if dx == 0 and dy == 0:
            return GeospatialTrackingService.calculate_distance(px, py, x1, y1)

        t = ((px - x1) * dx + (py - y1) * dy) / (dx*dx + dy*dy)
        t = max(0.0, min(1.0, t))
        
        proj_x = x1 + t * dx
        proj_y = y1 + t * dy
        return GeospatialTrackingService.calculate_distance(px, py, proj_x, proj_y)


def time_timestamp_ms() -> int:
    import time
    return int(time.time() * 1000)
