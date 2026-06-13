"""
Splunk Integration for AegisGraph Sentinel Enterprise
Bi-directional integration for SIEM correlation and alert management
"""

import json
import httpx
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class SplunkConfig:
    """Splunk configuration"""
    host: str
    port: int
    username: str
    password: str
    token: str  # Splunk token for HEC
    index: str = "aegisgraph"
    verify_ssl: bool = True


class SplunkClient:
    """Splunk integration client"""

    def __init__(self, config: SplunkConfig):
        self.config = config
        self.base_url = f"https://{config.host}:{config.port}"
        self.hec_url = f"{self.base_url}/services/collector"
        self.session = httpx.AsyncClient(
            verify=config.verify_ssl,
            timeout=30.0,
        )

    async def send_event(
        self,
        event: Dict[str, Any],
        sourcetype: str = "aegisgraph:fraud",
        host: str = "aegisgraph-sentinel",
    ) -> bool:
        """Send event to Splunk via HEC"""
        try:
            payload = {
                "time": datetime.utcnow().timestamp(),
                "host": host,
                "source": "aegisgraph-sentinel",
                "sourcetype": sourcetype,
                "event": event,
            }
            
            headers = {
                "Authorization": f"Splunk {self.config.token}",
                "Content-Type": "application/json",
            }
            
            response = await self.session.post(
                self.hec_url,
                json=payload,
                headers=headers,
            )
            
            response.raise_for_status()
            return True
            
        except Exception as e:
            logger.error(f"Failed to send event to Splunk: {e}")
            return False

    async def search(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Execute Splunk search"""
        try:
            auth = (self.config.username, self.config.password)
            
            # Create search job
            search_response = await self.session.post(
                f"{self.base_url}/services/search/jobs",
                auth=auth,
                data={
                    "search": query,
                    "earliest_time": earliest_time,
                    "latest_time": latest_time,
                    "output_mode": "json",
                },
            )
            
            search_response.raise_for_status()
            job_id = search_response.json().get("sid")
            
            if not job_id:
                return []
            
            # Wait for job completion
            await self._wait_for_job(job_id)
            
            # Get results
            results_response = await self.session.get(
                f"{self.base_url}/services/search/jobs/{job_id}/results",
                auth=auth,
                params={
                    "output_mode": "json",
                    "count": limit,
                },
            )
            
            results_response.raise_for_status()
            results = results_response.json()
            
            return results.get("results", [])
            
        except Exception as e:
            logger.error(f"Splunk search failed: {e}")
            return []

    async def _wait_for_job(self, job_id: str, max_wait: int = 60):
        """Wait for search job to complete"""
        auth = (self.config.username, self.config.password)
        
        for _ in range(max_wait):
            response = await self.session.get(
                f"{self.base_url}/services/search/jobs/{job_id}",
                auth=auth,
                params={"output_mode": "json"},
            )
            
            if response.status_code == 200:
                data = response.json()
                dispatch_state = data.get("entry", [{}])[0].get("content", {}).get("dispatchState")
                
                if dispatch_state == "DONE":
                    return
                if dispatch_state == "FAILED":
                    raise Exception(f"Search job failed: {data}")
            
            await asyncio.sleep(1)

    async def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts from Splunk"""
        query = """
        search earliest=-24h sourcetype=alert *
        | head {}
        | sort - _time
        """.format(limit)
        
        return await self.search(query)

    async def create_alert(
        self,
        name: str,
        query: str,
        description: str,
        severity: str = "high",
    ) -> bool:
        """Create saved search alert in Splunk"""
        try:
            auth = (self.config.username, self.config.password)
            
            response = await self.session.post(
                f"{self.base_url}/services/saved/searches",
                auth=auth,
                data={
                    "name": name,
                    "search": query,
                    "description": description,
                    "alert.severity": 2 if severity == "high" else 1,
                    "alert.type": "always",
                    "alert.track": 1,
                    "dispatch.earliest_time": "-1h",
                    "output_mode": "json",
                },
            )
            
            response.raise_for_status()
            return True
            
        except Exception as e:
            logger.error(f"Failed to create Splunk alert: {e}")
            return False


# Splunk Alert Handler
class SplunkAlertHandler:
    """Handle incoming alerts from Splunk"""

    def __init__(self, client: SplunkClient):
        self.client = client

    async def handle_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming Splunk alert"""
        alert_type = alert.get("alert_type", "generic")
        
        if alert_type == "siem_correlation":
            return await self._handle_siem_alert(alert)
        elif alert_type == "threat_intel":
            return await self._handle_threat_intel(alert)
        elif alert_type == "user_behavior":
            return await self._handle_uba_alert(alert)
        else:
            return await self._handle_generic_alert(alert)

    async def _handle_siem_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Handle SIEM correlation alert"""
        # Enrich with AegisGraph data
        enriched = {
            "original_alert": alert,
            "enriched_at": datetime.utcnow().isoformat(),
            "correlation_score": self._calculate_correlation(alert),
        }
        
        # Send to AegisGraph for analysis
        await self.client.send_event(
            enriched,
            sourcetype="aegisgraph:enriched_alert",
        )
        
        return enriched

    async def _handle_threat_intel(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Handle threat intelligence alert"""
        return {
            "type": "threat_intel",
            "source": alert.get("source", "unknown"),
            "indicator": alert.get("indicator"),
            "confidence": alert.get("confidence", 0.5),
            "processed_at": datetime.utcnow().isoformat(),
        }

    async def _handle_uba_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Handle user behavior analytics alert"""
        return {
            "type": "uba",
            "user": alert.get("user"),
            "behavior": alert.get("behavior"),
            "risk_score": alert.get("risk_score", 0.5),
            "processed_at": datetime.utcnow().isoformat(),
        }

    async def _handle_generic_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Handle generic alert"""
        return {
            "type": "generic",
            "alert": alert,
            "processed_at": datetime.utcnow().isoformat(),
        }

    def _calculate_correlation(self, alert: Dict[str, Any]) -> float:
        """Calculate correlation score"""
        # Simple scoring based on alert attributes
        score = 0.5
        
        if alert.get("severity") == "critical":
            score += 0.3
        if alert.get("confidence"):
            score += float(alert.get("confidence", 0)) * 0.2
        
        return min(1.0, score)


# Splunk Metrics Exporter
class SplunkMetricsExporter:
    """Export AegisGraph metrics to Splunk"""

    def __init__(self, client: SplunkClient):
        self.client = client

    async def export_metrics(
        self,
        metrics: Dict[str, Any],
        metric_type: str = "system",
    ):
        """Export metrics to Splunk"""
        event = {
            "metric_type": metric_type,
            "metrics": metrics,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "aegisgraph-sentinel",
        }
        
        await self.client.send_event(
            event,
            sourcetype=f"aegisgraph:metrics:{metric_type}",
        )

    async def export_detection_metrics(
        self,
        detection_type: str,
        count: int,
        accuracy: float,
        latency_ms: float,
    ):
        """Export fraud detection metrics"""
        await self.export_metrics(
            {
                "detection_type": detection_type,
                "count": count,
                "accuracy": accuracy,
                "latency_ms": latency_ms,
            },
            metric_type="fraud_detection",
        )