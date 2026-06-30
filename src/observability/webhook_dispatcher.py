import queue
import threading
import time
import urllib.request
import json
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class WebhookDispatcher:
    """Asynchronous webhook dispatcher for enterprise SIEM integrations."""

    def __init__(self, max_retries: int = 3, retry_delay: int = 5):
        self.webhooks: List[Dict[str, Any]] = []
        self._queue: queue.Queue = queue.Queue()
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def register_webhook(self, url: str, headers: Optional[Dict[str, str]] = None, severity_filter: Optional[List[str]] = None):
        """Register a new SIEM webhook endpoint."""
        if severity_filter is None:
            severity_filter = ["HIGH", "CRITICAL"]
        self.webhooks.append({
            "url": url,
            "headers": headers or {},
            "severity_filter": [s.upper() for s in severity_filter]
        })
        logger.info(f"Registered webhook URL: {url} with filters: {severity_filter}")

    def dispatch(self, payload: Dict[str, Any]):
        """Queue an alert payload for dispatch."""
        if not self.webhooks:
            return
            
        severity = str(payload.get("severity", "")).upper()
        
        for wh in self.webhooks:
            if severity in wh["severity_filter"]:
                self._queue.put((wh, payload, 0))

    def _worker_loop(self):
        """Background thread to process webhooks from the queue."""
        while not self._stop_event.is_set():
            try:
                # Block for 1 second so we can check the stop event
                wh, payload, attempt = self._queue.get(timeout=1.0)
                
                success = self._send_webhook(wh, payload)
                
                if not success and attempt < self.max_retries:
                    logger.warning(f"Webhook failed, retrying {attempt + 1}/{self.max_retries}...")
                    time.sleep(self.retry_delay * (2 ** attempt)) # Exponential backoff
                    self._queue.put((wh, payload, attempt + 1))
                elif not success:
                    logger.error(f"Webhook failed after {self.max_retries} retries. Dropping payload.")
                
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in webhook worker loop: {e}")

    def _send_webhook(self, webhook_config: Dict[str, Any], payload: Dict[str, Any]) -> bool:
        """Send a single HTTP POST request."""
        url = webhook_config["url"]
        headers = webhook_config["headers"].copy()
        headers["Content-Type"] = "application/json"
        
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                if 200 <= response.status < 300:
                    return True
                return False
        except Exception as e:
            logger.error(f"Webhook exception for {url}: {e}")
            return False

    def shutdown(self):
        """Cleanly shutdown the worker thread."""
        self._stop_event.set()
        self._worker_thread.join(timeout=5.0)

# Global singleton
_dispatcher_instance = None

def get_webhook_dispatcher() -> WebhookDispatcher:
    """Get or create the global webhook dispatcher singleton."""
    global _dispatcher_instance
    if _dispatcher_instance is None:
        _dispatcher_instance = WebhookDispatcher()
        # Mock default SIEM registrations for Enterprise config
        _dispatcher_instance.register_webhook("http://localhost:8080/splunk/hec", severity_filter=["HIGH", "CRITICAL"])
    return _dispatcher_instance
