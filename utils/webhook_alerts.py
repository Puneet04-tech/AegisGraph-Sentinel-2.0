import hashlib
import hmac
import json
import logging
import threading
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


def _send_payload_background(
    url: str,
    payload: Dict[str, Any],
    secret_key: Optional[str] = None,
    timeout: float = 5.0,
) -> None:
    """Perform HTTP POST in the background."""
    try:
        data = json.dumps(payload)
        headers = {"Content-Type": "application/json"}

        if secret_key:
            signature = hmac.new(
                secret_key.encode("utf-8"),
                data.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()
            headers["X-Sentinel-Signature"] = signature

        response = requests.post(
            url, data=data, headers=headers, timeout=timeout
        )
        if response.status_code not in (200, 201, 202, 204):
            status = response.status_code
            logger.warning(
                f"Webhook alert failed with HTTP {status}: "
                f"{response.text[:256]}"
            )
        else:
            logger.info("Webhook alert delivered successfully.")
    except requests.Timeout:
        logger.error(
            f"Webhook alert to {url} timed out after {timeout} seconds."
        )
    except Exception as e:
        logger.error(f"Failed to deliver webhook alert: {e}")


def trigger_webhook_alert(
    url: str,
    payload: Dict[str, Any],
    secret_key: Optional[str] = None,
    timeout: float = 5.0,
) -> None:
    """Dispatches webhook payload in a background thread."""
    if not url:
        return

    thread = threading.Thread(
        target=_send_payload_background,
        args=(url, payload, secret_key, timeout),
        daemon=True,
    )
    thread.start()
