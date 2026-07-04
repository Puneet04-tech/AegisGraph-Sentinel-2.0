import socket
import time
from datetime import datetime, timezone
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SyslogClient:
    """Client for exporting events to an external SIEM/Syslog server using RFC 5424."""

    def __init__(self, host: str = "127.0.0.1", port: int = 514, enabled: bool = True):
        self.host = host
        self.port = port
        self.enabled = enabled
        self.socket_type = socket.SOCK_DGRAM

    def format_rfc5424(
        self,
        severity: int,
        msg_id: str,
        message: str,
        structured_data: Optional[Dict[str, str]] = None,
        hostname: str = "aegisgraph-sentinel",
        app_name: str = "aegisgraph",
    ) -> str:
        """Format message in RFC 5424 compliance format.

        Format: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        Facility is fixed to 16 (local0). PRI = facility * 8 + severity.
        """
        # Facility 16 (local0)
        pri = 16 * 8 + severity
        version = 1
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        proc_id = "-"
        
        # Format structured data: [exampleSDID@32473 key="value"] or nilvalue '-'
        sd_str = "-"
        if structured_data:
            sd_elements = []
            for k, v in structured_data.items():
                # Escape double quotes and backslashes in value
                clean_v = str(v).replace("\\", "\\\\").replace('"', '\\"')
                sd_elements.append(f'{k}="{clean_v}"')
            sd_str = f"[meta@42424 {' '.join(sd_elements)}]"

        return f"<{pri}>{version} {timestamp} {hostname} {app_name} {proc_id} {msg_id} {sd_str} {message}"

    def send(self, formatted_message: str) -> bool:
        """Send a formatted message over UDP to the syslog receiver."""
        if not self.enabled:
            return False
        
        try:
            # We open a socket, send, and close. Using UDP means this is non-blocking.
            with socket.socket(socket.AF_INET, self.socket_type) as s:
                s.sendto(formatted_message.encode("utf-8"), (self.host, self.port))
            return True
        except Exception as e:
            logger.error(f"Failed to transmit syslog message: {e}")
            return False

    def log_event(
        self,
        msg_id: str,
        message: str,
        severity: int = 6,  # 6 = Info, 4 = Warning, 3 = Error
        metadata: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Log a generic event via syslog client."""
        formatted = self.format_rfc5424(
            severity=severity,
            msg_id=msg_id,
            message=message,
            structured_data=metadata,
        )
        return self.send(formatted)
