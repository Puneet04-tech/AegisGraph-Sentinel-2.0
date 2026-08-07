import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from src.soar.models import AuditRecord
from src.soar.store import SOARStore
from src.security.secure_logging import safe_log_metadata

logger = logging.getLogger("aegis.soar.audit")

class SOARAuditLogger:
    def __init__(self, store: SOARStore) -> None:
        self.store = store

    def log_action(self, action: str, user_id: str, ip_address: str, status: str, details: Dict[str, Any]) -> AuditRecord:
        record = AuditRecord(
            record_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
            action=action,
            user_id=user_id,
            ip_address=ip_address,
            timestamp=datetime.now(timezone.utc).isoformat(),
            details=details,
            status=status
        )
        self.store.add_audit_record(record)
        logger.info(f"[SOAR AUDIT] Action: {action} | User: {user_id} | Status: {status} | Details: {json.dumps(safe_log_metadata(details))}")
        return record

def json_details(details: Dict[str, Any]) -> str:
    try:
        import json
        return json.dumps(details)
    except Exception:
        return str(details)
