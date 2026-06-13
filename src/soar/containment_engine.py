import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional
from src.soar.models import ContainmentAction, ContainmentType, ActionStatus
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.containment_engine")

class ContainmentEngine:
    def __init__(self, store: SOARStore, audit_logger: SOARAuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger
        # Protection list of system entities that should never be contained
        self.whitelist = {"admin", "system", "super_admin", "127.0.0.1", "localhost", "safe_user", "central_switch"}

    def trigger_containment(
        self,
        containment_type: ContainmentType,
        target_entity: str,
        initiated_by: str,
        duration_seconds: Optional[int] = None
    ) -> ContainmentAction:
        containment_id = f"CNT-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()
        
        # Safeguard: Whitelist check
        if target_entity.lower() in self.whitelist:
            self.audit_logger.log_action(
                action="BLOCK_CONTAINMENT_BYPASSED",
                user_id=initiated_by,
                ip_address="127.0.0.1",
                status="FAILED",
                details={"target_entity": target_entity, "reason": "Target entity is in the protection whitelist"}
            )
            raise ValueError(f"Cannot contain whitelisted system-critical entity: {target_entity}")

        # Safeguard: Simple rate limiter (max 5 active containments in last 60 seconds)
        recent_actions = [
            a for a in self.store.list_containment_actions()
            # Parse and check diff
            if (datetime.now(timezone.utc) - datetime.fromisoformat(a.timestamp)).total_seconds() < 60
        ]
        if len(recent_actions) >= 5:
            self.audit_logger.log_action(
                action="BLOCK_CONTAINMENT_BYPASSED",
                user_id=initiated_by,
                ip_address="127.0.0.1",
                status="FAILED",
                details={"target_entity": target_entity, "reason": "Rate limit exceeded (max 5 per minute)"}
            )
            raise RuntimeError("Containment rate limit exceeded. Max 5 containment actions allowed per minute.")

        action = ContainmentAction(
            containment_id=containment_id,
            type=containment_type,
            status=ActionStatus.COMPLETED,  # Active
            target_entity=target_entity,
            initiated_by=initiated_by,
            timestamp=now_str,
            duration_seconds=duration_seconds
        )
        
        self.store.add_containment_action(action)
        
        self.audit_logger.log_action(
            action=f"TRIGGER_CONTAINMENT_{containment_type.value}",
            user_id=initiated_by,
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"containment_id": containment_id, "target_entity": target_entity}
        )
        
        return action

    def release_containment(self, containment_id: str, released_by: str) -> Optional[ContainmentAction]:
        action = self.store.get_containment_action(containment_id)
        if not action:
            return None
            
        action.status = ActionStatus.COMPLETED
        action.released_at = datetime.now(timezone.utc).isoformat()
        self.store.update_containment_action(action)
        
        self.audit_logger.log_action(
            action="RELEASE_CONTAINMENT",
            user_id=released_by,
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"containment_id": containment_id, "target_entity": action.target_entity}
        )
        
        return action
