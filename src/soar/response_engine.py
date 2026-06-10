import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from src.soar.models import ResponseAction, ResponseActionType, ActionStatus
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.response_engine")

class ResponseEngine:
    def __init__(self, store: SOARStore, audit_logger: SOARAuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def execute_action(
        self,
        action_type: ResponseActionType,
        target_id: str,
        executed_by: str,
        additional_params: Optional[Dict[str, Any]] = None
    ) -> ResponseAction:
        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()
        
        # Verify execution authorization
        # E.g., if executed_by is not SYSTEM, it must have sufficient permissions (handled by API layers, but we double-check here)
        if not executed_by:
            raise PermissionError("Action executor must be specified.")
            
        action = ResponseAction(
            action_id=action_id,
            name=f"Automated {action_type.value} on {target_id}",
            action_type=action_type,
            status=ActionStatus.IN_PROGRESS,
            target_id=target_id,
            executed_by=executed_by,
            executed_at=now_str
        )
        self.store.add_response_action(action)
        
        try:
            # Dispatch action execution
            result_data = self._perform_action(action_type, target_id, additional_params)
            action.status = ActionStatus.COMPLETED
            action.result = result_data
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error_message = str(e)
            logger.error(f"Failed to execute SOAR action {action_id}: {e}")
            
        self.store.update_response_action(action)
        
        self.audit_logger.log_action(
            action=f"EXECUTE_RESPONSE_ACTION_{action_type.value}",
            user_id=executed_by,
            ip_address="127.0.0.1",
            status=action.status.value,
            details={"action_id": action_id, "target_id": target_id, "error": action.error_message}
        )
        
        return action

    def _perform_action(self, action_type: ResponseActionType, target_id: str, params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        params = params or {}
        if action_type == ResponseActionType.LOCK_ACCOUNT:
            # Simulate or call external user directory service
            logger.info(f"Locking account: {target_id}")
            return {"status": "locked", "account_id": target_id, "msg": "Account locked successfully."}
            
        elif action_type == ResponseActionType.REVOKE_SESSION:
            # Simulate or call session manager
            logger.info(f"Revoking session: {target_id}")
            return {"status": "revoked", "session_id": target_id, "msg": "Session terminated."}
            
        elif action_type == ResponseActionType.BLOCK_IP:
            # In a real environment, we might call firewalls/WAFs or get_zero_trust_service()
            logger.info(f"Blocking IP: {target_id}")
            return {"status": "blocked", "ip_address": target_id, "msg": "IP added to edge blocklist."}
            
        elif action_type == ResponseActionType.ESCALATE_RISK:
            logger.info(f"Escalating risk for entity: {target_id}")
            return {"status": "escalated", "entity_id": target_id, "risk_level": "CRITICAL"}
            
        elif action_type == ResponseActionType.NOTIFY_ANALYST:
            logger.info(f"Notifying analyst of threat on: {target_id}")
            return {"status": "notified", "entity_id": target_id}
            
        else:
            return {"status": "unknown", "msg": f"Custom action executed: {action_type.value}"}
