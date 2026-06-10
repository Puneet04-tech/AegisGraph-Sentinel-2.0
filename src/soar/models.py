from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime, timezone

class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"

class InvestigationStatus(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    COMPLETE = "COMPLETE"
    SUSPENDED = "SUSPENDED"

class ResponseActionType(str, Enum):
    LOCK_ACCOUNT = "LOCK_ACCOUNT"
    REVOKE_SESSION = "REVOKE_SESSION"
    ESCALATE_RISK = "ESCALATE_RISK"
    NOTIFY_ANALYST = "NOTIFY_ANALYST"
    BLOCK_IP = "BLOCK_IP"
    CUSTOM = "CUSTOM"

class ActionStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ContainmentType(str, Enum):
    NETWORK_ISOLATE = "NETWORK_ISOLATE"
    ACCOUNT_SUSPEND = "ACCOUNT_SUSPEND"
    API_BLOCK = "API_BLOCK"

class WorkflowState(str, Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PAUSED = "PAUSED"

class Incident(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    incident_id: str
    title: str
    description: str
    severity: ThreatSeverity
    status: IncidentStatus = IncidentStatus.NEW
    source: str
    created_at: str
    updated_at: str
    entities: List[str] = []
    assigned_analyst: Optional[str] = None
    tags: List[str] = []
    metadata: Dict[str, Any] = {}

class Playbook(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    playbook_id: str
    name: str
    description: str
    version: str
    tasks: List[Dict[str, Any]] = []
    rules: Dict[str, Any] = {}
    status: str = "Active"
    created_at: str

class Investigation(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    investigation_id: str
    incident_id: str
    status: InvestigationStatus = InvestigationStatus.PENDING
    findings: List[str] = []
    evidence: List[Dict[str, Any]] = []
    start_time: str
    end_time: Optional[str] = None
    analyst_notes: List[str] = []

class ResponseAction(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    action_id: str
    name: str
    action_type: ResponseActionType
    status: ActionStatus = ActionStatus.PENDING
    target_id: str
    executed_by: str
    executed_at: str
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class ThreatCorrelation(BaseModel):
    correlation_id: str
    name: str
    correlation_score: float
    matched_indicators: List[str] = []
    linked_incidents: List[str] = []
    timestamp: str

class ContainmentAction(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    containment_id: str
    type: ContainmentType
    status: ActionStatus = ActionStatus.PENDING
    target_entity: str
    initiated_by: str
    timestamp: str
    duration_seconds: Optional[int] = None
    released_at: Optional[str] = None

class WorkflowExecution(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    execution_id: str
    playbook_id: str
    incident_id: str
    state: WorkflowState = WorkflowState.RUNNING
    current_task_index: int = 0
    task_results: Dict[str, Any] = {}
    start_time: str
    end_time: Optional[str] = None

class AutomationTask(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    task_id: str
    name: str
    task_type: str
    parameters: Dict[str, Any] = {}
    status: ActionStatus = ActionStatus.PENDING
    error_message: Optional[str] = None

class CaseEnrichment(BaseModel):
    enrichment_id: str
    entity_id: str
    threat_intel_data: Dict[str, Any] = {}
    behavior_summary: Dict[str, Any] = {}
    resolved_entities: List[str] = []
    updated_at: str

class AuditRecord(BaseModel):
    record_id: str
    action: str
    user_id: str
    ip_address: str
    timestamp: str
    details: Dict[str, Any] = {}
    status: str
