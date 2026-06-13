"""
ServiceNow Integration for AegisGraph Sentinel Enterprise
Bi-directional integration for incident management and ITSM workflows
"""

import json
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ServiceNowConfig:
    """ServiceNow configuration"""
    instance_url: str
    username: str
    password: str
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    table_prefix: str = "u_"  # Custom table prefix


class ServiceNowClient:
    """ServiceNow integration client"""

    def __init__(self, config: ServiceNowConfig):
        self.config = config
        self.base_url = f"https://{config.instance_url}.service-now.com"
        self.table_api = f"{self.base_url}/api/now/table"
        self.session = httpx.AsyncClient(
            auth=(config.username, config.password),
            timeout=30.0,
        )

    async def get_access_token(self) -> str:
        """Get OAuth2 access token"""
        if not self.config.client_id:
            return ""
        
        response = await self.session.post(
            f"{self.base_url}/oauth_token.do",
            data={
                "grant_type": "password",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "username": self.config.username,
                "password": self.config.password,
            },
        )
        
        response.raise_for_status()
        return response.json().get("access_token", "")

    async def create_incident(
        self,
        title: str,
        description: str,
        priority: int = 3,
        category: str = "fraud",
        assignment_group: Optional[str] = None,
        caller_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create ServiceNow incident"""
        incident_data = {
            "short_description": title,
            "description": description,
            "priority": priority,
            "category": category,
            "state": 1,  # New
            "impact": 2,
            "urgency": priority,
        }
        
        if assignment_group:
            incident_data["assignment_group"] = assignment_group
        if caller_id:
            incident_data["caller_id"] = caller_id
        
        return await self._create_record("incident", incident_data)

    async def create_task(
        self,
        incident_id: str,
        title: str,
        description: str,
        task_type: str = "task",
    ) -> Dict[str, Any]:
        """Create task on incident"""
        task_data = {
            "task_type": task_type,
            "short_description": title,
            "description": description,
            "state": -5,  # In Progress
            "parent_id": incident_id,
        }
        
        return await self._create_record("task", task_data)

    async def update_incident(
        self,
        incident_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update incident"""
        return await self._update_record("incident", incident_id, updates)

    async def add_work_note(
        self,
        table: str,
        record_id: str,
        note: str,
    ) -> bool:
        """Add work note to record"""
        try:
            response = await self.session.post(
                f"{self.table_api}/{table}/{record_id}/worknotes",
                json={"work_note": note},
                headers={"Content-Type": "application/json"},
            )
            
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to add work note: {e}")
            return False

    async def _create_record(
        self,
        table: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create record in ServiceNow"""
        try:
            response = await self.session.post(
                f"{self.table_api}/{table}",
                json=data,
                headers={"Content-Type": "application/json"},
            )
            
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to create {table} record: {e}")
            return {"error": str(e)}

    async def _update_record(
        self,
        table: str,
        record_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update record in ServiceNow"""
        try:
            response = await self.session.patch(
                f"{self.table_api}/{table}/{record_id}",
                json=data,
                headers={"Content-Type": "application/json"},
            )
            
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to update {table} record: {e}")
            return {"error": str(e)}

    async def get_record(
        self,
        table: str,
        record_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get record from ServiceNow"""
        try:
            response = await self.session.get(
                f"{self.table_api}/{table}/{record_id}",
                params={"sysparm_display_value": "all"},
            )
            
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to get {table} record: {e}")
            return None

    async def query(
        self,
        table: str,
        filters: Dict[str, Any],
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query records from ServiceNow"""
        try:
            params = {
                "sysparm_limit": limit,
                "sysparm_display_value": "all",
            }
            
            # Build query string
            query_parts = []
            for key, value in filters.items():
                query_parts.append(f"{key}={value}")
            
            if query_parts:
                params["sysparm_query"] = "^".join(query_parts)
            
            response = await self.session.get(
                f"{self.table_api}/{table}",
                params=params,
            )
            
            response.raise_for_status()
            result = response.json()
            
            return result.get("result", [])
            
        except Exception as e:
            logger.error(f"Failed to query {table}: {e}")
            return []


# ServiceNow Incident Handler
class ServiceNowIncidentHandler:
    """Handle fraud cases as ServiceNow incidents"""

    def __init__(self, client: ServiceNowClient):
        self.client = client

    async def create_fraud_incident(
        self,
        case_id: str,
        fraud_details: Dict[str, Any],
        priority: int = 2,
    ) -> Dict[str, Any]:
        """Create incident for fraud case"""
        title = f"Fraud Alert: {case_id} - {fraud_details.get('type', 'Unknown')}"
        description = f"""
AegisGraph Sentinel Fraud Alert
        
Case ID: {case_id}
Risk Score: {fraud_details.get('risk_score', 'N/A')}
Account: {fraud_details.get('account_id', 'Unknown')}
Amount: {fraud_details.get('amount', 'Unknown')}

Details:
{json.dumps(fraud_details, indent=2)}

Please investigate and take appropriate action.
        """.strip()
        
        incident = await self.client.create_incident(
            title=title,
            description=description,
            priority=priority,
            category="fraud",
            assignment_group=fraud_details.get("assignment_group"),
        )
        
        # Add case link as additional detail
        if "sys_id" in incident:
            await self.client.add_work_note(
                "incident",
                incident["sys_id"],
                f"AegisGraph Case: {case_id}",
            )
        
        return incident

    async def update_case_status(
        self,
        incident_id: str,
        status: str,
        notes: Optional[str] = None,
    ):
        """Update incident status from case management"""
        status_map = {
            "investigating": 2,  # In Progress
            "resolved": 7,  # Resolved
            "closed": 10,  # Closed
            "pending": 3,  # Pending
        }
        
        updates = {
            "state": status_map.get(status, 1),
        }
        
        await self.client.update_incident(incident_id, updates)
        
        if notes:
            await self.client.add_work_note("incident", incident_id, notes)

    async def link_evidence(
        self,
        incident_id: str,
        evidence: Dict[str, Any],
    ):
        """Link evidence to incident"""
        note = f"""
Evidence Attached from AegisGraph Sentinel:
        
Type: {evidence.get('type', 'Unknown')}
Description: {evidence.get('description', 'N/A')}
Hash: {evidence.get('hash', 'N/A')}
Collected: {evidence.get('collected_at', 'N/A')}
        """.strip()
        
        await self.client.add_work_note("incident", incident_id, note)


# ServiceNow Workflow Integration
class ServiceNowWorkflowIntegration:
    """Integrate with ServiceNow workflows"""

    def __init__(self, client: ServiceNowClient):
        self.client = client

    async def trigger_investigation_workflow(
        self,
        case_id: str,
        case_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Trigger ServiceNow investigation workflow"""
        # Create parent incident
        incident = await self.client.create_incident(
            title=f"Investigation Required: {case_id}",
            description=f"Investigation workflow triggered by AegisGraph Sentinel",
            priority=2,
        )
        
        # Create investigation tasks
        tasks = []
        
        # Task 1: Initial Review
        task1 = await self.client.create_task(
            incident_id=incident.get("sys_id", ""),
            title="Initial Case Review",
            description="Review fraud case details and determine investigation scope",
            task_type="task",
        )
        tasks.append(task1)
        
        # Task 2: Evidence Collection
        task2 = await self.client.create_task(
            incident_id=incident.get("sys_id", ""),
            title="Collect Evidence",
            description="Gather and preserve all evidence related to the case",
            task_type="task",
        )
        tasks.append(task2)
        
        # Task 3: Account Analysis
        task3 = await self.client.create_task(
            incident_id=incident.get("sys_id", ""),
            title="Account Analysis",
            description="Analyze involved accounts and transaction history",
            task_type="task",
        )
        tasks.append(task3)
        
        # Task 4: Report Generation
        task4 = await self.client.create_task(
            incident_id=incident.get("sys_id", ""),
            title="Generate Report",
            description="Prepare investigation report with findings and recommendations",
            task_type="task",
        )
        tasks.append(task4)
        
        return {
            "incident": incident,
            "tasks": tasks,
        }

    async def close_case_workflow(
        self,
        incident_id: str,
        resolution: Dict[str, Any],
    ) -> bool:
        """Complete ServiceNow workflow on case closure"""
        await self.client.update_incident(
            incident_id,
            {
                "state": 7,  # Resolved
                "close_code": resolution.get("code", "resolved"),
                "close_notes": resolution.get("notes", ""),
            },
        )
        
        await self.client.add_work_note(
            "incident",
            incident_id,
            f"Case resolved by AegisGraph Sentinel. Resolution: {resolution.get('summary', 'N/A')}",
        )
        
        return True