"""
Investigation Agent
AegisGraph Sentinel Enterprise
AI-powered fraud investigation with evidence gathering and case management
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass

from src.agents.base import (
    BaseAgent,
    AgentType,
    AgentTask,
    AgentStatus,
    TaskPriority,
    LLMClient,
    tool_registry,
)
from src.exceptions import InvestigationError


@dataclass
class InvestigationContext:
    """Context for fraud investigation"""
    case_id: str
    primary_account: str
    transaction_ids: List[str]
    entities_involved: List[str]
    timeline_start: Optional[datetime] = None
    timeline_end: Optional[datetime] = None
    risk_indicators: List[str] = None
    evidence_collected: List[Dict] = None
    findings: List[str] = None

    def __post_init__(self):
        self.risk_indicators = self.risk_indicators or []
        self.evidence_collected = self.evidence_collected or []
        self.findings = self.findings or []


@dataclass
class InvestigationReport:
    """Investigation report"""
    case_id: str
    summary: str
    risk_score: float
    confidence: float
    findings: List[Dict[str, Any]]
    recommendations: List[str]
    evidence_chain: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    related_entities: List[str]
    next_steps: List[str]
    created_at: datetime


class InvestigationAgent(BaseAgent):
    """AI Agent for automated fraud investigation"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            agent_id=config.get("agent_id", "investigation_agent_001"),
            agent_type=AgentType.INVESTIGATION,
            config=config,
        )
        
        # Initialize LLM client
        self.llm = LLMClient({
            "model": config.get("llm_model", "gpt-4"),
            "temperature": 0.3,  # Lower temp for factual analysis
            "api_key": config.get("openai_api_key"),
        })
        
        # Investigation parameters
        self.max_depth = config.get("max_depth", 3)
        self.max_entities = config.get("max_entities", 100)
        self.evidence_threshold = config.get("evidence_threshold", 0.7)
        
        # Register capabilities
        self._register_capabilities()

    def _register_capabilities(self):
        """Register agent capabilities"""
        self.register_capability(
            name="fraud_investigation",
            description="Automated fraud investigation with evidence gathering",
            input_schema={
                "case_id": "string",
                "account_id": "string",
                "transaction_ids": "array<string>",
            },
            output_schema={
                "report": "object",
                "risk_score": "float",
                "confidence": "float",
            },
            execution_time_estimate=60.0,
        )
        
        self.register_capability(
            name="money_flow_analysis",
            description="Analyze money flow patterns in transactions",
            input_schema={
                "account_id": "string",
                "start_date": "string",
                "end_date": "string",
            },
            output_schema={
                "flows": "array<object>",
                "patterns": "array<string>",
            },
            execution_time_estimate=30.0,
        )
        
        self.register_capability(
            name="entity_network_analysis",
            description="Analyze entity relationships and networks",
            input_schema={
                "entity_id": "string",
                "depth": "integer",
            },
            output_schema={
                "network": "object",
                "connections": "array<object>",
            },
            execution_time_estimate=45.0,
        )

    async def initialize(self) -> bool:
        """Initialize the agent"""
        logger = __import__('logging').getLogger(__name__)
        logger.info(f"Initializing {self.agent_id}")
        
        # Load ML models
        # In production, load HTGNN model and other ML models
        self.model_loaded = True
        
        # Initialize tool connections
        # graph_tool = tool_registry.get("graph")
        # await graph_tool.verify_connection()
        
        self.status = AgentStatus.IDLE
        return True

    async def execute(self, task: AgentTask) -> Dict[str, Any]:
        """Execute investigation task"""
        input_data = task.input_data
        action = input_data.get("action", "fraud_investigation")
        
        if action == "fraud_investigation":
            return await self.investigate_fraud(input_data)
        elif action == "money_flow_analysis":
            return await self.analyze_money_flow(input_data)
        elif action == "entity_network_analysis":
            return await self.analyze_entity_network(input_data)
        elif action == "evidence_collection":
            return await self.collect_evidence(input_data)
        elif action == "generate_report":
            return await self.generate_investigation_report(input_data)
        else:
            raise InvestigationError(f"Unknown action: {action}")

    async def investigate_fraud(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Investigate fraud case"""
        case_id = input_data.get("case_id")
        account_id = input_data.get("account_id")
        transaction_ids = input_data.get("transaction_ids", [])
        
        # Create investigation context
        context = InvestigationContext(
            case_id=case_id,
            primary_account=account_id,
            transaction_ids=transaction_ids,
            entities_involved=[account_id],
        )
        
        # Step 1: Gather initial evidence
        initial_evidence = await self._gather_initial_evidence(context)
        context.evidence_collected.extend(initial_evidence)
        
        # Step 2: Analyze transaction patterns
        patterns = await self._analyze_transaction_patterns(context)
        context.risk_indicators.extend(patterns)
        
        # Step 3: Trace money flow
        money_flows = await self._trace_money_flow(context)
        
        # Step 4: Identify connected entities
        connections = await self._identify_connected_entities(context)
        
        # Step 5: Build entity network
        network = await self._build_entity_network(context)
        
        # Step 6: Generate risk assessment
        risk_assessment = await self._assess_risk(context)
        
        # Step 7: Generate report
        report = await self._generate_report(context, risk_assessment)
        
        return {
            "case_id": case_id,
            "risk_score": risk_assessment["score"],
            "confidence": risk_assessment["confidence"],
            "report": report,
            "money_flows": money_flows,
            "connections": connections,
            "network": network,
            "risk_indicators": context.risk_indicators,
        }

    async def analyze_money_flow(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze money flow patterns"""
        account_id = input_data.get("account_id")
        start_date = input_data.get("start_date")
        end_date = input_data.get("end_date")
        
        # Query graph database for money flow
        graph_tool = tool_registry.get("graph")
        cypher = """
        MATCH (a:Account {id: $account_id})-[t:TRANSFER]->(b:Account)
        WHERE t.timestamp >= $start_date AND t.timestamp <= $end_date
        RETURN a, t, b
        ORDER BY t.timestamp
        """
        
        results = await graph_tool.execute(cypher, {
            "account_id": account_id,
            "start_date": start_date,
            "end_date": end_date,
        })
        
        # Analyze flow patterns
        flows = self._extract_money_flows(results)
        patterns = self._identify_flow_patterns(flows)
        
        return {
            "account_id": account_id,
            "flows": flows,
            "patterns": patterns,
            "total_volume": sum(f["amount"] for f in flows),
            "average_transaction": sum(f["amount"] for f in flows) / max(1, len(flows)),
        }

    async def analyze_entity_network(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze entity network"""
        entity_id = input_data.get("entity_id")
        depth = input_data.get("depth", self.max_depth)
        
        # Build network recursively
        network = await self._recursive_network_build(entity_id, depth, visited=set())
        
        return {
            "entity_id": entity_id,
            "network": network,
            "connections": self._count_connections(network),
            "suspicious_patterns": self._detect_suspicious_patterns(network),
        }

    async def collect_evidence(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Collect evidence for investigation"""
        case_id = input_data.get("case_id")
        evidence_types = input_data.get("evidence_types", ["transactions", "accounts", "devices", "ips"])
        
        evidence = {}
        
        if "transactions" in evidence_types:
            evidence["transactions"] = await self._collect_transaction_evidence(case_id)
        
        if "accounts" in evidence_types:
            evidence["accounts"] = await self._collect_account_evidence(case_id)
        
        if "devices" in evidence_types:
            evidence["devices"] = await self._collect_device_evidence(case_id)
        
        if "network" in evidence_types:
            evidence["network"] = await self._collect_network_evidence(case_id)
        
        # Add timestamp and hash for chain of custody
        timestamp = datetime.utcnow().isoformat()
        
        return {
            "case_id": case_id,
            "evidence": evidence,
            "collected_at": timestamp,
            "evidence_hash": self._calculate_evidence_hash(evidence),
        }

    async def generate_investigation_report(
        self,
        input_data: Dict[str, Any],
    ) -> InvestigationReport:
        """Generate comprehensive investigation report"""
        case_id = input_data.get("case_id")
        context = input_data.get("context")  # InvestigationContext serialized
        
        # Use LLM to generate coherent narrative
        analysis_data = {
            "case_id": case_id,
            "evidence": context.get("evidence_collected", []),
            "risk_indicators": context.get("risk_indicators", []),
            "findings": context.get("findings", []),
        }
        
        prompt = f"""
        Generate a comprehensive fraud investigation report for case {case_id}.
        
        Evidence collected: {analysis_data['evidence']}
        Risk indicators: {analysis_data['risk_indicators']}
        Findings: {analysis_data['findings']}
        
        Provide:
        1. Executive summary
        2. Detailed findings
        3. Evidence chain
        4. Recommendations
        5. Next steps
        """
        
        system_prompt = """You are a fraud investigation expert. Generate detailed, 
        factual reports based on evidence. Be precise and include specific details."""
        
        llm_summary = await self.llm.generate(prompt, system_prompt)
        
        report = InvestigationReport(
            case_id=case_id,
            summary=llm_summary,
            risk_score=input_data.get("risk_score", 0.5),
            confidence=input_data.get("confidence", 0.8),
            findings=analysis_data["findings"],
            recommendations=self._generate_recommendations(analysis_data),
            evidence_chain=analysis_data["evidence"],
            timeline=self._build_timeline(analysis_data),
            related_entities=context.get("entities_involved", []),
            next_steps=self._generate_next_steps(analysis_data),
            created_at=datetime.utcnow(),
        )
        
        return report

    # Private helper methods
    async def _gather_initial_evidence(self, context: InvestigationContext) -> List[Dict]:
        """Gather initial evidence for case"""
        evidence = []
        
        # Query transaction data
        graph_tool = tool_registry.get("graph")
        
        cypher = """
        MATCH (a:Account {id: $account_id})-[t:TRANSFER]->(b:Account)
        WHERE t.timestamp > datetime() - duration('P7D')
        RETURN t, b
        ORDER BY t.timestamp DESC
        LIMIT 100
        """
        
        transactions = await graph_tool.execute(cypher, {
            "account_id": context.primary_account,
        })
        
        for txn in transactions.get("rows", []):
            evidence.append({
                "type": "transaction",
                "data": txn,
                "collected_at": datetime.utcnow().isoformat(),
            })
        
        return evidence

    async def _analyze_transaction_patterns(self, context: InvestigationContext) -> List[str]:
        """Analyze transaction patterns for risk indicators"""
        patterns = []
        
        # Check for high velocity
        # Check for round amounts
        # Check for timing patterns
        # Check for beneficiary patterns
        
        return patterns

    async def _trace_money_flow(self, context: InvestigationContext) -> List[Dict]:
        """Trace money flow through accounts"""
        flows = []
        
        # Implement money flow tracing
        # Follow the money through the network
        
        return flows

    async def _identify_connected_entities(self, context: InvestigationContext) -> List[Dict]:
        """Identify entities connected to primary account"""
        connections = []
        
        # Query for connected accounts, devices, IPs, etc.
        
        return connections

    async def _build_entity_network(self, context: InvestigationContext) -> Dict:
        """Build entity network graph"""
        network = {
            "nodes": [],
            "edges": [],
        }
        
        # Recursively build network
        
        return network

    async def _recursive_network_build(
        self,
        entity_id: str,
        depth: int,
        visited: set,
    ) -> Dict:
        """Recursively build entity network"""
        if depth <= 0 or entity_id in visited:
            return {"id": entity_id, "children": []}
        
        visited.add(entity_id)
        
        # Query for connected entities
        # Build recursive structure
        
        return {
            "id": entity_id,
            "type": "account",
            "children": [],
        }

    async def _assess_risk(self, context: InvestigationContext) -> Dict:
        """Assess overall risk"""
        # Calculate risk score based on evidence and indicators
        
        risk_score = 0.5
        confidence = 0.8
        
        # Factor in various indicators
        if len(context.risk_indicators) > 5:
            risk_score += 0.1
        if len(context.evidence_collected) > 10:
            confidence += 0.1
        
        return {
            "score": min(1.0, risk_score),
            "confidence": min(1.0, confidence),
            "factors": context.risk_indicators,
        }

    async def _generate_report(
        self,
        context: InvestigationContext,
        risk_assessment: Dict,
    ) -> Dict:
        """Generate investigation report"""
        return {
            "case_id": context.case_id,
            "summary": "Investigation summary",
            "risk_score": risk_assessment["score"],
            "confidence": risk_assessment["confidence"],
            "findings": context.findings,
            "recommendations": [],
        }

    async def cleanup(self):
        """Cleanup resources"""
        self.status = AgentStatus.IDLE
        self._running = False

    def _extract_money_flows(self, results: Dict) -> List[Dict]:
        """Extract money flows from query results"""
        flows = []
        for row in results.get("rows", []):
            if "t" in row:
                flows.append({
                    "from": row.get("from", ""),
                    "to": row.get("to", ""),
                    "amount": row["t"].get("amount", 0),
                    "timestamp": row["t"].get("timestamp"),
                })
        return flows

    def _identify_flow_patterns(self, flows: List[Dict]) -> List[str]:
        """Identify patterns in money flows"""
        patterns = []
        # Implement pattern detection
        return patterns

    def _count_connections(self, network: Dict) -> int:
        """Count total connections in network"""
        count = len(network.get("edges", []))
        for child in network.get("children", []):
            count += self._count_connections(child)
        return count

    def _detect_suspicious_patterns(self, network: Dict) -> List[str]:
        """Detect suspicious patterns in network"""
        patterns = []
        # Detect cycles, suspicious clustering, etc.
        return patterns

    def _generate_recommendations(self, analysis_data: Dict) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        # Generate actionable recommendations
        return recommendations

    def _build_timeline(self, analysis_data: Dict) -> List[Dict]:
        """Build event timeline"""
        timeline = []
        # Build chronological timeline
        return timeline

    def _generate_next_steps(self, analysis_data: Dict) -> List[str]:
        """Generate next steps for investigation"""
        next_steps = []
        # Generate actionable next steps
        return next_steps

    def _calculate_evidence_hash(self, evidence: Dict) -> str:
        """Calculate hash for evidence chain of custody"""
        import hashlib
        import json
        evidence_str = json.dumps(evidence, sort_keys=True)
        return hashlib.sha256(evidence_str.encode()).hexdigest()

    async def _collect_transaction_evidence(self, case_id: str) -> List[Dict]:
        """Collect transaction evidence"""
        return []

    async def _collect_account_evidence(self, case_id: str) -> List[Dict]:
        """Collect account evidence"""
        return []

    async def _collect_device_evidence(self, case_id: str) -> List[Dict]:
        """Collect device evidence"""
        return []

    async def _collect_network_evidence(self, case_id: str) -> List[Dict]:
        """Collect network evidence"""
        return []