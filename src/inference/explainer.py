"""
Aegis-Oracle: Explainable AI Module

Generates human-readable explanations for fraud detection decisions
for regulatory compliance and transparency.
"""
# Working on explainable AI for regulatory compliance

from typing import Dict, List, Optional
import numpy as np
import torch
from torch_geometric.explain import Explainer, GNNExplainer

class AegisModelExplainer:
    """
    Compliance engine for the HTGNN. Extracts the critical subgraph 
    responsible for triggering a fraud alert using Mutual Information.
    """
    def __init__(self, model):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = model.to(self.device)
        self.model.eval()
        self._explainer = None

    def _get_explainer(self):
        if self._explainer is None:
            self._explainer = Explainer(
                model=self.model,
                algorithm=GNNExplainer(epochs=200),
                explanation_type='model',
                node_mask_type='attributes',
                edge_mask_type='object',
                model_config=dict(
                    mode='binary_classification',
                    task_level='node',
                    return_type='probs',
                ),
            )
        return self._explainer

    def extract_critical_topology(self, node_features, edge_index, target_node_idx):
        """Returns a list of the most suspicious connections."""
        x = node_features.to(self.device)
        edge_idx = edge_index.to(self.device)

        with torch.enable_grad():
            explanation = self._get_explainer()(x, edge_idx, index=target_node_idx)
        
        edge_weights = explanation.edge_mask
        k = min(10, edge_weights.size(0))
        top_edges = torch.topk(edge_weights, k)
        
        critical_path = []
        for idx in top_edges.indices:
            weight = edge_weights[idx].item()
            if weight > 0.5:
                critical_path.append({
                    "source_node": edge_idx[0, idx].item(), 
                    "target_node": edge_idx[1, idx].item(), 
                    "fraud_contribution": weight
                })
        return critical_path

class AegisOracle:
    """
    Explainable AI engine for fraud detection
    
    Generates natural language explanations for:
    - Why a transaction was blocked/flagged
    - Which factors contributed most
    - Recommended actions
    
    Args:
        detail_level: 'low', 'medium', or 'high'
    """
    
    def __init__(self, detail_level: str = 'high'):
        self.detail_level = detail_level
    
    def explain_decision(
        self,
        transaction: dict,
        risk_result: dict,
        graph_patterns: Optional[dict] = None,
    ) -> Dict[str, str]:
        """
        Generate explanation for fraud detection decision
        
        Args:
            transaction: Transaction details
            risk_result: Risk scoring result from RiskScorer
            graph_patterns: Detected graph patterns
        
        Returns:
            Dictionary with explanation components
        """
        risk_score = risk_result['risk_score']
        decision = risk_result['decision']
        breakdown = risk_result['breakdown']
        confidence = risk_result['confidence']
        
        # Main explanation
        explanation = self._generate_explanation(
            transaction,
            risk_score,
            decision,
            breakdown,
            graph_patterns,
        )
        
        # Detailed factors
        factors = self._list_risk_factors(breakdown, graph_patterns)
        
        # Recommended action
        action = self._recommend_action(decision, confidence, risk_score)
        
        # Executive summary
        summary = self._generate_summary(transaction, decision, confidence)
        
        return {
            'summary': summary,
            'explanation': explanation,
            'factors': factors,
            'recommended_action': action,
            'confidence': f"{confidence * 100:.1f}%",
            'decision': decision,
        }
    
    def _generate_explanation(
        self,
        transaction: dict,
        risk_score: float,
        decision: str,
        breakdown: dict,
        graph_patterns: Optional[dict],
    ) -> str:
        """Generate detailed explanation"""
        
        # Extract transaction info
        txn_id = transaction.get('transaction_id', 'N/A')
        source = transaction.get('source_account', 'N/A')
        target = transaction.get('target_account', 'N/A')
        amount = transaction.get('amount', 0)
        currency = transaction.get('currency', 'INR')
        
        # Start explanation
        lines = []
        lines.append(f"Transaction {txn_id}: {currency} {amount:,.2f} from {source} to {target}")
        lines.append("")
        lines.append(f"**Decision: {decision}** (Risk Score: {risk_score:.2%})")
        lines.append("")
        
        # Reason based on decision
        if decision == 'BLOCK':
            lines.append("**REASON FOR BLOCKING:**")
        elif decision == 'REVIEW':
            lines.append("**REASON FOR REVIEW:**")
        else:
            lines.append("**ASSESSMENT:**")
        
        lines.append("")
        
        # Analyze risk components
        sorted_components = sorted(breakdown.items(), key=lambda x: x[1], reverse=True)
        
        for component, score in sorted_components:
            if score >= 0.7:  # High risk component
                lines.append(f"- **{component.capitalize()} Risk: HIGH ({score:.1%})**")
                lines.append(f"  {self._explain_component(component, score, transaction, graph_patterns)}")
            elif score >= 0.5:
                if self.detail_level in ['medium', 'high']:
                    lines.append(f"- {component.capitalize()} Risk: Moderate ({score:.1%})")
                    lines.append(f"  {self._explain_component(component, score, transaction, graph_patterns)}")
        
        # Graph patterns
        if graph_patterns:
            lines.append("")
            lines.append("**Network Analysis:**")
            lines.extend(self._explain_graph_patterns(graph_patterns))
        
        return "\n".join(lines)
    
    def _explain_component(
        self,
        component: str,
        score: float,
        transaction: dict,
        graph_patterns: Optional[dict],
    ) -> str:
        """Explain individual risk component"""
        
        if component == 'graph':
            if graph_patterns:
                if graph_patterns.get('chain_detected'):
                    return f"Account is part of a suspicious transaction chain with {graph_patterns.get('chain_length', 0)} hops."
                if graph_patterns.get('star_topology'):
                    return f"Account exhibits star topology pattern (central hub with {graph_patterns.get('num_branches', 0)} branches)."
            return "Network structure analysis indicates suspicious connectivity patterns."
        
        elif component == 'velocity':
            return "Unusually rapid transaction activity detected (high kinetic energy)."
        
        elif component == 'behavior':
            if score >= 0.7:
                return "Behavioral biometrics indicate high stress or hesitation during transaction (potential coercion)."
            return "Minor behavioral anomalies detected in typing patterns."
        
        elif component == 'entropy':
            if score >= 0.7:
                return "Account connects to highly diverse, random entities (typical of mule accounts)."
            return "Network diversity suggests some irregularity in connection patterns."
        
        return "Elevated risk detected."
    
    def _explain_graph_patterns(self, graph_patterns: dict) -> List[str]:
        """Explain detected graph patterns"""
        explanations = []
        
        if graph_patterns.get('chain_detected'):
            chain_length = graph_patterns.get('chain_length', 0)
            explanations.append(f"  • Sequential transaction chain detected ({chain_length} accounts)")
        
        if graph_patterns.get('star_topology'):
            num_branches = graph_patterns.get('num_branches', 0)
            explanations.append(f"  • Star disbursement pattern ({num_branches} recipient accounts)")
        
        if graph_patterns.get('rapid_movement'):
            time = graph_patterns.get('total_time_seconds', 0)
            explanations.append(f"  • Rapid fund movement (completed in {time:.0f} seconds)")
        
        if graph_patterns.get('new_accounts'):
            count = graph_patterns.get('new_account_count', 0)
            explanations.append(f"  • {count} recently created accounts involved")
        
        # --- NEW DEEP LEARNING EXPLAINER INTEGRATION ---
        if graph_patterns.get('critical_topology'):
            explanations.append("\n  **Mathematical GNN Subgraph Interrogation (Top Edges):**")
            for edge in graph_patterns['critical_topology']:
                src = edge['source_node']
                dst = edge['target_node']
                weight = edge['fraud_contribution']
                explanations.append(f"  • Suspicious Edge [Node {src} -> Node {dst}]: AI Impact Weight {weight:.4f}")

        if not explanations:
            explanations.append("  • Structural anomalies in transaction network")
        
        return explanations
    
    def _list_risk_factors(
        self,
        breakdown: dict,
        graph_patterns: Optional[dict],
    ) -> List[str]:
        """List prominent risk factors"""
        factors = []
        
        # Sort components by risk
        sorted_components = sorted(breakdown.items(), key=lambda x: x[1], reverse=True)
        
        for component, score in sorted_components:
            if score >= 0.6:
                factor_name = {
                    'graph': 'Suspicious network structure',
                    'velocity': 'High transaction velocity',
                    'behavior': 'Abnormal user behavior',
                    'entropy': 'Irregular connection diversity',
                }[component]
                factors.append(f"{factor_name} ({score:.1%})")
        
        # Add graph pattern factors
        if graph_patterns:
            if graph_patterns.get('chain_detected'):
                factors.append("Transaction chain pattern detected")
            if graph_patterns.get('star_topology'):
                factors.append("Star disbursement pattern detected")
        
        return factors
    
    def _recommend_action(
        self,
        decision: str,
        confidence: float,
        risk_score: float,
    ) -> str:
        """Recommend action for analysts"""
        
        if decision == 'BLOCK':
            if confidence >= 0.95:
                return ("**BLOCK TRANSACTION** - High confidence fraud detection. "
                       "Initiate investigation, freeze involved accounts, and alert law enforcement.")
            elif confidence >= 0.80:
                return ("**BLOCK + REVIEW** - Strong fraud indicators. "
                       "Block transaction and conduct immediate manual review.")
            else:
                return ("**BLOCK + URGENT REVIEW** - Multiple risk factors but moderate confidence. "
                       "Block transaction pending urgent analyst review.")
        
        elif decision == 'REVIEW':
            if risk_score >= 0.80:
                return ("**HIGH PRIORITY REVIEW** - Elevated risk score. "
                       "Analyst review required within 15 minutes.")
            else:
                return ("**STANDARD REVIEW** - Moderate risk indicators. "
                       "Route to fraud analyst queue for assessment.")
        
        else:  # ALLOW
            if risk_score >= 0.40:
                return "**ALLOW + MONITOR** - Transaction approved but continue monitoring account activity."
            else:
                return "**ALLOW** - Transaction appears legitimate. Proceed normally."
    
    def _generate_summary(
        self,
        transaction: dict,
        decision: str,
        confidence: float,
    ) -> str:
        """Generate executive summary"""
        
        amount = transaction.get('amount', 0)
        currency = transaction.get('currency', 'INR')
        
        if decision == 'BLOCK':
            return (f"Transaction of {currency} {amount:,.2f} BLOCKED due to high fraud risk. "
                   f"Confidence: {confidence:.1%}.")
        elif decision == 'REVIEW':
            return (f"Transaction of {currency} {amount:,.2f} flagged for REVIEW due to suspicious patterns. "
                   f"Confidence: {confidence:.1%}.")
        else:
            return (f"Transaction of {currency} {amount:,.2f} APPROVED. "
                   f"No significant fraud indicators detected.")


def generate_explanation(
    transaction: dict,
    risk_result: dict,
    graph_patterns: Optional[dict] = None,
    detail_level: str = 'high',
) -> Dict[str, str]:
    """
    Convenience function to generate explanation
    
    Args:
        transaction: Transaction details
        risk_result: Risk scoring result
        graph_patterns: Detected graph patterns
        detail_level: Level of detail ('low', 'medium', 'high')
    
    Returns:
        Explanation dictionary
    """
    oracle = AegisOracle(detail_level=detail_level)
    return oracle.explain_decision(transaction, risk_result, graph_patterns)

if __name__ == "__main__":
    print("--- 🛡️ Booting AegisOracle Compliance Engine ---")
    
    # 1. Mock a flagged transaction
    mock_txn = {
        "transaction_id": "TXN-9942-X", 
        "source_account": "ACC-8091", 
        "target_account": "ACC-4432", 
        "amount": 250000, 
        "currency": "USD"
    }
    
    # 2. Mock the ML risk scores
    mock_risk = {
        "risk_score": 0.94, 
        "decision": "BLOCK", 
        "breakdown": {"graph": 0.91, "velocity": 0.85, "behavior": 0.40}, 
        "confidence": 0.96
    }
    
    # 3. Mock the PyTorch GNNExplainer output
    mock_patterns = {
        "chain_detected": True,
        "chain_length": 3,
        "critical_topology": [
            {"source_node": 8091, "target_node": 7712, "fraud_contribution": 0.9412},
            {"source_node": 7712, "target_node": 4432, "fraud_contribution": 0.8845}
        ]
    }

    # Run the engine
    report = generate_explanation(mock_txn, mock_risk, mock_patterns, detail_level='high')
    
    print("\n[EXECUTIVE SUMMARY]")
    print(report['summary'])
    
    print("\n[FULL COMPLIANCE EXPLANATION]")
    print(report['explanation'])
    
    print("\n[RECOMMENDED ACTION]")
    print(report['recommended_action'])
