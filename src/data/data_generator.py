"""
Synthetic Fraud Data Generator

Generates realistic synthetic financial transaction data including:
- Legitimate transaction patterns
- Mule account networks (chain, star, mesh topologies)
- Behavioral biometrics
- Temporal patterns
"""

import numpy as np
import networkx as nx
from typing import Dict, List, Tuple, Optional
import random
from datetime import datetime, timedelta
import json
from pathlib import Path
from tqdm import tqdm
import pickle


def convert_numpy_types(obj):
    """Convert numpy types to native Python types for JSON serialization"""
    if isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    return obj


class SyntheticFraudGenerator:
    """
    Generate synthetic fraud transaction data
    
    Args:
        num_accounts: Number of accounts to create
        num_transactions: Number of transactions to generate
        fraud_rate: Fraction of fraudulent transactions
        random_seed: Random seed for reproducibility
    """
    
    def __init__(
        self,
        num_accounts: int = 10000,
        num_transactions: int = 100000,
        fraud_rate: float = 0.01,
        random_seed: int = 42,
    ):
        self.num_accounts = num_accounts
        self.num_transactions = num_transactions
        self.fraud_rate = fraud_rate
        
        np.random.seed(random_seed)
        random.seed(random_seed)
        
        # Initialize graph
        self.graph = nx.DiGraph()
        self.accounts = []
        self.transactions = []
        self.fraud_chains = []
    
    def generate(self) -> Dict:
        """
        Generate complete synthetic dataset
        
        Returns:
            Dictionary with accounts, transactions, and graph
        """
        print("Generating synthetic fraud dataset...")
        
        # Create accounts
        print("Creating accounts...")
        self._create_accounts()
        
        # Generate legitimate transaction patterns
        print("Generating legitimate transactions...")
        num_legit = int(self.num_transactions * (1 - self.fraud_rate))
        self._generate_legitimate_transactions(num_legit)
        
        # Generate fraudulent transaction patterns
        print("Generating fraudulent transactions...")
        num_fraud = int(self.num_transactions * self.fraud_rate)
        self._generate_fraud_transactions(num_fraud)
        
        # Shuffle transactions
        random.shuffle(self.transactions)
        
        print(f"✓ Generated {len(self.transactions)} transactions")
        print(f"  - Legitimate: {len([t for t in self.transactions if not t['is_fraud']])}")
        print(f"  - Fraudulent: {len([t for t in self.transactions if t['is_fraud']])}")
        
        return {
            'accounts': self.accounts,
            'transactions': self.transactions,
            'fraud_chains': self.fraud_chains,
            'graph': self.graph,
        }
    
    def _create_accounts(self):
        """Create synthetic accounts"""
        start_date = datetime(2025, 1, 1)
        
        for i in range(self.num_accounts):
            # Account creation date
            days_ago = np.random.exponential(180)  # Exponential distribution
            created_date = start_date - timedelta(days=days_ago)
            
            account = {
                'account_id': f'ACC{i:08d}',
                'account_type': np.random.choice(['savings', 'current', 'wallet'], p=[0.7, 0.2, 0.1]),
                'balance': max(0, np.random.lognormal(10, 2)),  # Log-normal distribution
                'created_date': created_date.isoformat(),
                'kyc_verified': np.random.choice([True, False], p=[0.95, 0.05]),
                'age_days': int((start_date - created_date).days),
            }
            
            self.accounts.append(account)
            self.graph.add_node(account['account_id'], **account)
    
    def _generate_legitimate_transactions(self, num_transactions: int):
        """Generate legitimate transaction patterns"""
        base_timestamp = datetime(2025, 6, 1).timestamp()
        
        for _ in tqdm(range(num_transactions), desc="Legitimate transactions"):
            # Select random accounts
            source_idx = np.random.randint(0, self.num_accounts)
            target_idx = np.random.randint(0, self.num_accounts)
            
            if source_idx == target_idx:
                continue
            
            source = self.accounts[source_idx]['account_id']
            target = self.accounts[target_idx]['account_id']
            
            # Transaction amount (log-normal)
            amount = max(100, np.random.lognormal(8, 1.5))
            
            # Timestamp (random within 6 months)
            timestamp = base_timestamp + np.random.uniform(0, 180 * 86400)
            
            # Mode
            mode = np.random.choice(['UPI', 'IMPS', 'NEFT', 'RTGS'], p=[0.6, 0.2, 0.15, 0.05])
            
            transaction = {
                'transaction_id': f'TXN{len(self.transactions):010d}',
                'source_account': source,
                'target_account': target,
                'amount': round(amount, 2),
                'currency': 'INR',
                'mode': mode,
                'timestamp': timestamp,
                'is_fraud': False,
                'fraud_type': None,
            }
            
            self.transactions.append(transaction)
            self.graph.add_edge(source, target, **transaction)
    
    def _generate_fraud_transactions(self, num_fraud: int):
        """Generate fraudulent transaction patterns"""
        # Distribute fraud types
        num_chain = int(num_fraud * 0.5)
        num_star = int(num_fraud * 0.3)
        num_mesh = num_fraud - num_chain - num_star
        
        self._generate_chain_fraud(num_chain)
        self._generate_star_fraud(num_star)
        self._generate_mesh_fraud(num_mesh)
    
    def _generate_chain_fraud(self, num_chains: int):
        """Generate chain topology fraud (sequential transfers)"""
        base_timestamp = datetime(2025, 6, 1).timestamp()
        
        for _ in tqdm(range(num_chains), desc="Chain fraud"):
            # Chain length
            chain_length = np.random.randint(3, 8)
            
            # Select accounts for chain
            account_indices = np.random.choice(self.num_accounts, chain_length, replace=False)
            chain_accounts = [self.accounts[idx]['account_id'] for idx in account_indices]
            
            # Initial amount
            amount = max(10000, np.random.lognormal(10, 1))
            
            # Starting timestamp
            start_time = base_timestamp + np.random.uniform(0, 180 * 86400)
            
            # Generate chain transactions
            chain_txns = []
            for i in range(chain_length - 1):
                # Time between hops (rapid)
                hop_time = np.random.uniform(30, 300)  # 30 seconds to 5 minutes
                timestamp = start_time + sum(
                    [np.random.uniform(30, 300) for _ in range(i)]
                )
                
                # Amount may decrease slightly (fees)
                if i > 0:
                    amount *= np.random.uniform(0.95, 0.99)
                
                transaction = {
                    'transaction_id': f'TXN{len(self.transactions):010d}',
                    'source_account': chain_accounts[i],
                    'target_account': chain_accounts[i + 1],
                    'amount': round(amount, 2),
                    'currency': 'INR',
                    'mode': 'UPI',
                    'timestamp': timestamp,
                    'is_fraud': True,
                    'fraud_type': 'chain',
                    'chain_position': i,
                    'chain_length': chain_length,
                }
                
                self.transactions.append(transaction)
                self.graph.add_edge(
                    chain_accounts[i], chain_accounts[i + 1],
                    **transaction
                )
                chain_txns.append(transaction)
            
            self.fraud_chains.append({
                'type': 'chain',
                'accounts': chain_accounts,
                'transactions': chain_txns,
            })
    
    def _generate_star_fraud(self, num_stars: int):
        """Generate star topology fraud (central disbursement)"""
        base_timestamp = datetime(2025, 6, 1).timestamp()
        
        for _ in tqdm(range(num_stars), desc="Star fraud"):
            # Number of branches
            num_branches = np.random.randint(3, 8)
            
            # Select central account and recipients
            account_indices = np.random.choice(self.num_accounts, num_branches + 1, replace=False)
            central = self.accounts[account_indices[0]]['account_id']
            recipients = [self.accounts[idx]['account_id'] for idx in account_indices[1:]]
            
            # Total amount to disburse
            total_amount = max(10000, np.random.lognormal(11, 1))
            
            # Starting timestamp
            start_time = base_timestamp + np.random.uniform(0, 180 * 86400)
            
            # Generate disbursement transactions
            star_txns = []
            for i, recipient in enumerate(recipients):
                # Split amount
                amount = total_amount / num_branches * np.random.uniform(0.8, 1.2)
                
                # Time offset (rapid sequential or simultaneous)
                timestamp = start_time + np.random.uniform(0, 60)  # Within 1 minute
                
                transaction = {
                    'transaction_id': f'TXN{len(self.transactions):010d}',
                    'source_account': central,
                    'target_account': recipient,
                    'amount': round(amount, 2),
                    'currency': 'INR',
                    'mode': 'UPI',
                    'timestamp': timestamp,
                    'is_fraud': True,
                    'fraud_type': 'star',
                    'branch_number': i,
                    'total_branches': num_branches,
                }
                
                self.transactions.append(transaction)
                self.graph.add_edge(central, recipient, **transaction)
                star_txns.append(transaction)
            
            self.fraud_chains.append({
                'type': 'star',
                'central': central,
                'recipients': recipients,
                'transactions': star_txns,
            })
    
    def _generate_mesh_fraud(self, num_mesh: int):
        """Generate mesh topology fraud (complex interconnected)"""
        base_timestamp = datetime(2025, 6, 1).timestamp()
        
        for _ in tqdm(range(num_mesh), desc="Mesh fraud"):
            # Network size
            network_size = np.random.randint(5, 10)
            
            # Select accounts
            account_indices = np.random.choice(self.num_accounts, network_size, replace=False)
            network_accounts = [self.accounts[idx]['account_id'] for idx in account_indices]
            
            # Generate random transactions within network
            num_edges = np.random.randint(network_size, network_size * 2)
            
            amount = max(5000, np.random.lognormal(9, 1))
            start_time = base_timestamp + np.random.uniform(0, 180 * 86400)
            
            mesh_txns = []
            for i in range(num_edges):
                # Random edge
                source = np.random.choice(network_accounts)
                target = np.random.choice([a for a in network_accounts if a != source])
                
                # Time
                timestamp = start_time + np.random.uniform(0, 3600)  # Within 1 hour
                
                # Amount
                edge_amount = amount * np.random.uniform(0.3, 1.0)
                
                transaction = {
                    'transaction_id': f'TXN{len(self.transactions):010d}',
                    'source_account': source,
                    'target_account': target,
                    'amount': round(edge_amount, 2),
                    'currency': 'INR',
                    'mode': 'UPI',
                    'timestamp': timestamp,
                    'is_fraud': True,
                    'fraud_type': 'mesh',
                }
                
                self.transactions.append(transaction)
                self.graph.add_edge(source, target, **transaction)
                mesh_txns.append(transaction)
            
            self.fraud_chains.append({
                'type': 'mesh',
                'accounts': network_accounts,
                'transactions': mesh_txns,
            })
    
    def save_to_disk(self, output_dir: str = 'data/synthetic'):
        """Save generated data to disk"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save accounts (convert numpy types)
        with open(output_path / 'accounts.json', 'w') as f:
            json.dump(convert_numpy_types(self.accounts), f, indent=2)
        
        # Save transactions (convert numpy types)
        with open(output_path / 'transactions.json', 'w') as f:
            json.dump(convert_numpy_types(self.transactions), f, indent=2)
        
        # Save fraud chains (convert numpy types)
        with open(output_path / 'fraud_chains.json', 'w') as f:
            json.dump(convert_numpy_types(self.fraud_chains), f, indent=2)
        
        # Save graph using pickle
        with open(output_path / 'graph.gpickle', 'wb') as f:
            pickle.dump(self.graph, f)
        
        print(f"✓ Data saved to {output_dir}")


if __name__ == "__main__":
    # Generate synthetic data
    generator = SyntheticFraudGenerator(
        num_accounts=10000,
        num_transactions=100000,
        fraud_rate=0.01,
    )
    
    data = generator.generate()
    generator.save_to_disk()
