"""Quick script to demonstrate variable risk scores for mule and normal accounts"""
import requests
import json
from pathlib import Path

API = "http://localhost:8000/api/v1/fraud/check"

# load first few mule accounts from synthetic chains
chains = json.load(open('data/synthetic/fraud_chains.json'))
mules = set()
for chain in chains[:5]:
    for acc in chain.get('accounts', []):
        mules.add(acc)
        if len(mules) >= 10:
            break
    if len(mules) >= 10:
        break

mules = list(mules)

print(f"Using mule accounts sample: {mules[:5]}")

for acc in mules[:5]:
    payload = {
        "transaction_id": f"TEST_{acc}",
        "source_account": acc,
        "target_account": "NORMAL_0001",
        "amount": 12345,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": "2026-02-28T12:00:00Z"
    }
    res = requests.post(API, json=payload).json()
    print(acc, res['risk_score'], res['decision'])

# also send normal
for i in range(3):
    payload = {
        "transaction_id": f"NORM_{i}",
        "source_account": f"USR{i}",
        "target_account": f"MER{i}",
        "amount": 100*(i+1),
        "currency": "INR",
        "mode": "UPI",
        "timestamp": "2026-02-28T12:00:00Z"
    }
    res = requests.post(API, json=payload).json()
    print("normal", res['risk_score'], res['decision'])
