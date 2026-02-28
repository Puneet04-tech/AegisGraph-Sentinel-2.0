from src.inference.risk_scorer import compute_risk_score

print('using', compute_risk_score)
print(compute_risk_score({'source_account':'A','target_account':'B','amount':1000}))
