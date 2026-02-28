from src.api.main import state

print('manager', state.honeypot_manager)
hp = state.honeypot_manager.activate_honeypot(
    transaction_id='MANUAL001',
    source_account='ACC123',
    target_account='ACC456',
    amount=99999,
    currency='INR',
    risk_score=0.95,
    fraud_indicators=['known_mule_account']
)
print('activated', hp.honeypot_id, hp.status)
print('active list', list(state.honeypot_manager.active_honeypots.keys()))
