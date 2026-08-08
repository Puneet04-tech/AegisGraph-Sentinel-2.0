import threading

from fastapi import HTTPException, status
from src.saas.services.billing import billing_service, UsageMeteringService, PriceTier

# In-memory resource tracker for tenants (simulating DB query counts)
_tenant_resource_counts = {}
_counts_lock = threading.Lock()

def get_tenant_resource_count(tenant_id: str, resource_type: str) -> int:
    return _tenant_resource_counts.get(tenant_id, {}).get(resource_type, 0)

def set_tenant_resource_count(tenant_id: str, resource_type: str, count: int) -> None:
    with _counts_lock:
        _tenant_resource_counts.setdefault(tenant_id, {})[resource_type] = count


def increment_if_within_limit(tenant_id: str, resource_type: str, plan_tier: PriceTier = PriceTier.COMMUNITY) -> None:
    """Atomically check and increment a tenant resource counter."""
    with _counts_lock:
        current_count = _tenant_resource_counts.get(tenant_id, {}).get(resource_type, 0)
        result = UsageMeteringService(billing_service).check_limit(tenant_id, resource_type, current_count, plan_tier)
        if not result["within_limit"]:
            raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail="Subscription limit exceeded")
        _tenant_resource_counts.setdefault(tenant_id, {})[resource_type] = current_count + 1

def enforce_tenant_limit(tenant_id: str, resource_type: str, plan_tier: PriceTier = PriceTier.COMMUNITY) -> None:
    """Validate active resource count against subscription tier limits.

    Raises:
        HTTPException (402 Payment Required) if subscription limit is exceeded.
    """
    current_count = get_tenant_resource_count(tenant_id, resource_type)
    metering = UsageMeteringService(billing_service)
    result = metering.check_limit(tenant_id, resource_type, current_count, plan_tier)
    if not result["within_limit"]:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Subscription limit exceeded for '{resource_type}'. Current: {current_count}, Limit: {result['limit']}. Please upgrade your subscription tier."
        )
