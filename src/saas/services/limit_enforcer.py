from fastapi import HTTPException, status
from src.saas.services.billing import billing_service, UsageMeteringService, PriceTier

# In-memory resource tracker for tenants (simulating DB query counts)
_tenant_resource_counts = {}

# In-memory subscription tier registry for tenants (simulating the tenant
# record's ``subscription_tier`` field). Tenants without an explicit tier are
# treated as the free COMMUNITY plan.
_tenant_tiers = {}

def get_tenant_resource_count(tenant_id: str, resource_type: str) -> int:
    return _tenant_resource_counts.get(tenant_id, {}).get(resource_type, 0)

def set_tenant_resource_count(tenant_id: str, resource_type: str, count: int) -> None:
    if tenant_id not in _tenant_resource_counts:
        _tenant_resource_counts[tenant_id] = {}
    _tenant_resource_counts[tenant_id][resource_type] = count

def get_tenant_tier(tenant_id: str) -> PriceTier:
    """Resolve the tenant's actual subscription tier (COMMUNITY by default)."""
    return _tenant_tiers.get(tenant_id, PriceTier.COMMUNITY)

def set_tenant_tier(tenant_id: str, tier: PriceTier) -> None:
    """Record a tenant's subscription tier so limit checks use the real plan."""
    _tenant_tiers[tenant_id] = tier

def enforce_tenant_limit(tenant_id: str, resource_type: str, plan_tier: PriceTier) -> None:
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
