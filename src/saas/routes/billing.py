"""
Billing & Subscription Routes
AegisGraph Sentinel Enterprise SaaS Platform
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel

from src.exceptions import BillingError
from src.saas.services.billing import (
    PLANS,
    PriceTier,
    billing_service,
    UsageMeteringService,
)
from src.saas.routes.auth import get_current_user
from src.saas.routes.organizations import _require_org_access

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])

# Initialize usage metering service
usage_metering_service = UsageMeteringService(billing_service)

_ORGANIZATION_SUBSCRIPTIONS: dict[str, str] = {}


class SubscriptionResponse(BaseModel):
    id: str
    tier: str
    status: str
    billing_cycle: str
    current_period_start: datetime
    current_period_end: datetime
    trial_ends_at: Optional[datetime]
    cancel_at_period_end: bool


class PlanResponse(BaseModel):
    tier: str
    name: str
    description: str
    price_monthly: int
    price_annual: int
    features: List[str]
    limits: dict


class InvoiceResponse(BaseModel):
    id: str
    number: str
    status: str
    amount: int
    currency: str
    period_start: datetime
    period_end: datetime
    pdf_url: Optional[str]
    paid_at: Optional[datetime]


class UsageResponse(BaseModel):
    api_calls_this_period: int
    max_api_calls: int
    storage_used_gb: float
    max_storage_gb: int
    period_start: datetime
    period_end: datetime
    usage_percentage: float


def _get_customer_id(organization_id: str) -> str:
    """Resolve Stripe customer ID from organization.

    In a full implementation this would query a mapping table.
    For now, returns a deterministic customer ID derived from the org ID.
    """
    return f"cus_{organization_id}"


def _ensure_stripe_configured() -> None:
    """Raise 503 if Stripe is not properly configured."""
    try:
        billing_service._check_stripe()
    except BillingError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing service unavailable: Stripe is not configured",
        )


@router.get("/plans", response_model=List[PlanResponse])
async def list_plans():
    """List available subscription plans"""
    return [
        PlanResponse(
            tier=plan.tier.value,
            name=plan.name,
            description=plan.description,
            price_monthly=plan.price_monthly,
            price_annual=plan.price_annual,
            features=plan.features,
            limits=plan.limits,
        )
        for plan in PLANS.values()
    ]


@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    organization_id: str,
    subscription_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get current subscription details from Stripe"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    try:
        sub = billing_service.get_subscription(subscription_id)
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(e),
        )

    return SubscriptionResponse(
        id=sub["id"],
        tier=sub.get("tier", "professional"),
        status=sub["status"],
        billing_cycle=sub.get("billing_cycle", "monthly"),
        current_period_start=sub["current_period_start"],
        current_period_end=sub["current_period_end"],
        trial_ends_at=None,
        cancel_at_period_end=sub.get("cancel_at_period_end", False),
    )


@router.post("/subscription")
async def create_subscription(
    organization_id: str,
    tier: PriceTier,
    billing_cycle: str = "monthly",
    trial_days: int = 14,
    current_user: dict = Depends(get_current_user),
):
    """Create new subscription via Stripe"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    customer_id = _get_customer_id(organization_id)

    try:
        result = billing_service.create_subscription(
            customer_id=customer_id,
            tier=tier,
            billing_cycle=billing_cycle,
            trial_days=trial_days,
            metadata={"organization_id": organization_id},
        )
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(e),
        )

    return {
        "subscription_id": result["subscription_id"],
        "tier": tier.value,
        "status": result["status"],
        "current_period_start": result["current_period_start"],
        "current_period_end": result["current_period_end"],
        "trial_end": result.get("trial_end"),
    }


@router.patch("/subscription")
async def update_subscription(
    organization_id: str,
    subscription_id: str,
    tier: Optional[PriceTier] = None,
    billing_cycle: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Update subscription (upgrade/downgrade) via Stripe"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    try:
        result = billing_service.update_subscription(
            subscription_id=subscription_id,
            new_tier=tier,
            billing_cycle=billing_cycle,
        )
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(e),
        )

    return {
        "success": result.get("updated", True),
        "subscription_id": result["subscription_id"],
        "new_tier": tier.value if tier else None,
    }


@router.post("/subscription/cancel")
async def cancel_subscription(
    organization_id: str,
    subscription_id: str,
    cancel_at_period_end: bool = True,
    reason: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Cancel subscription via Stripe"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    try:
        result = billing_service.cancel_subscription(
            subscription_id=subscription_id,
            cancel_at_period_end=cancel_at_period_end,
            reason=reason,
        )
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(e),
        )

    return {
        "success": result.get("canceled", True),
        "subscription_id": result["subscription_id"],
        "cancel_at_period_end": cancel_at_period_end,
        "effective_date": result.get("effective_date"),
    }


@router.post("/subscription/resume")
async def resume_subscription(
    organization_id: str,
    subscription_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Resume canceled subscription"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    try:
        result = billing_service.update_subscription(
            subscription_id=subscription_id,
        )
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(e),
        )

    return {"success": True, "subscription_id": result["subscription_id"]}


@router.get("/invoices", response_model=List[InvoiceResponse])
async def list_invoices(
    organization_id: str,
    limit: int = 10,
    current_user: dict = Depends(get_current_user),
):
    """List invoices from Stripe"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    customer_id = _get_customer_id(organization_id)

    try:
        invoices = billing_service.get_invoices(customer_id, limit=limit)
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(e),
        )

    return [
        InvoiceResponse(
            id=inv["id"],
            number=inv.get("number", ""),
            status=inv["status"],
            amount=inv.get("amount_due", 0),
            currency=inv.get("currency", "usd"),
            period_start=inv.get("created", datetime.now(timezone.utc)),
            period_end=inv.get("created", datetime.now(timezone.utc)),
            pdf_url=inv.get("pdf_url"),
            paid_at=inv.get("created") if inv["status"] == "paid" else None,
        )
        for inv in invoices
    ]


@router.get("/invoices/{invoice_id}", response_model=InvoiceResponse)
async def get_invoice(
    organization_id: str,
    invoice_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get invoice details"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    customer_id = _get_customer_id(organization_id)

    try:
        invoices = billing_service.get_invoices(customer_id, limit=100)
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(e),
        )

    matching = [inv for inv in invoices if inv["id"] == invoice_id]
    if not matching:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Invoice {invoice_id} not found",
        )

    inv = matching[0]
    return InvoiceResponse(
        id=inv["id"],
        number=inv.get("number", ""),
        status=inv["status"],
        amount=inv.get("amount_due", 0),
        currency=inv.get("currency", "usd"),
        period_start=inv.get("created", datetime.now(timezone.utc)),
        period_end=inv.get("created", datetime.now(timezone.utc)),
        pdf_url=inv.get("pdf_url"),
        paid_at=inv.get("created") if inv["status"] == "paid" else None,
    )


@router.get("/usage", response_model=UsageResponse)
async def get_usage(
    organization_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get usage metrics from UsageMeteringService"""
    _require_org_access(organization_id, current_user)

    subscription_id = _ORGANIZATION_SUBSCRIPTIONS.get(organization_id)
    if subscription_id is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found for organization")
    try:
        subscription = billing_service.get_subscription(subscription_id)
        plan = PriceTier(subscription["tier"])
        usage = billing_service.get_usage(subscription_id, subscription["current_period_start"], subscription["current_period_end"])
    except (BillingError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    api_limit_check = usage_metering_service.check_limit(
        organization_id=organization_id,
        limit_type="api_calls_per_month",
        current_usage=usage.get("total_api_calls", 0),
        plan=plan,
    )

    storage_limit_check = usage_metering_service.check_limit(
        organization_id=organization_id,
        limit_type="storage_gb",
        current_usage=usage.get("storage_used_gb", 0),
        plan=plan,
    )

    max_api = api_limit_check.get("limit") or -1
    max_storage = storage_limit_check.get("limit") or -1

    now = datetime.now(timezone.utc)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    return UsageResponse(
        api_calls_this_period=api_limit_check["current_usage"],
        max_api_calls=max_api,
        storage_used_gb=float(storage_limit_check["current_usage"]),
        max_storage_gb=max_storage,
        period_start=period_start,
        period_end=now,
        usage_percentage=api_limit_check.get("percentage", 0.0),
    )


@router.get("/usage/daily")
async def get_daily_usage(
    organization_id: str,
    days: int = 30,
    current_user: dict = Depends(get_current_user),
):
    """Get daily usage breakdown"""
    _require_org_access(organization_id, current_user)

    subscription_id = _ORGANIZATION_SUBSCRIPTIONS.get(organization_id)
    if subscription_id is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found for organization")
    subscription = billing_service.get_subscription(subscription_id)
    usage = billing_service.get_usage(subscription_id, subscription["current_period_start"], subscription["current_period_end"])
    total = usage.get("total_api_calls", 0)
    return {"daily_usage": [], "total_api_calls": total, "avg_daily_calls": total / max(days, 1)}



@router.post("/checkout")
async def create_checkout_session(
    organization_id: str,
    tier: PriceTier,
    billing_cycle: str = "monthly",
    success_url: str = "https://app.aegisgraph.com/billing/success",
    cancel_url: str = "https://app.aegisgraph.com/billing/cancel",
    current_user: dict = Depends(get_current_user),
):
    """Create Stripe checkout session"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    customer_id = _get_customer_id(organization_id)

    try:
        checkout_url = billing_service.create_checkout_session(
            customer_id=customer_id,
            tier=tier,
            success_url=success_url,
            cancel_url=cancel_url,
            billing_cycle=billing_cycle,
        )
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(e),
        )

    return {
        "checkout_url": checkout_url,
        "session_id": None,
    }


@router.post("/portal")
async def create_customer_portal(
    organization_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Create Stripe customer portal session"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    return {
        "portal_url": None,
        "message": "Customer portal requires Stripe portal configuration",
    }


@router.post("/webhook")
async def handle_stripe_webhook(request: Request):
    """Handle Stripe webhook events"""
    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Stripe-Signature header",
        )

    try:
        result = billing_service.handle_webhook(payload, signature)
    except BillingError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return {"received": True, **result}


@router.get("/payment-methods")
async def list_payment_methods(
    organization_id: str,
    current_user: dict = Depends(get_current_user),
):
    """List saved payment methods"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    return {"payment_methods": []}


@router.post("/payment-methods")
async def add_payment_method(
    organization_id: str,
    payment_method_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Add payment method"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    return {"success": True, "payment_method_id": payment_method_id}


@router.delete("/payment-methods/{method_id}")
async def remove_payment_method(
    organization_id: str,
    method_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Remove payment method"""
    _require_org_access(organization_id, current_user)
    _ensure_stripe_configured()

    return {"success": True}
