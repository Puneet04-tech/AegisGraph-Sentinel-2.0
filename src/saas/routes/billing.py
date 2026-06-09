"""
Billing & Subscription Routes
AegisGraph Sentinel Enterprise SaaS Platform
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel

from src.saas.services.billing import PLANS, PriceTier, billing_service

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])


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
async def get_subscription(organization_id: str):
    """Get current subscription"""
    return SubscriptionResponse(
        id="sub_123",
        tier="professional",
        status="active",
        billing_cycle="monthly",
        current_period_start=datetime.utcnow(),
        current_period_end=datetime.utcnow(),
        trial_ends_at=None,
        cancel_at_period_end=False,
    )


@router.post("/subscription")
async def create_subscription(
    organization_id: str,
    tier: PriceTier,
    billing_cycle: str = "monthly",
):
    """Create new subscription"""
    return {
        "subscription_id": f"sub_{datetime.utcnow().timestamp()}",
        "tier": tier.value,
        "status": "active",
        "checkout_url": "https://checkout.stripe.com/...",
    }


@router.patch("/subscription")
async def update_subscription(
    organization_id: str,
    tier: Optional[PriceTier] = None,
    billing_cycle: Optional[str] = None,
):
    """Update subscription (upgrade/downgrade)"""
    return {
        "success": True,
        "subscription_id": "sub_123",
        "new_tier": tier.value if tier else "professional",
    }


@router.post("/subscription/cancel")
async def cancel_subscription(
    organization_id: str,
    cancel_at_period_end: bool = True,
    reason: Optional[str] = None,
):
    """Cancel subscription"""
    return {
        "success": True,
        "subscription_id": "sub_123",
        "cancel_at_period_end": cancel_at_period_end,
        "effective_date": datetime.utcnow(),
    }


@router.post("/subscription/resume")
async def resume_subscription(organization_id: str):
    """Resume canceled subscription"""
    return {"success": True}


@router.get("/invoices", response_model=List[InvoiceResponse])
async def list_invoices(organization_id: str, limit: int = 10):
    """List invoices"""
    return [
        InvoiceResponse(
            id="inv_1",
            number="INV-2024-001",
            status="paid",
            amount=49900,
            currency="usd",
            period_start=datetime.utcnow(),
            period_end=datetime.utcnow(),
            pdf_url="https://...",
            paid_at=datetime.utcnow(),
        )
    ]


@router.get("/invoices/{invoice_id}", response_model=InvoiceResponse)
async def get_invoice(organization_id: str, invoice_id: str):
    """Get invoice details"""
    return InvoiceResponse(
        id=invoice_id,
        number="INV-2024-001",
        status="paid",
        amount=49900,
        currency="usd",
        period_start=datetime.utcnow(),
        period_end=datetime.utcnow(),
        pdf_url="https://...",
        paid_at=datetime.utcnow(),
    )


@router.get("/usage", response_model=UsageResponse)
async def get_usage(organization_id: str):
    """Get usage metrics"""
    return UsageResponse(
        api_calls_this_period=75000,
        max_api_calls=100000,
        storage_used_gb=45.2,
        max_storage_gb=100,
        period_start=datetime.utcnow(),
        period_end=datetime.utcnow(),
        usage_percentage=75.0,
    )


@router.get("/usage/daily")
async def get_daily_usage(organization_id: str, days: int = 30):
    """Get daily usage breakdown"""
    return {
        "daily_usage": [
            {
                "date": datetime.utcnow().isoformat(),
                "api_calls": 2500,
                "storage_gb": 45.2,
            }
        ],
        "total_api_calls": 75000,
        "avg_daily_calls": 2500,
    }


@router.post("/checkout")
async def create_checkout_session(
    organization_id: str,
    tier: PriceTier,
    billing_cycle: str = "monthly",
):
    """Create Stripe checkout session"""
    return {
        "checkout_url": "https://checkout.stripe.com/...",
        "session_id": "cs_123",
    }


@router.post("/portal")
async def create_customer_portal(organization_id: str):
    """Create Stripe customer portal session"""
    return {
        "portal_url": "https://billing.stripe.com/...",
    }


@router.post("/webhook")
async def handle_stripe_webhook(payload: dict, headers: dict):
    """Handle Stripe webhook events"""
    return {"received": True}


@router.get("/payment-methods")
async def list_payment_methods(organization_id: str):
    """List saved payment methods"""
    return {
        "payment_methods": [
            {
                "id": "pm_1",
                "type": "card",
                "brand": "visa",
                "last4": "4242",
                "exp_month": 12,
                "exp_year": 2025,
                "is_default": True,
            }
        ]
    }


@router.post("/payment-methods")
async def add_payment_method(organization_id: str, payment_method_id: str):
    """Add payment method"""
    return {"success": True, "payment_method_id": payment_method_id}


@router.delete("/payment-methods/{method_id}")
async def remove_payment_method(organization_id: str, method_id: str):
    """Remove payment method"""
    return {"success": True}