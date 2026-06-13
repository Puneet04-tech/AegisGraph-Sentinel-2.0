"""SaaS routes package"""
# auth is imported first — other route modules import get_current_user from it
from .auth import router as auth_router
from .organizations import router as organizations_router
from .users import router as users_router
from .workspaces import router as workspaces_router
from .billing import router as billing_router

__all__ = [
    "organizations_router",
    "users_router",
    "workspaces_router",
    "auth_router",
    "billing_router",
]