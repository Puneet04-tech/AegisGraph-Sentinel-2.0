"""Authentication routes for identity provider integration.

Provides OAuth2 endpoints for JWT token issuance.
"""

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from .security import create_access_token, Role

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

class Token(BaseModel):
    access_token: str
    token_type: str

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    Simulate an Identity Provider login to get an OAuth2 JWT token.
    Mock credentials:
    - username: 'admin', 'analyst', 'auditor', or 'viewer'
    - password: any
    """
    username = form_data.username.lower()
    
    # Map mock username to roles
    role_map = {
        "admin": Role.ADMIN.value,
        "analyst": Role.ANALYST.value,
        "auditor": Role.AUDITOR.value,
        "viewer": Role.VIEWER.value,
        "superadmin": Role.SUPER_ADMIN.value,
    }
    
    if username not in role_map:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials (use 'admin', 'analyst', 'auditor', or 'viewer')",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token(
        data={"sub": username, "role": role_map[username]}
    )
    return Token(access_token=access_token, token_type="bearer")
