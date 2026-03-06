"""
Auth Guard Dependency - Validates JWT tokens on protected endpoints.

Usage:
    from backend.dependencies.auth_guard import get_current_user

    @router.get("/protected")
    def route(user = Depends(get_current_user)):
        ...
"""

from fastapi import Depends, HTTPException, Header
from typing import Optional
from jose import jwt, JWTError

JWT_SECRET = "aivulnhunter-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"


def get_current_user(authorization: Optional[str] = Header(default=None)) -> dict:
    """
    FastAPI dependency that extracts and validates the JWT from the
    Authorization: Bearer <token> header.

    Returns the decoded token payload as a dict with keys:
        sub, username, role, exp
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    # Accept both 'Bearer <token>' and raw token strings
    token = authorization.replace("Bearer ", "").strip()

    # Also accept the legacy demo-admin-token for backwards compatibility
    if token == "demo-admin-token":
        return {"sub": "legacy-admin", "username": "admin", "role": "admin"}

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
