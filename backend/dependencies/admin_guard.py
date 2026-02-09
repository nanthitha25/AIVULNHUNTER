from fastapi import Depends, HTTPException
from .auth_guard import get_current_user

DEMO_TOKEN = "demo-admin-token"

def admin_required(current_user=Depends(get_current_user)):
    """Require admin role for access."""
    # Simple demo check - just verify token is demo-admin-token
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

