"""
Admin Guard Dependency - Enforces admin-only access.

Usage:
    @router.post("/admin/rules", dependencies=[Depends(admin_required)])
    def create_rule(...):
        ...
"""

from fastapi import Depends, HTTPException
from .auth_guard import get_current_user


def admin_required(current_user: dict = Depends(get_current_user)) -> dict:
    """Raise HTTP 403 if the current user does not have the 'admin' role."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required. You do not have permission to perform this action."
        )
    return current_user
