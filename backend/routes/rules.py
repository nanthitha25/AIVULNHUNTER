"""
Rules API Router - DB-backed rule management (Admin only)

Endpoints:
    GET    /rules/           - List all rules
    POST   /rules/           - Create a new rule
    PUT    /rules/{rule_id}  - Update an existing rule
    DELETE /rules/{rule_id}  - Delete a rule
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from backend.dependencies.admin_guard import admin_required
from backend.database import sqlite_db as db

router = APIRouter(prefix="/rules", tags=["Rules"])


# ------------------------------------------------------------------ #
# Request model                                                        #
# ------------------------------------------------------------------ #

class RuleCreate(BaseModel):
    id: Optional[str] = None
    name: str
    owasp_category: str
    severity: str = "MEDIUM"             # CRITICAL / HIGH / MEDIUM / LOW
    priority: int = 3
    description: Optional[str] = ""
    attack_payload: Optional[str] = ""
    detection_pattern: Optional[str] = ""
    mitigation: Optional[str] = ""


# ------------------------------------------------------------------ #
# Routes                                                               #
# ------------------------------------------------------------------ #

@router.get("/", dependencies=[Depends(admin_required)])
def get_rules():
    """Return all security rules ordered by priority (admin only)."""
    return db.get_all_rules()


@router.post("/", dependencies=[Depends(admin_required)])
def add_rule(rule: RuleCreate):
    """
    Create a new security rule (admin only).

    Each rule must include:
        name, owasp_category, severity, description, attack_payload,
        detection_pattern, mitigation
    """
    created = db.create_rule(rule.dict())
    return {"message": "Rule created successfully", "rule": created}


@router.put("/{rule_id}", dependencies=[Depends(admin_required)])
def update_rule(rule_id: str, data: dict):
    """Update an existing rule by ID (admin only)."""
    updated = db.update_rule(rule_id, data)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    return {"message": "Rule updated", "rule": updated}


@router.delete("/{rule_id}", dependencies=[Depends(admin_required)])
def delete_rule(rule_id: str):
    """Delete a rule by ID (admin only)."""
    success = db.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    return {"message": f"Rule '{rule_id}' deleted"}
