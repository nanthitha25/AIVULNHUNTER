"""
Rules API router - ADMIN ONLY
"""

from fastapi import APIRouter, Depends
from backend.dependencies.admin_guard import admin_required
from rules_store import rules_db
import uuid

router = APIRouter(prefix="/rules", tags=["Rules"])

@router.get("/", dependencies=[Depends(admin_required)])
def get_rules():
    """Get all rules (admin only)."""
    return rules_db

@router.post("/", dependencies=[Depends(admin_required)])
def add_rule(rule: dict):
    """Add a new rule (admin only)."""
    rule["id"] = rule.get("id", str(uuid.uuid4()))
    rules_db.append(rule)
    return {"message": "Rule created", "rule": rule}

@router.put("/{rule_id}", dependencies=[Depends(admin_required)])
def update_rule(rule_id: str, updated: dict):
    """Update a rule (admin only)."""
    for r in rules_db:
        if r["id"] == rule_id:
            r.update(updated)
    return {"status": "updated"}

@router.delete("/{rule_id}", dependencies=[Depends(admin_required)])
def delete_rule(rule_id: str):
    """Delete a rule (admin only)."""
    global rules_db
    rules_db = [r for r in rules_db if r["id"] != rule_id]
    return {"status": "deleted"}

