"""
Rules API router - ADMIN ONLY
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from backend.dependencies.admin_guard import admin_required
from backend.database.connection import get_db
from backend.database import crud_rules
from backend.schemas import VulnerabilityBase # Reusing for rules if needed or creating Schema
import uuid

from backend.schemas import RuleCreate, RuleUpdate

router = APIRouter(prefix="/rules", tags=["Rules"])

@router.get("/", dependencies=[Depends(admin_required)])
def get_rules(db: Session = Depends(get_db)):
    """Get all rules (admin only)."""
    rules = crud_rules.get_rules(db, enabled_only=False)
    # Include RL weight priority scores if they exist
    result = []
    for r in rules:
        r_dict = {
            "id": r.id,
            "name": r.name,
            "owasp": r.owasp,
            "severity": r.severity,
            "target_types": r.target_types,
            "description": r.description,
            "enabled": r.enabled,
            "priority_score": r.rl_weight.priority_score if r.rl_weight else None
        }
        result.append(r_dict)
    return result

@router.post("/", dependencies=[Depends(admin_required)])
def add_rule(rule: RuleCreate, db: Session = Depends(get_db)):
    """Add a new rule (admin only)."""
    # Check for existing rule name
    from backend.database.models import Rule
    existing = db.query(Rule).filter(Rule.name == rule.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rule with this name already exists")
        
    created = crud_rules.create_rule(
        db=db,
        name=rule.name,
        owasp=rule.owasp,
        severity=rule.severity,
        target_types=rule.target_types,
        description=rule.description,
        enabled=rule.enabled
    )
    return {"message": "Rule created successfully", "id": created.id}

@router.put("/{rule_id}", dependencies=[Depends(admin_required)])
def update_rule(rule_id: int, updated: RuleUpdate, db: Session = Depends(get_db)):
    """Update a rule (admin only)."""
    update_data = updated.model_dump(exclude_unset=True)
    rule = crud_rules.update_rule(db, rule_id, **update_data)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "updated", "id": rule.id}

@router.delete("/{rule_id}", dependencies=[Depends(admin_required)])
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    """Delete a rule (admin only)."""
    success = crud_rules.delete_rule(db, rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "deleted"}
