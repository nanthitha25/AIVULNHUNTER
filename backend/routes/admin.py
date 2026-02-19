"""
Admin API Routes
Provides endpoints for user management, rule CRUD, and system stats.
All routes require admin role.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database import crud_scans, crud_rules
from backend.database.models import User, Rule, RLWeight, Scan
from backend.dependencies.admin_guard import admin_required

router = APIRouter(prefix="/admin", tags=["Admin"])


# ─── Pydantic Schemas ────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    severity: Optional[str] = None
    description: Optional[str] = None


# ─── User Management ─────────────────────────────────────────────────────────

@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    admin=Depends(admin_required)
):
    """List all users."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    return {
        "users": [
            {
                "id": str(u.id),
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            }
            for u in users
        ],
        "total": len(users)
    }


@router.post("/users")
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin=Depends(admin_required)
):
    """Create a new user."""
    import uuid
    from passlib.context import CryptContext

    # Check username uniqueness
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    user = User(
        id=uuid.uuid4(),
        username=payload.username,
        email=payload.email,
        password_hash=pwd_context.hash(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
    }


@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    admin=Depends(admin_required)
):
    """Update user role or active status."""
    import uuid
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.email is not None:
        user.email = payload.email
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    db.commit()
    return {"message": "User updated", "id": user_id}


@router.delete("/users/{user_id}")
def deactivate_user(
    user_id: str,
    db: Session = Depends(get_db),
    admin=Depends(admin_required)
):
    """Deactivate (soft-delete) a user."""
    import uuid
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == "admin":
        raise HTTPException(status_code=400, detail="Cannot deactivate the default admin")

    user.is_active = False
    db.commit()
    return {"message": "User deactivated", "id": user_id}


# ─── Rules Management ────────────────────────────────────────────────────────

@router.get("/rules")
def list_rules(
    db: Session = Depends(get_db),
    admin=Depends(admin_required)
):
    """List all rules with RL weights."""
    rules = db.query(Rule).order_by(Rule.id).all()
    return {
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "owasp": r.owasp,
                "severity": r.severity,
                "priority": r.priority,
                "description": r.description,
                "enabled": r.enabled,
                "target_types": r.target_types,
                "rl_weight": (
                    {
                        "weight": r.rl_weight.weight,
                        "priority_score": r.rl_weight.priority_score,
                        "success_count": r.rl_weight.success_count,
                        "failure_count": r.rl_weight.failure_count,
                        "total_scans": r.rl_weight.total_scans,
                    }
                    if r.rl_weight else None
                ),
            }
            for r in rules
        ],
        "total": len(rules)
    }


@router.patch("/rules/{rule_id}")
def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    db: Session = Depends(get_db),
    admin=Depends(admin_required)
):
    """Enable/disable a rule or change its priority/severity."""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.priority is not None:
        rule.priority = payload.priority
    if payload.severity is not None:
        rule.severity = payload.severity
    if payload.description is not None:
        rule.description = payload.description

    db.commit()
    return {"message": "Rule updated", "id": rule_id}


@router.post("/rules/{rule_id}/reset-rl")
def reset_rl_weight(
    rule_id: int,
    db: Session = Depends(get_db),
    admin=Depends(admin_required)
):
    """Reset RL weights for a rule back to defaults."""
    rl = db.query(RLWeight).filter(RLWeight.rule_id == rule_id).first()
    if not rl:
        raise HTTPException(status_code=404, detail="RL weight not found")

    rl.weight = 0.5
    rl.priority_score = 0.5
    rl.success_count = 0
    rl.failure_count = 0
    rl.total_scans = 0
    db.commit()
    return {"message": "RL weight reset", "rule_id": rule_id}


# ─── System Stats ─────────────────────────────────────────────────────────────

@router.get("/stats")
def get_system_stats(
    db: Session = Depends(get_db),
    admin=Depends(admin_required)
):
    """Get system-wide statistics."""
    from sqlalchemy import func
    from backend.database.models import Vulnerability

    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    completed_scans = db.query(func.count(Scan.id)).filter(Scan.status == "completed").scalar() or 0
    failed_scans = db.query(func.count(Scan.id)).filter(Scan.status == "failed").scalar() or 0
    running_scans = db.query(func.count(Scan.id)).filter(Scan.status == "running").scalar() or 0

    total_vulns = db.query(func.count(Vulnerability.id)).scalar() or 0
    vuln_by_severity = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )

    total_users = db.query(func.count(User.id)).scalar() or 0
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 0

    total_rules = db.query(func.count(Rule.id)).scalar() or 0
    enabled_rules = db.query(func.count(Rule.id)).filter(Rule.enabled == True).scalar() or 0

    # Top rules by success rate
    top_rules = (
        db.query(Rule, RLWeight)
        .join(RLWeight, Rule.id == RLWeight.rule_id)
        .order_by(RLWeight.priority_score.desc())
        .limit(5)
        .all()
    )

    return {
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "failed": failed_scans,
            "running": running_scans,
        },
        "vulnerabilities": {
            "total": total_vulns,
            "by_severity": {row[0]: row[1] for row in vuln_by_severity},
        },
        "users": {
            "total": total_users,
            "active": active_users,
        },
        "rules": {
            "total": total_rules,
            "enabled": enabled_rules,
        },
        "top_rules_by_rl": [
            {
                "id": rule.id,
                "name": rule.name,
                "owasp": rule.owasp,
                "priority_score": rl.priority_score,
                "success_count": rl.success_count,
                "total_scans": rl.total_scans,
            }
            for rule, rl in top_rules
        ],
    }
