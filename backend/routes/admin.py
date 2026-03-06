"""
Admin Router - Admin-only endpoints for rule management and analytics

Endpoints:
    POST   /admin/rules       - Create a new OWASP rule
    GET    /admin/rules       - List all rules
    DELETE /admin/rules/{id}  - Delete a rule
    GET    /admin/rlmap       - Rule Learning Map (effectiveness stats)
    GET    /admin/scans       - View all scan history
    GET    /admin/users       - View all users
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.dependencies.admin_guard import admin_required
from backend.database import sqlite_db as db

router = APIRouter(prefix="/admin", tags=["Admin"])


# ------------------------------------------------------------------ #
# Request model                                                        #
# ------------------------------------------------------------------ #

class RuleCreate(BaseModel):
    id: Optional[str] = None
    name: str
    owasp_category: str
    severity: str = "MEDIUM"
    priority: int = 3
    description: Optional[str] = ""
    attack_payload: Optional[str] = ""
    detection_pattern: Optional[str] = ""
    mitigation: Optional[str] = ""


# ------------------------------------------------------------------ #
# Rule management                                                      #
# ------------------------------------------------------------------ #

@router.get("/rules", dependencies=[Depends(admin_required)])
def list_rules():
    """Return all security rules (admin only)."""
    return db.get_all_rules()


@router.post("/rules", dependencies=[Depends(admin_required)])
def create_rule(rule: RuleCreate):
    """
    Create a new OWASP-mapped security rule (admin only).

    Rule structure:
        name             - Human-readable rule name
        owasp_category   - e.g. LLM01, LLM08, AGENT01
        severity         - CRITICAL / HIGH / MEDIUM / LOW
        priority         - 1 (highest) to 5 (lowest)
        attack_payload   - Example adversarial payload string
        detection_pattern- Regex or keyword pattern for detection
        mitigation       - Recommended fix / guidance
    """
    created = db.create_rule(rule.dict())
    return {"message": "Rule created", "rule": created}


@router.delete("/rules/{rule_id}", dependencies=[Depends(admin_required)])
def remove_rule(rule_id: str):
    """Delete a rule by ID (admin only)."""
    success = db.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    return {"message": f"Rule '{rule_id}' deleted"}


# ------------------------------------------------------------------ #
# RL Map - Rule Learning / Effectiveness Dashboard                     #
# ------------------------------------------------------------------ #

@router.get("/rlmap", dependencies=[Depends(admin_required)])
def get_rl_map():
    """
    Return Rule Learning Map data (admin only).

    Shows:
        - Total detections per rule
        - VULNERABLE vs SECURE hit counts
        - Rule success rate
        - False positive rate
        - Rule priority effectiveness rank
    """
    raw = db.get_rl_map()

    enriched = []
    for entry in raw:
        total = entry.get("total_detections") or 0
        vuln = entry.get("vuln_hits") or 0
        attack_success_rate = round(vuln / total, 4) if total > 0 else 0.0

        enriched.append({
            **entry,
            "attack_success_rate": attack_success_rate,
            "effectiveness_rank": _rank(entry["priority"], entry["success_rate"], attack_success_rate),
        })

    return {
        "summary": {
            "total_rules": len(enriched),
            "avg_success_rate": round(
                sum(e["success_rate"] for e in enriched) / len(enriched), 4
            ) if enriched else 0.0,
        },
        "rules": enriched,
    }


def _rank(priority: int, success_rate: float, attack_rate: float) -> str:
    """Simple textual rank for the RL Map."""
    score = (6 - priority) + (success_rate * 3) + (attack_rate * 2)
    if score >= 7:
        return "HIGH_IMPACT"
    elif score >= 4:
        return "MODERATE"
    else:
        return "LOW_IMPACT"


# ------------------------------------------------------------------ #
# Scan & User audit logs                                               #
# ------------------------------------------------------------------ #

@router.get("/scans", dependencies=[Depends(admin_required)])
def all_scan_logs():
    """Return all scan history across all users (admin only)."""
    return db.get_all_scans()


@router.get("/users", dependencies=[Depends(admin_required)])
def list_users(current_admin=Depends(admin_required)):
    """
    Return all registered users (admin only).
    Passwords are NOT included in the response.
    """
    from backend.database.sqlite_db import get_connection
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, username, role, scan_count, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
