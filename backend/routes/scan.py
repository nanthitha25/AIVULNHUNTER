"""
Scan API - Extended with scan limiter, target_type support, MCP pipeline, and DB persistence

Endpoints:
    POST /scan/              - Start a vulnerability scan (free users: max 3)
    GET  /scan/{scan_id}     - Get scan status and results by ID
    GET  /scan/history       - Get current user's scan history
    POST /scan/report        - Generate and download a PDF report
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
import uuid
import asyncio

from backend.dependencies.auth_guard import get_current_user
from backend.database import sqlite_db as db
from backend.services.scan_pipeline import run_scan_pipeline, get_scan_result, SCANS_DB
from backend.services.pdf_report import generate_pdf_report

router = APIRouter(prefix="/scan", tags=["Scan"])

FREE_SCAN_LIMIT = 3


# ------------------------------------------------------------------ #
# Request / Response models                                            #
# ------------------------------------------------------------------ #

class ScanInput(BaseModel):
    target: str
    target_type: Optional[str] = "LLM"   # LLM | API | AGENT | FULL
    scan_type: Optional[str] = None       # Legacy alias, maps to target_type


# ------------------------------------------------------------------ #
# Routes                                                               #
# ------------------------------------------------------------------ #

@router.post("/")
async def start_scan(payload: ScanInput, user: dict = Depends(get_current_user)):
    """
    Start a vulnerability scan on the target.

    Scan limits:
        - Free users (role='user'): maximum 3 scans total
        - Admins: unlimited scans

    target_type options:
        LLM    - Language model endpoint (focus: prompt injection, data leakage)
        API    - REST/GraphQL API endpoint (focus: auth, injection, rate limiting)
        AGENT  - AI agent system (focus: excessive agency, tool misuse)
        FULL   - All rules applied

    Returns:
        scan_id for tracking results via GET /scan/{scan_id}
    """
    user_id = user.get("sub", "")
    role    = user.get("role", "user")

    # ── Scan Limit Check (free tier) ─────────────────────────────── #
    if role != "admin":
        current_count = db.get_scan_count(user_id)
        if current_count >= FREE_SCAN_LIMIT:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Free scan limit reached ({FREE_SCAN_LIMIT} scans). "
                    "Upgrade required to run additional scans."
                ),
            )

    # ── Resolve target_type (support legacy scan_type field) ──────── #
    target_type = payload.target_type or payload.scan_type or "LLM"
    target_type = target_type.upper()

    # ── Create scan record in DB ──────────────────────────────────── #
    scan_id = str(uuid.uuid4())
    db.create_scan(scan_id, payload.target, target_type, user_id)

    # ── Increment scan counter for free users ────────────────────── #
    if role != "admin":
        db.increment_scan_count(user_id)

    # ── Load rules from DB ────────────────────────────────────────── #
    rules = db.get_all_rules()

    # ── Launch MCP pipeline asynchronously ───────────────────────── #
    from backend.services.mcp_orchestrator import run_mcp_pipeline

    # Initialize in-memory scan record for WebSocket compatibility
    SCANS_DB[scan_id] = {
        "scan_id":     scan_id,
        "target":      payload.target,
        "target_type": target_type,
        "status":      "running",
        "profile":     {},
        "results":     [],
        "risk_summary": {},
        "mcp_log":     [],
    }

    async def _run_mcp():
        """Run the MCP pipeline in the background task."""
        try:
            result = run_mcp_pipeline(
                target=payload.target,
                target_type=target_type,
                rules=rules,
                scan_id=scan_id,
            )
            # Merge results back into in-memory store for legacy WebSocket consumers
            SCANS_DB[scan_id].update(result)
            db.update_scan_status(scan_id, result.get("status", "success"))
        except Exception as e:
            print(f"[Scan] MCP pipeline error: {e}")
            SCANS_DB[scan_id]["status"] = "error"
            db.update_scan_status(scan_id, "error")

    # Schedule as background task using current event loop
    loop = asyncio.get_event_loop()
    if loop.is_running():
        loop.create_task(_run_mcp())
    else:
        asyncio.run(_run_mcp())

    scans_remaining = (
        "unlimited" if role == "admin"
        else max(0, FREE_SCAN_LIMIT - db.get_scan_count(user_id))
    )

    return {
        "scan_id":         scan_id,
        "target":          payload.target,
        "target_type":     target_type,
        "status":          "started",
        "scans_remaining": scans_remaining,
        "results_url":     f"/scan/{scan_id}",
    }


@router.get("/history")
def scan_history(user: dict = Depends(get_current_user)):
    """
    Return the current user's scan history.

    Admins see all scans via GET /admin/scans instead.
    """
    user_id = user.get("sub", "")
    role    = user.get("role", "user")
    if role == "admin":
        return db.get_all_scans()
    return db.get_user_scans(user_id)


@router.get("/{scan_id}")
def get_scan(scan_id: str, user: dict = Depends(get_current_user)):
    """Get a scan result by ID (from in-memory store, falls back to DB results)."""
    # Check in-memory first (most recent / in-progress scans)
    result = get_scan_result(scan_id)
    if result:
        return result

    # Fall back to DB for historical scans
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_results = db.get_scan_results(scan_id)
    return {
        **scan,
        "results": scan_results,
    }


@router.get("/{scan_id}/results")
def get_scan_results(scan_id: str, user: dict = Depends(get_current_user)):
    """Get only the vulnerability results for a completed scan."""
    result = get_scan_result(scan_id)
    if result:
        return {
            "scan_id": scan_id,
            "status":  result.get("status"),
            "results": result.get("results", []),
        }
    # Try DB
    results = db.get_scan_results(scan_id)
    return {"scan_id": scan_id, "results": results}


@router.post("/report")
def generate_report(scan_result: dict, user: dict = Depends(get_current_user)):
    """
    Generate and download a PDF vulnerability report for a scan.

    The request body should be a scan result dict (from GET /scan/{id}).
    """
    import os
    os.makedirs("reports", exist_ok=True)
    pdf_path = generate_pdf_report(scan_result)
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename="aivulnhunter_report.pdf",
    )
