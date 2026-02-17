"""
Scan routes for AivulnHunter API
Handles scan creation, status checking, and results retrieval
Now using PostgreSQL-backed pipeline by default
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.orm import Session
import uuid

# Use database-backed pipeline as default
from backend.services.scan_pipeline_db import run_scan_pipeline, get_scan_result
from backend.database.connection import get_db
from backend.database import crud_scans
from backend.dependencies.auth_guard import get_current_user
from backend.services.pdf_report import generate_pdf_report

router = APIRouter(prefix="/scan", tags=["Scan"])

FREE_SCAN_LIMIT = 3


# ------------------------------------------------------------------ #
# Request / Response models                                            #
# ------------------------------------------------------------------ #

class ScanInput(BaseModel):
    target: str
    scan_type: Optional[str] = "full"


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

    Returns:
        scan_id for tracking results via GET /scan/{scan_id}
    """
    # Get user_id if user is authenticated
    user_id = None
    if user and hasattr(user, 'id'):
        user_id = user.id
    elif isinstance(user, dict):
        user_id = user.get("sub") or user.get("id")
    
    # Run the database-backed pipeline
    result = run_scan_pipeline(payload.target, user_id=user_id)
    
    return {
        "scan_id": result.get("scan_id"),
        "target": result["target"],
        "status": result["status"],
        "results_url": result.get("results_url", f"/scan/{result.get('scan_id')}")
    }

@router.get("/history")
def get_scan_history(
    limit: int = 20,
    offset: int = 0,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    """
    Get scan history with pagination.
    
    Args:
        limit: Maximum number of scans to return (default: 20)
        offset: Offset for pagination (default: 0)
        status: Filter by status (optional)
        db: Database session
        user: Authenticated user
        
    Returns:
        List of scans with metadata
    """
    # Get user_id if available
    user_id = None
    if user and hasattr(user, 'id'):
        user_id = user.id
    elif isinstance(user, dict):
        user_id = user.get("sub") or user.get("id")
    
    # Fetch scans from database
    scans = crud_scans.get_scans(
        db=db,
        user_id=user_id,
        status=status,
        limit=limit,
        offset=offset
    )
    
    # Format response
    return {
        "scans": [
            {
                "id": str(scan.id),
                "target": scan.target,
                "status": scan.status,
                "scan_type": scan.scan_type,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
                "vulnerabilities_found": scan.vulnerabilities_found,
                "total_rules_tested": scan.total_rules_tested
            }
            for scan in scans
        ],
        "limit": limit,
        "offset": offset,
        "count": len(scans)
    }

@router.get("/{scan_id}")
def get_scan_result_by_id(scan_id: str, user=Depends(get_current_user)):
    """Get a previously run scan result by ID from database."""
    result = get_scan_result(scan_id)
    if result:
        return result
    raise HTTPException(status_code=404, detail="Scan not found")

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
