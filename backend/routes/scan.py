"""
Scan API - Exposes the scan pipeline via REST endpoint
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from backend.dependencies.auth_guard import get_current_user
from backend.services.scan_pipeline import run_scan_pipeline, get_scan_result, SCANS_DB
from backend.services.pdf_report import generate_pdf_report
from fastapi.responses import FileResponse

router = APIRouter(prefix="/scan", tags=["Scan"])

class ScanInput(BaseModel):
    target: str
    scan_type: Optional[str] = "API"

class ScanResult(BaseModel):
    id: str
    target: str
    status: str
    results: List[dict]

@router.post("/")
async def start_scan(payload: ScanInput, user=Depends(get_current_user)):
    """
    Start a vulnerability scan on the target.
    
    Args:
        payload: Scan input containing target URL
        user: Authenticated user (injected by get_current_user)
        
    Returns:
        Scan result with scan_id for tracking progress
    """
    import uuid
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Run the pipeline (now async with WebSocket support)
    result = run_scan_pipeline(payload.target, scan_id=scan_id)
    
    return {
        "scan_id": result.get("scan_id", scan_id),
        "target": result["target"],
        "status": result["status"],
        "profile": result.get("profile", {}),
        "results": result.get("results", []),
        "message": result.get("message", "")
    }

@router.get("/{scan_id}")
def get_scan_result_by_id(scan_id: str, user=Depends(get_current_user)):
    """Get a previously run scan result by ID."""
    result = get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

@router.get("/{scan_id}/results")
def get_scan_results(scan_id: str, user=Depends(get_current_user)):
    """Get just the results of a scan."""
    result = get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "status": result.get("status", "unknown"),
        "results": result.get("results", [])
    }

@router.get("/{scan_id}/profile")
def get_scan_profile(scan_id: str, user=Depends(get_current_user)):
    """Get the target profile from a scan."""
    result = get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "profile": result.get("profile", {})
    }

@router.post("/report")
def download_report(scan_result: dict, user=Depends(get_current_user)):
    """
    Generate and download a PDF report for a scan result.
    
    Args:
        scan_result: Scan result dictionary containing target and results
        user: Authenticated user
        
    Returns:
        PDF file response
    """
    import os
    os.makedirs("backend/reports", exist_ok=True)
    pdf_path = generate_pdf_report(scan_result)
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename="scan_report.pdf"
    )
