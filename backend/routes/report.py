"""
Report API - PDF generation and download endpoints
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
import os
import uuid
from pathlib import Path

from backend.dependencies.auth_guard import get_current_user
from backend.services.pdf_report import generate_pdf_report

router = APIRouter(prefix="/report", tags=["Report"])

# Ensure reports directory exists
REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

class ReportRequest(BaseModel):
    target: str
    results: List[dict]
    scan_id: Optional[str] = None

class ScanReportRequest(BaseModel):
    scan_id: str

@router.post("/demo/pdf")
async def demo_pdf_report():
    """
    Generate a demo PDF report without authentication.
    For use in interactive demo mode.
    
    Returns:
        PDF file for download
    """
    try:
        # Demo scan result
        scan_data = {
            "target": "Demo API Endpoint",
            "results": [{
                "name": "Prompt Injection",
                "owasp": "LLM01",
                "status": "DETECTED",
                "explanation": "User-controlled input modified system-level instructions.",
                "mitigation": "Separate system and user prompts, apply input sanitization"
            }]
        }
        
        filepath = generate_pdf_report(scan_data)
        filename = Path(filepath).name
        
        return FileResponse(
            path=str(filepath),
            filename="AI_Vulnerability_Report.pdf",
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate demo report: {str(e)}")

@router.post("/generate")
async def generate_report(payload: ReportRequest, user=Depends(get_current_user)):
    """
    Generate a PDF report from scan results.
    
    Args:
        payload: Report data including target and results
        user: Authenticated user
        
    Returns:
        Report file information
    """
    try:
        # Generate PDF
        scan_data = {
            "target": payload.target,
            "results": payload.results
        }
        
        filepath = generate_pdf_report(scan_data)
        filename = Path(filepath).name
        
        return {
            "status": "success",
            "filename": filename,
            "filepath": filepath,
            "download_url": f"/report/download/{filename}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

@router.post("/generate-from-scan")
async def generate_report_from_scan(
    payload: ScanReportRequest,
    user=Depends(get_current_user)
):
    """
    Generate and stream a PDF report directly from a scan ID.
    Fetches scan data from the database and returns the PDF file.

    Args:
        payload: { scan_id: str }
        user: Authenticated user

    Returns:
        PDF file response (direct download)
    """
    from backend.database.connection import SessionLocal
    from backend.database import crud_scans

    db = SessionLocal()
    try:
        try:
            scan_uuid = uuid.UUID(payload.scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan ID format")

        scan = crud_scans.get_scan(db, scan_uuid)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        vulnerabilities = crud_scans.get_scan_vulnerabilities(db, scan_uuid)

        results_list = [
            {
                "name": v.name,
                "owasp": v.owasp,
                "severity": v.severity,
                "confidence": float(v.confidence) if v.confidence else 0.0,
                "explanation": v.explanation or "No description available.",
                "mitigation": v.mitigation or "No mitigation guidance available.",
                "evidence": v.evidence or "No evidence provided.",
            }
            for v in vulnerabilities
            if v.status == "VULNERABLE"
        ]

        scan_data = {
            "target": scan.target,
            "results": results_list,
        }

        filepath = generate_pdf_report(scan_data)
        safe_name = f"aivulnhunter_scan_{payload.scan_id[:8]}.pdf"

        return FileResponse(
            path=str(filepath),
            filename=safe_name,
            media_type="application/pdf"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")
    finally:
        db.close()

@router.get("/download/{filename}")
def download_report(filename: str, user=Depends(get_current_user)):
    """
    Download a generated PDF report.
    
    Args:
        filename: Name of the PDF file to download
        user: Authenticated user
        
    Returns:
        PDF file for download
    """
    filepath = REPORTS_DIR / filename
    
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(
        path=str(filepath),
        filename=f"aivulnhunter_report_{filename}",
        media_type="application/pdf"
    )

@router.get("/list")
def list_reports(user=Depends(get_current_user)):
    """
    List all generated reports.
    
    Args:
        user: Authenticated user
        
    Returns:
        List of available reports
    """
    reports = []
    # Check if directory exists before globbing
    if REPORTS_DIR.exists():
        for f in REPORTS_DIR.glob("*.pdf"):
            stat = f.stat()
            reports.append({
                "filename": f.name,
                "size": stat.st_size,
                "created": stat.st_ctime
            })
    
    # Sort by creation time (newest first)
    reports.sort(key=lambda x: x["created"], reverse=True)
    
    return {"reports": reports}

@router.delete("/{filename}")
def delete_report(filename: str, user=Depends(get_current_user)):
    """
    Delete a generated report.
    
    Args:
        filename: Name of the PDF file to delete
        user: Authenticated user
        
    Returns:
        Deletion status
    """
    filepath = REPORTS_DIR / filename
    
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    os.remove(str(filepath))
    
    return {"status": "deleted", "filename": filename}
