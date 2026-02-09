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

from dependencies.auth_guard import get_current_user
from services.pdf_report import generate_pdf_report

router = APIRouter(prefix="/report", tags=["Report"])

# Ensure reports directory exists
REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

class ReportRequest(BaseModel):
    target: str
    results: List[dict]
    scan_id: Optional[str] = None

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

