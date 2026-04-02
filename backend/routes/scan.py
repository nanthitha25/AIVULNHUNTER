from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import uuid
import asyncio

from backend.database.connection import get_db, SessionLocal
from backend.database import crud_scans
from backend.schemas import ScanBase, ScanCreate, ScanResult
from backend.services.pipeline_service import pipeline_service

router = APIRouter()

async def run_scan_background(scan_id: uuid.UUID):
    """Background task wrapper for the pipeline."""
    db = SessionLocal()
    try:
        await pipeline_service.run_scan(db, scan_id=scan_id)
    except Exception as e:
        print(f"Background scan failed: {e}")
    finally:
        db.close()

from backend.dependencies.auth_guard import get_current_user

@router.post("/", response_model=ScanResult)
async def start_scan(
    scan_request: ScanCreate, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Start a new vulnerability scan.
    Creates DB record immediately and runs pipeline in background.
    """
    username = current_user.get("username")
    role = current_user.get("role")

    # Look up user in DB to bind the scan
    from backend.database.models import User
    user_record = db.query(User).filter(User.username == username).first()
    if not user_record:
        raise HTTPException(status_code=404, detail="User not found")
        
    user_id = user_record.id
    
    # Removed Demo limitations

    # 1. Create a pending scan record immediately
    scan_db = crud_scans.create_scan(db, target=scan_request.target, user_id=user_id, scan_type=scan_request.scan_type)
    
    # 2. Launch the pipeline in the background
    background_tasks.add_task(run_scan_background, scan_db.id)
    
    return {
        "scan_id": str(scan_db.id),
        "status": "pending",
        "target": scan_request.target,
        "results_url": f"/api/v1/scans/{scan_db.id}",
        "results": []
    }

@router.get("/{scan_id}", response_model=ScanResult)
def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    """
    Get the status and results of a scan.
    """
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = crud_scans.get_scan(db, scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    vulnerabilities = crud_scans.get_scan_vulnerabilities(db, scan_uuid)
    
    results_list = [
        {
            "rule_id": str(v.rule_id) if v.rule_id else None,
            "name": v.name,
            "owasp": v.owasp,
            "severity": v.severity,
            "status": v.status,
            "confidence": v.confidence,
            "explanation": v.explanation,
            "mitigation": v.mitigation,
            "evidence": v.evidence
        }
        for v in vulnerabilities
    ]
        
    return {
        "scan_id": str(scan.id),
        "status": scan.status,
        "target": scan.target,
        "profile": scan.profile,
        "results": results_list,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "results_url": f"/api/v1/scans/{scan_id}"
    }

@router.get("/", response_model=List[ScanResult])
def list_scans(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """List recent scans."""
    scans = crud_scans.get_scans(db, offset=skip, limit=limit)
    return [
        {
            "scan_id": str(s.id),
            "status": s.status,
            "target": s.target,
            "vulnerabilities_found": s.vulnerabilities_found,
            "results_url": f"/api/v1/scans/{s.id}",
            "results": []
        }
        for s in scans
    ]
