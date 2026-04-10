from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, File, UploadFile, Form
from sqlalchemy.orm import Session
from typing import List, Optional
import uuid
import asyncio

from backend.database.connection import get_db, SessionLocal
from backend.database import crud_scans
from backend.schemas import ScanBase, ScanCreate, ScanResult, UrlScanRequest, FileDataScanRequest
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

@router.post("/url", response_model=ScanResult)
async def start_url_scan(
    scan_request: UrlScanRequest, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Start a URL-based scan."""
    # Map target to the target field expected by the pipeline
    internal_request = ScanCreate(target=scan_request.target, scan_type="full")
    return await start_scan(internal_request, background_tasks, db, current_user)

@router.post("/api", response_model=ScanResult)
async def start_api_scan(
    scan_request: ScanCreate, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Start an API-specific scan."""
    # We can add API-specific profiling or rules here later if needed
    return await start_scan(scan_request, background_tasks, db, current_user)

@router.post("/upload", response_model=ScanResult)
async def start_file_upload_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scanType: str = Form("file_upload"),
    metadata: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Handle file upload scanning (.json, .csv).
    Max file size: 5MB
    """
    # 1. Validate file extension
    filename = file.filename or "uploaded_file"
    if not (filename.endswith('.json') or filename.endswith('.csv')):
        raise HTTPException(status_code=400, detail="Only .json and .csv files are supported")

    # 2. Validate file size (rough check via content length if available, or reading)
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large. Max 5MB.")

    # 3. Get user
    username = current_user.get("username")
    from backend.database.models import User
    user_record = db.query(User).filter(User.username == username).first()
    if not user_record:
        raise HTTPException(status_code=404, detail="User not found")

    # 4. Create scan record
    # Store content in meta_data for the pipeline to use
    meta = {"content": content.decode("utf-8", errors="ignore"), "original_filename": filename}
    if metadata:
        try:
            import json
            meta.update(json.loads(metadata))
        except:
            pass

    scan_db = crud_scans.create_scan(
        db, 
        target=filename, 
        user_id=user_record.id, 
        scan_type="file_upload",
        meta_data=meta
    )

    # 5. Launch background task
    background_tasks.add_task(run_scan_background, scan_db.id)

    return {
        "scan_id": str(scan_db.id),
        "status": "pending",
        "target": filename,
        "results_url": f"/api/v1/scans/{scan_db.id}",
        "results": []
    }

@router.post("/upload-data", response_model=ScanResult)
async def start_json_data_scan(
    scan_request: FileDataScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Handle file scan via JSON payload (direct string data).
    """
    username = current_user.get("username")
    from backend.database.models import User
    user_record = db.query(User).filter(User.username == username).first()
    if not user_record:
        raise HTTPException(status_code=404, detail="User not found")

    filename = f"uploaded_{scan_request.file_type}_{uuid.uuid4().hex[:8]}"
    
    # Store content in meta_data for the pipeline to use
    meta = {"content": scan_request.scan_data, "file_type": scan_request.file_type}

    scan_db = crud_scans.create_scan(
        db, 
        target=filename, 
        user_id=user_record.id, 
        scan_type="file_upload",
        meta_data=meta
    )

    background_tasks.add_task(run_scan_background, scan_db.id)

    return {
        "scan_id": str(scan_db.id),
        "status": "pending",
        "target": filename,
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
