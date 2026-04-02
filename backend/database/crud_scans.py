"""
Database CRUD operations for scans
Provides helper functions for scan-related database operations
"""

from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
import uuid

from backend.database.models import Scan, Vulnerability, ScanLog


def create_scan(
    db: Session,
    target: str,
    user_id: Optional[uuid.UUID] = None,
    scan_type: str = "full"
) -> Scan:
    """
    Create a new scan record
    
    Args:
        db: Database session
        target: Target URL to scan
        user_id: Optional user ID who initiated the scan
        scan_type: Type of scan (full, quick, custom)
    
    Returns:
        Created Scan object
    """
    scan = Scan(
        target=target,
        user_id=user_id,
        scan_type=scan_type,
        status="pending"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: uuid.UUID) -> Optional[Scan]:
    """Get scan by ID"""
    return db.query(Scan).filter(Scan.id == scan_id).first()


def get_scans(
    db: Session,
    user_id: Optional[uuid.UUID] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Scan]:
    """
    Get list of scans with optional filtering
    
    Args:
        db: Database session
        user_id: Filter by user ID
        status: Filter by status
        limit: Maximum number of results
        offset: Offset for pagination
    
    Returns:
        List of Scan objects
    """
    query = db.query(Scan)
    
    if user_id:
        query = query.filter(Scan.user_id == user_id)
    
    if status:
        query = query.filter(Scan.status == status)
    return query.order_by(Scan.started_at.desc()).limit(limit).offset(offset).all()


def count_scans_by_user(
    db: Session,
    user_id: uuid.UUID
) -> int:
    """
    Count total scans for a given user.
    """
    return db.query(Scan).filter(Scan.user_id == user_id).count()


def update_scan_status(
    db: Session,
    scan_id: uuid.UUID,
    status: str,
    profile: Optional[dict] = None
) -> Optional[Scan]:
    """Update scan status and optionally profile"""
    scan = get_scan(db, scan_id)
    if scan:
        scan.status = status
        if profile:
            scan.profile = profile
        db.commit()
        db.refresh(scan)
    return scan


def complete_scan(
    db: Session,
    scan_id: uuid.UUID,
    vulnerabilities_found: int,
    total_rules_tested: int
) -> Optional[Scan]:
    """Mark scan as completed"""
    scan = get_scan(db, scan_id)
    if scan:
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.vulnerabilities_found = vulnerabilities_found
        scan.total_rules_tested = total_rules_tested
        
        # Calculate duration
        if scan.started_at:
            started = scan.started_at.replace(tzinfo=timezone.utc) if getattr(scan.started_at, 'tzinfo', None) is None else scan.started_at
            completed = scan.completed_at
            if getattr(completed, 'tzinfo', None) is None:
                completed = completed.replace(tzinfo=timezone.utc)
            duration = (completed - started).total_seconds()
            scan.duration_seconds = int(duration)
        
        db.commit()
        db.refresh(scan)
    return scan


def add_vulnerability(
    db: Session,
    scan_id: uuid.UUID,
    rule_id: Optional[int],
    name: str,
    owasp: str,
    severity: str,
    status: str,
    confidence: float,
    explanation: str,
    mitigation: str,
    evidence: str = "",
    error_message: str = ""
) -> Vulnerability:
    """Add a vulnerability finding to a scan"""
    vuln = Vulnerability(
        scan_id=scan_id,
        rule_id=rule_id,
        name=name,
        owasp=owasp,
        severity=severity,
        status=status,
        confidence=confidence,
        explanation=explanation,
        mitigation=mitigation,
        evidence=evidence,
        error_message=error_message
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


def add_scan_log(
    db: Session,
    scan_id: uuid.UUID,
    agent_name: str,
    log_level: str,
    message: str,
    details: dict = None
) -> ScanLog:
    """Add a log entry for a scan"""
    log = ScanLog(
        scan_id=scan_id,
        agent_name=agent_name,
        log_level=log_level,
        message=message,
        details=details or {}
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def get_scan_vulnerabilities(
    db: Session,
    scan_id: uuid.UUID
) -> List[Vulnerability]:
    """Get all vulnerabilities for a scan"""
    return db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()


def delete_scan(db: Session, scan_id: uuid.UUID) -> bool:
    """Delete a scan and all related data (cascades to vulnerabilities and logs)"""
    scan = get_scan(db, scan_id)
    if scan:
        db.delete(scan)
        db.commit()
        return True
    return False
