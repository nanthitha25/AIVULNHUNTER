from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

class ScanBase(BaseModel):
    target: str
    scan_type: Optional[str] = "full"

class ScanCreate(ScanBase):
    pass

class UrlScanRequest(BaseModel):
    target: str

class FileDataScanRequest(BaseModel):
    file_type: str
    scan_data: str

class ScanResult(BaseModel):
    scan_id: str
    target: str
    status: str
    profile: Optional[Dict[str, Any]] = None
    results: List[Dict[str, Any]] = []
    vulnerabilities_found: int = 0
    results_url: str
    
    model_config = ConfigDict(from_attributes=True)

class VulnerabilityBase(BaseModel):
    name: str
    owasp: str
    severity: str
    status: str
    confidence: float
    explanation: Optional[str] = None
    mitigation: Optional[str] = None
    evidence: Optional[str] = None

class Vulnerability(VulnerabilityBase):
    id: uuid.UUID
    scan_id: uuid.UUID
    rule_id: Optional[uuid.UUID] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class RuleBase(BaseModel):
    name: str
    owasp: str
    severity: str
    target_types: List[str]
    description: Optional[str] = ""
    enabled: bool = True

class RuleCreate(RuleBase):
    pass

class RuleUpdate(BaseModel):
    name: Optional[str] = None
    owasp: Optional[str] = None
    severity: Optional[str] = None
    target_types: Optional[List[str]] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
