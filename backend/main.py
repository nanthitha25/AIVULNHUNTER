from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import FileResponse
import os

app = FastAPI()

# Security scheme for Swagger UI
security = HTTPBearer()

# JWT Configuration
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"

def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """JWT dependency to verify admin tokens.
    
    Args:
        credentials: HTTP Bearer credentials from Authorization header
        
    Returns:
        Decoded username from token
        
    Raises:
        HTTPException: 401 if token is invalid
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

# Include routers
from .routes.rules import router as rules_router
app.include_router(rules_router, prefix="/rules", tags=["Rules"])

# Multi-agent scan pipeline (new implementation)
from .routes.scan import router as scan_router
app.include_router(scan_router, tags=["Scan"])

# WebSocket endpoint for real-time progress updates
from .routes.scan_ws import router as scan_ws_router
app.include_router(scan_ws_router)

# RL Heatmap and metrics endpoint
from .routes.rl import router as rl_router
app.include_router(rl_router)

# LLM Analysis endpoint (Ollama/Llama 2 integration)
from .routes.llm import router as llm_router
app.include_router(llm_router)

# Login endpoint
from .routes.auth import create_access_token
from .admin_config import ADMIN_USERNAME, ADMIN_PASSWORD

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/admin/login")
def admin_login(data: LoginRequest):
    """Admin login endpoint that returns JWT token.
    
    Args:
        data: Login credentials with username and password
        
    Returns:
        access_token and token_type
        
    Raises:
        HTTPException: 401 if credentials are invalid
    """
    if data.username != ADMIN_USERNAME or data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": data.username, "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}

# Protected endpoint - requires JWT authentication
@app.get("/admin/me", tags=["Admin"])
def get_current_admin_info(admin: str = Depends(get_current_admin)):
    """Get current admin information.
    
    This endpoint is protected and requires a valid JWT token.
    The Authorize button in Swagger UI will appear after this endpoint is added.
    
    Args:
        admin: Username from JWT token (injected by get_current_admin dependency)
        
    Returns:
        Admin username
    """
    return {"admin": admin, "message": "You are authenticated as an admin"}

# ========== PDF REPORT GENERATION ==========
from .report_generator import generate_report

class ReportRequest(BaseModel):
    target: dict
    rules_applied: list = []
    vulnerabilities: list = []
    explainable_ai: list = []
    mitigations: list = []

@app.post("/report", tags=["Report"])
def generate_pdf_report(request: ReportRequest):
    """Generate a comprehensive PDF vulnerability assessment report.
    
    Report Sections:
    1. Target Overview
    2. Rules Applied
    3. Vulnerabilities Found
    4. Severity & Priority Summary
    5. Mitigation Steps
    6. Explainable AI Summary
    
    Args:
        request: Report data containing target, rules, vulnerabilities, etc.
        
    Returns:
        PDF file download
    """
    output_file = "vulnerability_report.pdf"
    
    # Convert request to dict
    scan_result = request.dict()
    
    # Generate the PDF
    generate_report(scan_result, output_file)
    
    # Return the PDF file
    if os.path.exists(output_file):
        return FileResponse(
            output_file,
            filename="AivulnHunter_Report.pdf",
            media_type="application/pdf"
        )
    else:
        raise HTTPException(status_code=500, detail="Failed to generate report")

# CORS (MANDATORY for frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later restrict
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

