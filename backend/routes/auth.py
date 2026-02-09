from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["Auth"])

# TEMP demo credentials (OK for college project)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
def login(data: LoginRequest):
    """
    Authenticate user and return JWT token.
    
    Admin credentials: admin / admin123
    """
    print("🔥 LOGIN FUNCTION CALLED 🔥")
    print("DATA:", data)
    
    if data.username != ADMIN_USERNAME or data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {
        "access_token": "demo-admin-token",
        "token_type": "bearer",
        "role": "admin"
    }

@router.get("/test")
def test():
    """Test endpoint to verify router is registered."""
    return {"status": "auth router works"}

