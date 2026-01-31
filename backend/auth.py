"""
Authentication Module

Handles admin authentication using JWT tokens.
"""

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from jose import jwt
from datetime import datetime, timedelta
from admin_config import ADMIN_USERNAME, ADMIN_PASSWORD

SECRET = "REDTEAM_SECRET"
ALGO = "HS256"

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str


def create_access_token(payload: dict):
    """Create a JWT token for the authenticated user.
    
    Args:
        payload: Token payload with user info
        
    Returns:
        JWT token string
    """
    payload["exp"] = datetime.utcnow() + timedelta(hours=2)
    return jwt.encode(payload, SECRET, algorithm=ALGO)


def verify_token(token: str):
    """Verify and decode a JWT token.
    
    Args:
        token: JWT token to verify
        
    Returns:
        Decoded token payload if valid
        
    Raises:
        HTTPException: If token is invalid
    """
    try:
        return jwt.decode(token, SECRET, algorithms=[ALGO])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.post("/login")
def login(data: LoginRequest):
    """Authenticate admin user and return JWT token.
    
    Args:
        data: Login credentials (username and password)
        
    Returns:
        JWT access token on successful authentication
        
    Raises:
        HTTPException: 401 if credentials are invalid
    """
    if data.username == ADMIN_USERNAME and data.password == ADMIN_PASSWORD:
        token = create_access_token({"sub": "admin"})
        return {"access_token": token}
    raise HTTPException(status_code=401, detail="Invalid credentials")


def authenticate(username: str, password: str):
    """Authenticate admin credentials.
    
    Args:
        username: Admin username
        password: Admin password
        
    Returns:
        JWT token if credentials are valid, None otherwise
    """
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return create_access_token({"sub": username})
    return None


def get_current_user(token: str = Depends(verify_token)):
    """Get the current user from the JWT token.
    
    Args:
        token: JWT token from Authorization header
        
    Returns:
        Username from the token
    """
    return token.get("sub")


def verify_admin(authorization: str = Header(None)):
    """Verify admin authorization token.
    
    Args:
        authorization: Authorization header with Bearer token
        
    Returns:
        Decoded token payload if valid
        
    Raises:
        HTTPException: 401 if token missing/invalid, 403 if not admin
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET, algorithms=[ALGO])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=403)
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

