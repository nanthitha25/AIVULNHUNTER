"""
Auth Routes - JWT-backed authentication with RBAC

Endpoints:
    POST /auth/login     - Authenticate and get JWT token
    POST /auth/register  - Register new user (user role only)
    GET  /auth/me        - Get current user profile
    GET  /auth/test      - Keep-alive / sanity check
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from jose import jwt, JWTError
import time

from backend.database.sqlite_db import verify_password, create_user, get_user

router = APIRouter(prefix="/auth", tags=["Auth"])

# ------------------------------------------------------------------ #
# JWT configuration                                                    #
# ------------------------------------------------------------------ #
JWT_SECRET = "aivulnhunter-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 12

FREE_SCAN_LIMIT = 3


def create_token(user: dict) -> str:
    """Issue a signed JWT containing user id, username, and role."""
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "exp": int(time.time()) + JWT_EXPIRY_HOURS * 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Verify and decode a JWT. Returns the payload or None on failure."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


# ------------------------------------------------------------------ #
# Request / Response models                                            #
# ------------------------------------------------------------------ #

class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


# ------------------------------------------------------------------ #
# Routes                                                               #
# ------------------------------------------------------------------ #

@router.post("/login")
def login(data: LoginRequest):
    """
    Authenticate a user and return a signed JWT token.

    Admin credentials (default):
        username: admin
        password: admin123

    Demo user credentials:
        username: demo_user
        password: demo123
    """
    user = verify_password(data.username, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "username": user["username"],
        "scan_limit": "unlimited" if user["role"] == "admin" else FREE_SCAN_LIMIT,
    }


@router.post("/register")
def register(data: RegisterRequest):
    """
    Register a new user account (role: user).
    Admins can only be created by existing admins via database seeding.
    """
    existing = get_user(data.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already taken")

    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    new_user = create_user(data.username, data.password, role="user")
    return {
        "message": "Registration successful",
        "username": new_user["username"],
        "role": new_user["role"],
    }


@router.get("/me")
def get_current_user_profile(token: str = ""):
    """Return current user profile from JWT (pass token as query param for quick testing)."""
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {
        "id": payload["sub"],
        "username": payload["username"],
        "role": payload["role"],
    }


@router.get("/test")
def health():
    """Sanity check - confirms auth router is registered."""
    return {"status": "auth router OK"}
