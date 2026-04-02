from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from backend.database.connection import get_db
from backend.database.models import User
from backend.auth.jwt import create_access_token

import bcrypt

router = APIRouter(prefix="/auth", tags=["Auth"])

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate user and return JWT token.
    """
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    # Verify password using bcrypt directly to avoid passlib bugs
    password_bytes = data.password.encode('utf-8')
    hashed_bytes = user.hashed_password.encode('utf-8')
    if not bcrypt.checkpw(password_bytes, hashed_bytes):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(data={"sub": user.username, "role": user.role})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role
    }

@router.post("/demo-login")
def demo_login(db: Session = Depends(get_db)):
    """
    Authenticate demo user without password and return JWT token.
    """
    # Use the existing 'user' account as the demo user, or create it if missing
    user = db.query(User).filter(User.username == "user").first()
    if not user:
        # Auto-create demo user for seamless experience
        hashed = bcrypt.hashpw(b"demo123", bcrypt.gensalt()).decode('utf-8')
        user = User(
            username="user",
            email="demo@example.com",
            hashed_password=hashed,
            role="user",
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Demo user is disabled")
        
    access_token = create_access_token(data={"sub": user.username, "role": user.role})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role
    }

@router.get("/test")
def test():
    """Test endpoint to verify router is registered."""
    return {"status": "auth router works"}
