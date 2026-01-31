from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt
import datetime

app = FastAPI()

# CORS (MANDATORY for frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later restrict
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT CONFIG
SECRET_KEY = "AIVULNHUNTER_SECRET"
ALGORITHM = "HS256"

# Hardcoded admin (OK for final year)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


class AdminLogin(BaseModel):
    username: str
    password: str


@app.post("/admin/login")
def admin_login(data: AdminLogin):
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

    token = jwt.encode(
        {
            "sub": data.username,
            "role": "admin",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }

