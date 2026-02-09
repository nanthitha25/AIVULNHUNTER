import bcrypt

# Pre-computed bcrypt hashes - STATIC, never change on restart
# Generated once using: bcrypt.hashpw(b"admin123", bcrypt.gensalt())
ADMIN_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.dW8KIuJ3eHFfTi"
USER_HASH = "$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi"

# User database with STATIC hashes
USERS_DB = {
    "admin": {
        "username": "admin",
        "hashed_password": ADMIN_HASH,
        "role": "admin"
    },
    "user": {
        "username": "user",
        "hashed_password": USER_HASH,
        "role": "user"
    }
}

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using bcrypt."""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def authenticate_user(username: str, password: str):
    """Authenticate user by username and password."""
    # DEBUG PRINTS
    print("DEBUG USERNAME:", username)
    print("DEBUG PASSWORD:", password)
    
    user = USERS_DB.get(username)
    print("DEBUG USER RECORD:", user)
    
    if not user:
        print("DEBUG: user not found")
        return None
    
    ok = verify_password(password, user["hashed_password"])
    print("DEBUG PASSWORD VERIFY RESULT:", ok)
    
    if not ok:
        return None
    
    return user

def create_access_token(data: dict, SECRET_KEY: str, ALGORITHM: str, expires_minutes: int = 60):
    """Create a JWT access token."""
    from datetime import datetime, timedelta
    from jose import jwt
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

