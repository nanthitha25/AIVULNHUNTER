from fastapi import Header, HTTPException, Depends
from backend.auth.jwt import get_current_user as decode_token

def get_current_user(authorization: str = Header(None)):
    """Validate JWT token and return user payload."""
    if authorization is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = decode_token(token)
        # return the payload dict, e.g., {"sub": "admin", "role": "admin"}
        return {"username": payload.get("sub"), "role": payload.get("role")}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


from fastapi import Depends

def require_role(required_role: str):
    """
    Dependency to require a specific role.
    Usage: @app.get("/", dependencies=[Depends(require_role("admin"))])
    """
    def role_checker(user: dict = Depends(get_current_user)):
        if user.get("role") != required_role:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_checker

