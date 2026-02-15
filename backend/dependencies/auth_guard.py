from fastapi import Header, HTTPException

DEMO_TOKEN = "demo-admin-token"

def get_current_user(authorization: str = Header(None)):
    """Simple demo-safe token validation."""
    if authorization is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    
    token = authorization.replace("Bearer ", "")
    
    # Simple demo token check
    if token != DEMO_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return {"username": "admin", "role": "admin"}


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

