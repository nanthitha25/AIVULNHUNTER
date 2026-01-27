"""
Rules Management API

FastAPI application for managing vulnerability detection rules.
Provides REST endpoints for CRUD operations on rules with authentication.
"""

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from rules_manager import (
    read_rules,
    add_rule,
    update_rule,
    delete_rule
)
from auth import authenticate, verify_token

app = FastAPI()

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/admin/login")
def admin_login(credentials: dict):
    """Admin login endpoint.
    
    Args:
        credentials: Dictionary with username and password
        
    Returns:
        Token if credentials are valid
        
    Raises:
        HTTPException: If credentials are invalid
    """
    token = authenticate(
        credentials.get("username"),
        credentials.get("password")
    )
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": token}


@app.get("/admin/rules")
def get_rules(token: str = Header(...)):
    """Get all rules (requires authentication).
    
    Args:
        token: Admin token from header
        
    Returns:
        List of all rules
        
    Raises:
        HTTPException: If token is invalid
    """
    if not verify_token(token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    return read_rules()


@app.post("/admin/rules")
def create_rule(rule: dict, token: str = Header(...)):
    """Create a new rule (requires authentication).
    
    Args:
        rule: Rule data
        token: Admin token from header
        
    Returns:
        The created rule with assigned ID
        
    Raises:
        HTTPException: If token is invalid
    """
    if not verify_token(token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    return add_rule(rule)


@app.put("/admin/rules/{rule_id}")
def edit_rule(rule_id: int, rule: dict, token: str = Header(...)):
    """Update an existing rule (requires authentication).
    
    Args:
        rule_id: ID of the rule to update
        rule: Updated rule data
        token: Admin token from header
        
    Returns:
        The updated rule dictionary
        
    Raises:
        HTTPException: If token is invalid or rule not found
    """
    if not verify_token(token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    updated = update_rule(rule_id, rule)
    if not updated:
        return {"error": "Rule not found"}
    return updated


@app.delete("/admin/rules/{rule_id}")
def remove_rule(rule_id: int, token: str = Header(...)):
    """Delete a rule (requires authentication).
    
    Args:
        rule_id: ID of the rule to delete
        token: Admin token from header
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If token is invalid
    """
    if not verify_token(token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    delete_rule(rule_id)
    return {"message": "Rule deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

