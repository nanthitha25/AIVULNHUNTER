from fastapi import APIRouter, Header, HTTPException
import json, uuid
from auth import verify_token

router = APIRouter()
RULES_PATH = "rules/rules.json"

def load_rules():
    with open(RULES_PATH) as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_PATH, "w") as f:
        json.dump(rules, f, indent=2)

@router.get("/admin/rules")
def get_rules(authorization: str = Header(...)):
    """Get all rules (requires JWT authentication).
    
    Args:
        authorization: Bearer token in Authorization header
        
    Returns:
        List of all rules
        
    Raises:
        HTTPException: 401 if token is invalid
    """
    verify_token(authorization.replace("Bearer ", ""))
    return load_rules()

@router.post("/admin/rules")
def create_rule(rule: dict, authorization: str = Header(...)):
    """Create a new rule (requires JWT authentication).
    
    Args:
        rule: Rule data to create
        authorization: Bearer token in Authorization header
        
    Returns:
        Created rule with ID
        
    Raises:
        HTTPException: 401 if token is invalid
    """
    verify_token(authorization.replace("Bearer ", ""))
    rules = load_rules()
    rule["id"] = rule.get("id", str(uuid.uuid4()))
    rules.append(rule)
    save_rules(rules)
    return rule

@router.put("/admin/rules/{rule_id}")
def update_rule(rule_id: str, updated: dict, authorization: str = Header(...)):
    """Update an existing rule (requires JWT authentication).
    
    Args:
        rule_id: ID of rule to update
        updated: Updated rule data
        authorization: Bearer token in Authorization header
        
    Returns:
        Status message
        
    Raises:
        HTTPException: 401 if token is invalid
    """
    verify_token(authorization.replace("Bearer ", ""))
    rules = load_rules()
    for r in rules:
        if r["id"] == rule_id:
            r.update(updated)
    save_rules(rules)
    return {"status": "updated"}

@router.delete("/admin/rules/{rule_id}")
def delete_rule(rule_id: str, authorization: str = Header(...)):
    """Delete a rule (requires JWT authentication).
    
    Args:
        rule_id: ID of rule to delete
        authorization: Bearer token in Authorization header
        
    Returns:
        Status message
        
    Raises:
        HTTPException: 401 if token is invalid
    """
    verify_token(authorization.replace("Bearer ", ""))
    rules = load_rules()
    rules = [r for r in rules if r["id"] != rule_id]
    save_rules(rules)
    return {"status": "deleted"}

