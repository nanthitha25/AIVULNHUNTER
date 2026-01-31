from fastapi import APIRouter, Depends
from auth import verify_admin
import json

router = APIRouter()
RULES_PATH = "rules/rules.json"

def load_rules():
    with open(RULES_PATH) as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_PATH, "w") as f:
        json.dump(rules, f, indent=2)

@router.get("/admin/rules")
def get_rules(admin=Depends(verify_admin)):
    """Get all rules (requires admin authentication).
    
    Args:
        admin: Verified admin from JWT token
        
    Returns:
        List of all rules
    """
    return load_rules()

@router.post("/admin/rules")
def create_rule(rule: dict, admin=Depends(verify_admin)):
    """Create a new rule (requires admin authentication).
    
    Args:
        rule: Rule data to create
        admin: Verified admin from JWT token
        
    Returns:
        Created rule with ID
    """
    import uuid
    rules = load_rules()
    rule["id"] = rule.get("id", str(uuid.uuid4()))
    rules.append(rule)
    save_rules(rules)
    return rule

@router.put("/admin/rules/{rule_id}")
def update_rule(rule_id: str, updated: dict, admin=Depends(verify_admin)):
    """Update an existing rule (requires admin authentication).
    
    Args:
        rule_id: ID of rule to update
        updated: Updated rule data
        admin: Verified admin from JWT token
        
    Returns:
        Status message
    """
    rules = load_rules()
    for r in rules:
        if r["id"] == rule_id:
            r.update(updated)
    save_rules(rules)
    return {"status": "updated"}

@router.delete("/admin/rules/{rule_id}")
def delete_rule(rule_id: str, admin=Depends(verify_admin)):
    """Delete a rule (requires admin authentication).
    
    Args:
        rule_id: ID of rule to delete
        admin: Verified admin from JWT token
        
    Returns:
        Status message
    """
    rules = load_rules()
    rules = [r for r in rules if r["id"] != rule_id]
    save_rules(rules)
    return {"status": "deleted"}

