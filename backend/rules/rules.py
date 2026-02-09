"""
Rules module for loading and managing security rules
"""

import json
from typing import List, Dict, Any
from pathlib import Path

RULES_FILE = Path(__file__).parent / "rules.json"

def load_rules() -> List[Dict[str, Any]]:
    """
    Load security rules from the rules JSON file.
    
    Returns:
        List of rule dictionaries
    """
    try:
        with open(RULES_FILE, "r") as f:
            rules = json.load(f)
        return rules
    except FileNotFoundError:
        return []

def save_rules(rules: List[Dict[str, Any]]) -> None:
    """
    Save security rules to the rules JSON file.
    
    Args:
        rules: List of rule dictionaries to save
    """
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)

def get_rule_by_id(rule_id: str) -> Dict[str, Any]:
    """
    Get a single rule by its ID.
    
    Args:
        rule_id: The rule ID to look for
        
    Returns:
        Rule dictionary or None if not found
    """
    rules = load_rules()
    for rule in rules:
        # Handle both string and integer IDs
        rule_id_str = str(rule.get("id", ""))
        if rule_id_str == str(rule_id):
            return rule
    return None

def get_rule_by_name(rule_name: str) -> Dict[str, Any]:
    """
    Get a single rule by its name.
    
    Args:
        rule_name: The rule name to look for
        
    Returns:
        Rule dictionary or None if not found
    """
    rules = load_rules()
    for rule in rules:
        if rule.get("name", "").lower() == rule_name.lower():
            return rule
    return None

def add_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a new rule to the rules file.
    
    Args:
        rule: Rule dictionary to add
        
    Returns:
        Added rule with generated ID
    """
    import uuid
    
    rules = load_rules()
    
    # Generate ID if not provided
    if "id" not in rule:
        rule["id"] = str(uuid.uuid4())
    
    rules.append(rule)
    save_rules(rules)
    
    return rule

def update_rule(rule_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update an existing rule.
    
    Args:
        rule_id: ID of the rule to update
        updates: Dictionary of fields to update
        
    Returns:
        Updated rule dictionary
    """
    rules = load_rules()
    
    for i, rule in enumerate(rules):
        if str(rule.get("id", "")) == str(rule_id):
            # Update the rule
            rules[i] = {**rule, **updates}
            save_rules(rules)
            return rules[i]
    
    raise ValueError(f"Rule with ID {rule_id} not found")

def delete_rule(rule_id: str) -> bool:
    """
    Delete a rule from the rules file.
    
    Args:
        rule_id: ID of the rule to delete
        
    Returns:
        True if deleted, False if not found
    """
    rules = load_rules()
    
    for i, rule in enumerate(rules):
        if str(rule.get("id", "")) == str(rule_id):
            del rules[i]
            save_rules(rules)
            return True
    
    return False

def get_unique_rules() -> List[Dict[str, Any]]:
    """
    Get unique rules (deduplicated by name).
    
    Returns:
        List of unique rule dictionaries
    """
    rules = load_rules()
    seen = set()
    unique_rules = []
    
    for rule in rules:
        name = rule.get("name", "")
        if name and name not in seen:
            seen.add(name)
            unique_rules.append(rule)
    
    return unique_rules

