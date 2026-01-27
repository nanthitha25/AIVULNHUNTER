"""
Rules Manager Module

Handles all CRUD operations for vulnerability detection rules.
Rules are stored in a JSON file for persistence.
"""

import json

RULES_FILE = "rules/rules.json"


def read_rules():
    """Read all rules from the JSON file.
    
    Returns:
        List of rule dictionaries
    """
    with open(RULES_FILE, "r") as f:
        return json.load(f)


def write_rules(rules):
    """Write all rules to the JSON file.
    
    Args:
        rules: List of rule dictionaries to save
    """
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


def add_rule(rule):
    """Add a new rule.
    
    Args:
        rule: Rule dictionary (without id)
        
    Returns:
        The added rule with assigned ID
    """
    rules = read_rules()
    rule["id"] = len(rules) + 1
    rules.append(rule)
    write_rules(rules)
    return rule


def update_rule(rule_id, updated_data):
    """Update an existing rule.
    
    Args:
        rule_id: The ID of the rule to update
        updated_data: Dictionary of fields to update
        
    Returns:
        Updated rule dictionary or None if not found
    """
    rules = read_rules()
    for rule in rules:
        if rule["id"] == rule_id:
            rule.update(updated_data)
            write_rules(rules)
            return rule
    return None


def delete_rule(rule_id):
    """Delete a rule by ID.
    
    Args:
        rule_id: The ID of the rule to delete
        
    Returns:
        True if rule was deleted
    """
    rules = read_rules()
    new_rules = [r for r in rules if r["id"] != rule_id]
    write_rules(new_rules)
    return True

