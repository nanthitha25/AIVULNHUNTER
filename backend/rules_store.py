"""
Rules Store - In-memory storage for security rules
"""

import json
import os

# Default rules
DEFAULT_RULES = [
    {
        "id": "1",
        "name": "Prompt Injection",
        "owasp": "LLM01",
        "severity": "HIGH",
        "priority": 1
    },
    {
        "id": "2",
        "name": "Broken Authentication",
        "owasp": "A02",
        "severity": "HIGH",
        "priority": 2
    },
    {
        "id": "3",
        "name": "Insecure Output Handling",
        "owasp": "LLM02",
        "severity": "MEDIUM",
        "priority": 3
    },
    {
        "id": "4",
        "name": "Training Data Poisoning",
        "owasp": "LLM03",
        "severity": "CRITICAL",
        "priority": 1
    }
]

def load_rules():
    """Load rules from JSON file."""
    rules_path = os.path.join(os.path.dirname(__file__), "rules", "rules.json")
    try:
        with open(rules_path) as f:
            rules = json.load(f)
            if rules:
                return rules
    except Exception as e:
        print(f"[Rules] Could not load rules from file: {e}")
    return DEFAULT_RULES.copy()

# In-memory rules database
rules_db = load_rules()

