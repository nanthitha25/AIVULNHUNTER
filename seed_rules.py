import os
import sys

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal
from backend.database.crud_rules import create_rule, get_rules

def seed_rules():
    db: Session = SessionLocal()
    try:
        existing_rules = get_rules(db)
        existing_owasps = [r.owasp for r in existing_rules]
        
        rules_to_seed = [
            {
                "name": "Prompt Injection",
                "owasp": "LLM01",
                "severity": "CRITICAL",
                "description": "Tests for prompt injection vulnerabilities.",
                "target_types": ["LLM_API"]
            },
            {
                "name": "BOLA / Auth bypass",
                "owasp": "API01",
                "severity": "HIGH",
                "description": "Tests for Broken Object Level Authorization.",
                "target_types": ["REST_API"]
            },
            {
                "name": "Autonomous Escalation",
                "owasp": "LLM08",
                "severity": "HIGH",
                "description": "Tests for AI Agent excessive agency and tool abuse.",
                "target_types": ["AGENT", "REST_API"]
            }
        ]
        
        for rule_data in rules_to_seed:
            if rule_data["owasp"] not in existing_owasps:
                print(f"Adding rule {rule_data['owasp']} ({rule_data['name']})")
                create_rule(
                    db=db,
                    name=rule_data["name"],
                    owasp=rule_data["owasp"],
                    severity=rule_data["severity"],
                    description=rule_data["description"],
                    target_types=rule_data["target_types"],
                    enabled=True
                )
            else:
                print(f"Rule {rule_data['owasp']} already exists.")
                
        print("Rule seeding complete.")
                
    except Exception as e:
        print(f"Error seeding rules: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_rules()
