"""
Data migration utility to migrate from JSON/in-memory storage to PostgreSQL
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from sqlalchemy.orm import Session

# Add parent directory to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal, init_db, check_connection
from backend.database.models import Rule, RLWeight, User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def migrate_rules_from_json(db: Session, json_path: str = None):
    """
    Migrate rules from rules.json to PostgreSQL
    
    Args:
        db: Database session
        json_path: Path to rules.json file
    """
    if json_path is None:
        # Default path
        json_path = Path(__file__).resolve().parent.parent / "rules" / "rules.json"
    
    print(f"📂 Loading rules from {json_path}")
    
    try:
        with open(json_path, 'r') as f:
            rules_data = json.load(f)
        
        print(f"✅ Found {len(rules_data)} rules to migrate")
        
        migrated_count = 0
        for rule_data in rules_data:
            # Check if rule already exists
            existing_rule = db.query(Rule).filter(Rule.id == int(rule_data.get('id', 0))).first()
            
            if existing_rule:
                print(f"⏭️  Rule {rule_data.get('name')} already exists, skipping")
                continue
            
            # Create new rule
            rule = Rule(
                id=int(rule_data.get('id', 0)),
                name=rule_data.get('name'),
                owasp=rule_data.get('owasp'),
                severity=rule_data.get('severity', 'MEDIUM'),
                priority=rule_data.get('priority', 1),
                description=rule_data.get('description', ''),
                enabled=rule_data.get('enabled', True),
                target_types=rule_data.get('target_types', ['LLM_API', 'WEB_APP']),
                meta_data=rule_data.get('metadata', {})
            )
            
            db.add(rule)
            
            # Create corresponding RL weight entry
            rl_weight = RLWeight(
                rule_id=rule.id,
                weight=0.5,
                priority_score=0.5,
                success_count=0,
                failure_count=0,
                total_scans=0
            )
            db.add(rl_weight)
            
            migrated_count += 1
            print(f"✅ Migrated rule: {rule.name} ({rule.owasp})")
        
        db.commit()
        print(f"\n🎉 Successfully migrated {migrated_count} rules to PostgreSQL")
        
    except FileNotFoundError:
        print(f"❌ Rules file not found at {json_path}")
        print("Creating default rules instead...")
        create_default_rules(db)
    except Exception as e:
        print(f"❌ Error migrating rules: {e}")
        db.rollback()
        raise


def create_default_rules(db: Session):
    """Create default OWASP rules if no rules.json exists"""
    
    default_rules = [
        {
            "id": 1,
            "name": "Prompt Injection",
            "owasp": "LLM01",
            "severity": "HIGH",
            "priority": 1,
            "description": "Tests for prompt injection vulnerabilities",
            "target_types": ["LLM_API"]
        },
        {
            "id": 2,
            "name": "Insecure Output Handling",
            "owasp": "LLM02",
            "severity": "HIGH",
            "priority": 2,
            "description": "Tests for insecure output handling",
            "target_types": ["LLM_API"]
        },
        {
            "id": 3,
            "name": "Training Data Poisoning",
            "owasp": "LLM03",
            "severity": "CRITICAL",
            "priority": 1,
            "description": "Tests for training data poisoning indicators",
            "target_types": ["LLM_API"]
        },
        {
            "id": 4,
            "name": "Model Denial of Service",
            "owasp": "LLM04",
            "severity": "MEDIUM",
            "priority": 3,
            "description": "Tests for DoS vulnerabilities",
            "target_types": ["LLM_API", "WEB_APP"]
        },
        {
            "id": 5,
            "name": "Supply Chain Vulnerabilities",
            "owasp": "LLM05",
            "severity": "CRITICAL",
            "priority": 1,
            "description": "Tests for supply chain vulnerabilities",
            "target_types": ["LLM_API"]
        },
        {
            "id": 6,
            "name": "Sensitive Information Disclosure",
            "owasp": "LLM06",
            "severity": "HIGH",
            "priority": 2,
            "description": "Tests for information disclosure",
            "target_types": ["LLM_API", "WEB_APP"]
        },
        {
            "id": 7,
            "name": "Insecure Plugin Design",
            "owasp": "LLM07",
            "severity": "HIGH",
            "priority": 2,
            "description": "Tests for insecure plugin design",
            "target_types": ["LLM_API"]
        },
        {
            "id": 8,
            "name": "Excessive Agency",
            "owasp": "LLM08",
            "severity": "CRITICAL",
            "priority": 1,
            "description": "Tests for excessive agency vulnerabilities",
            "target_types": ["LLM_API"]
        },
        {
            "id": 9,
            "name": "Overreliance",
            "owasp": "LLM09",
            "severity": "MEDIUM",
            "priority": 3,
            "description": "Tests for overreliance on AI outputs",
            "target_types": ["LLM_API"]
        },
        {
            "id": 10,
            "name": "Model Theft",
            "owasp": "LLM10",
            "severity": "HIGH",
            "priority": 2,
            "description": "Tests for model theft vulnerabilities",
            "target_types": ["LLM_API"]
        },
        {
            "id": 11,
            "name": "Broken Authentication",
            "owasp": "API02",
            "severity": "CRITICAL",
            "priority": 1,
            "description": "Tests for authentication vulnerabilities",
            "target_types": ["WEB_APP", "GENERIC_API"]
        }
    ]
    
    for rule_data in default_rules:
        rule = Rule(**rule_data)
        db.add(rule)
        
        # Create RL weight
        rl_weight = RLWeight(
            rule_id=rule.id,
            weight=0.5,
            priority_score=0.5
        )
        db.add(rl_weight)
    
    db.commit()
    print(f"✅ Created {len(default_rules)} default rules")


def create_admin_user(db: Session):
    """Create default admin user if not exists"""
    
    existing_admin = db.query(User).filter(User.username == 'admin').first()
    if existing_admin:
        print("⏭️  Admin user already exists")
        return
    
    admin = User(
        username='admin',
        email='admin@aivulnhunter.local',
        hashed_password=pwd_context.hash('admin123'),
        full_name='System Administrator',
        role='admin',
        is_active=True
    )
    
    db.add(admin)
    db.commit()
    print("✅ Created admin user (username: admin, password: admin123)")
    print("⚠️  IMPORTANT: Change the default password in production!")


def main():
    """Main migration function"""
    print("🚀 Starting database migration...")
    print("=" * 60)
    
    # Check database connection
    print("\n1️⃣ Checking database connection...")
    if not check_connection():
        print("❌ Cannot connect to database. Please ensure PostgreSQL is running.")
        print("   Connection string: Check DATABASE_URL environment variable")
        return
    print("✅ Database connection successful")
    
    # Initialize database (create tables)
    print("\n2️⃣ Creating database tables...")
    try:
        init_db()
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return
    
    # Get database session
    db = SessionLocal()
    
    try:
        # Migrate rules
        print("\n3️⃣ Migrating rules from JSON...")
        migrate_rules_from_json(db)
        
        # Create admin user
        print("\n4️⃣ Creating admin user...")
        create_admin_user(db)
        
        print("\n" + "=" * 60)
        print("🎉 Migration completed successfully!")
        print("\n📊 Database Summary:")
        print(f"   - Rules: {db.query(Rule).count()}")
        print(f"   - Users: {db.query(User).count()}")
        print(f"   - RL Weights: {db.query(RLWeight).count()}")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    main()
