import json
import sqlite3
import uuid
import sys
import os

# Set up paths
base_dir = r"C:\Users\nanth\Downloads\AIVULNHUNTER-main\AIVULNHUNTER-main"
db_path = os.path.join(base_dir, "aivulnhunter.db")
rules_file = os.path.join(base_dir, "owasp_api_agent_rules.json")

print(f"Loading rules from {rules_file} into {db_path}...")

# Load JSON rules
with open(rules_file, 'r') as f:
    rules = json.load(f)

# Connect to database
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Optional: Clear existing rules if you just want latest
# Uncomment the line below to clear old rules before importing
# conn.execute("DELETE FROM rules")

imported_count = 0
skipped_count = 0

for rule in rules:
    # Check if a rule with this name already exists to avoid duplicates
    existing = conn.execute("SELECT id FROM rules WHERE name = ?", (rule["name"],)).fetchone()
    
    if existing:
        print(f"Skipping '{rule['name']}' - already exists.")
        skipped_count += 1
        continue
        
    rid = f"IMPORTED-{str(uuid.uuid4())[:8]}"
    
    conn.execute(
        """INSERT INTO rules
           (id, name, owasp_category, severity, priority, description,
            attack_payload, detection_pattern, mitigation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            rid,
            rule["name"],
            rule["owasp_category"],
            rule["severity"],
            rule["priority"],
            rule["description"],
            rule["attack_payload"],
            rule["detection_pattern"],
            rule["mitigation"]
        )
    )
    imported_count += 1
    print(f"Imported: '{rule['name']}' ({rule['owasp_category']})")

conn.commit()
conn.close()

print(f"\nImport Summary: {imported_count} imported, {skipped_count} skipped.")
print("Rules are now active in the AIVulnHunter engine!")
