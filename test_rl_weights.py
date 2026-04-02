import sys
import os
import sqlite3
import requests
import time

sys.path.append(os.getcwd())
from backend.database.connection import init_db, SessionLocal
from backend.database import crud_rules
from backend.database.models import Rule, RLWeight

# 1. Fetch current RL weights for our test rule (BOLA - API01)
db = SessionLocal()
rule = db.query(Rule).filter(Rule.owasp == 'API01').first()
if not rule:
    crud_rules.create_rule(db, "Broken Object Level Authorization (BOLA)", "API01", "HIGH", target_types=["REST_API"])
    rule = db.query(Rule).filter(Rule.owasp == 'API01').first()
    
weight_before = db.query(RLWeight).filter(RLWeight.rule_id == rule.id).first()
if not weight_before:
    weight_before = RLWeight(rule_id=rule.id, priority_score=0.5)
    db.add(weight_before)
    db.commit()
    db.refresh(weight_before)

score_before = weight_before.priority_score
print(f"Rule: {rule.name} (ID: {rule.id}), Initial Score: {score_before}")

# 2. Login
base_url = "http://localhost:8000/api/v1"
login_res = requests.post(f"{base_url}/auth/demo-login")
token = login_res.json().get("access_token")
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# 3. Hit the vulnerable endpoint
print("\n--- Running scan on vulnerable endpoint ---")
target_vuln = "http://localhost:9001/api/v1/users/2"
res = requests.post(f"{base_url}/scans/", headers=headers, json={"target": target_vuln})
if res.status_code == 200:
    scan_id = res.json().get("scan_id")
    print(f"Scan started: {scan_id}")
    # poll until done
    for _ in range(10):
        time.sleep(1)
        st = requests.get(f"{base_url}/scans/{scan_id}", headers=headers).json().get("status")
        if st in ["completed", "failed"]:
            print(f"Status: {st}")
            break

# 4. Check score after vulnerable hit
db.expire_all()
weight_after1 = db.query(RLWeight).filter(RLWeight.rule_id == rule.id).first()
score_after1 = weight_after1.priority_score
print(f"Score after vulnerable hit: {score_after1}")
if score_after1 > score_before:
    print("✅ Score INCREASED as expected.")
else:
    print("❌ Score did NOT increase.")

# 5. Hit a secure endpoint (e.g. 404 endpoint or endpoint that rejects)
print("\n--- Running scan on secure endpoint ---")
target_sec = "http://localhost:9001/api/v1/does_not_exist"
res = requests.post(f"{base_url}/scans/", headers=headers, json={"target": target_sec})
if res.status_code == 200:
    scan_id2 = res.json().get("scan_id")
    print(f"Scan started: {scan_id2}")
    for _ in range(10):
        time.sleep(1)
        st = requests.get(f"{base_url}/scans/{scan_id2}", headers=headers).json().get("status")
        if st in ["completed", "failed"]:
            print(f"Status: {st}")
            break

# 6. Check score after secure hit
db.expire_all()
weight_after2 = db.query(RLWeight).filter(RLWeight.rule_id == rule.id).first()
score_after2 = weight_after2.priority_score
print(f"Score after secure hit: {score_after2}")
if score_after2 < score_after1:
    print("✅ Score DECREASED as expected.")
else:
    print("❌ Score did NOT decrease.")

db.close()
