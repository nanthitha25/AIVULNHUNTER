import sys
import os
import sqlite3
import time
import requests

# 1. Init DB
sys.path.append(os.getcwd())
from backend.database.connection import init_db, SessionLocal
init_db()

# Insert test rules if none exist
from backend.database import crud_rules
from backend.database.models import Rule
db = SessionLocal()
if db.query(Rule).count() == 0:
    crud_rules.create_rule(db, "Prompt Injection Vulnerability", "LLM01", "HIGH", target_types=["LLM_API"])
    crud_rules.create_rule(db, "Broken Object Level Authorization (BOLA)", "API01", "HIGH", target_types=["REST_API"])
    crud_rules.create_rule(db, "Tool Argument Injection", "AGENT01", "HIGH", target_types=["AGENT"])
    crud_rules.create_rule(db, "Broken Access Control", "A01", "HIGH", target_types=["WEB_APP"])
db.close()

# 2. Register User and get Token
base_url = "http://localhost:8000/api/v1"
try:
    login_res = requests.post(f"{base_url}/auth/demo-login")
    token = login_res.json().get("access_token")
except Exception as e:
    print(e)
    token = None
    
print(f"Token: {token}")

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

targets = [
    "http://localhost:9001/api/v1/users/1",
    "http://localhost:8080/v1/chat/completions",
    "http://localhost:9001/agent/execute"
]
scan_ids = []

for t in targets:
    print(f"Sending scan for {t}")
    res = requests.post(f"{base_url}/scans/", headers=headers, json={"target": t})
    print(res.status_code, res.text)
    if res.status_code == 200:
        scan_ids.append(res.json().get("scan_id"))

# Wait a bit for background tasks to finish profiling
time.sleep(3)

# 3. Check DB for ProfilingAgent output
conn = sqlite3.connect("aivuln.db")
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

for sid in scan_ids:
    cursor.execute("SELECT target, profile FROM scans WHERE id = ?", (sid,))
    row = cursor.fetchone()
    if row:
        print(f"\nTarget: {row['target']}\nProfile: {row['profile']}")

conn.close()
