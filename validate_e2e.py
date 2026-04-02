import requests
import time
import sys
import sqlite3
import json

BASE_URL = "http://localhost:8000"
DB_PATH = "aivuln.db"

def get_token():
    res = requests.post(f"{BASE_URL}/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    if res.status_code == 200:
        return res.json()["access_token"]
    else:
        print("Failed to login:", res.text)
        sys.exit(1)

def submit_scan(target, token, use_advanced_mcp=False):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"target": target}
    if use_advanced_mcp:
        payload["use_advanced_mcp"] = True
    res = requests.post(f"{BASE_URL}/api/v1/scans/", json=payload, headers=headers)
    if res.status_code == 200:
        return res.json()["scan_id"]
    else:
        print(f"Failed to submit scan for {target}:", res.text)
        return None

def poll_scan(scan_id, token):
    headers = {"Authorization": f"Bearer {token}"}
    print(f"Polling scan {scan_id}...")
    for _ in range(60): # wait up to 60 seconds
        res = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}", headers=headers)
        if res.status_code == 200:
            data = res.json()
            status = data["status"]
            if status in ["completed", "failed"]:
                print(f"Scan {scan_id} finished with status: {status}")
                return data
        time.sleep(2)
    print(f"Scan {scan_id} timed out.")
    return None

def verify_db_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    scan_id_db = scan_id.replace("-", "")
    cursor.execute("SELECT profile, total_rules_tested FROM scans WHERE id=?", (scan_id_db,))
    scan_row = cursor.fetchone()
    
    cursor.execute("SELECT name, severity FROM vulnerabilities WHERE scan_id=?", (scan_id_db,))
    vulns = cursor.fetchall()
    
    return scan_row, vulns

def test_1_rest_api(token):
    print("\n\n=== TEST 1: REST API ===")
    target = "http://localhost:9001/api/v1/users/2"
    scan_id = submit_scan(target, token)
    result = poll_scan(scan_id, token)
    
    scan_row, vulns = verify_db_scan(scan_id)
    profile_data = json.loads(scan_row[0]) if scan_row[0] else {}
    print(f"Profile Type: {profile_data.get('type')}")
    print(f"Total Rules Tested: {scan_row[1]}")
    print(f"Vulnerabilities: {vulns}")
    
    # Assertions
    assert profile_data.get("type") == "REST_API", "Profile should be REST_API"
    assert scan_row[1] > 0, "Should test some rules"
    
def test_2_llm(token):
    print("\n\n=== TEST 2: LLM Endpoint ===")
    target = "http://localhost:8080/v1/chat/completions"
    scan_id = submit_scan(target, token)
    result = poll_scan(scan_id, token)
    
    scan_row, vulns = verify_db_scan(scan_id)
    profile_data = json.loads(scan_row[0]) if scan_row[0] else {}
    print(f"Profile Type: {profile_data.get('type')}")
    print(f"Total Rules Tested: {scan_row[1]}")
    print(f"Vulnerabilities: {vulns}")

    assert profile_data.get("type") == "LLM_API", "Profile should be LLM_API"
    
def test_3_chatbot(token):
    print("\n\n=== TEST 3: Chatbot ===")
    target = "http://localhost:8080/chat"
    scan_id = submit_scan(target, token)
    result = poll_scan(scan_id, token)
    
    scan_row, vulns = verify_db_scan(scan_id)
    profile_data = json.loads(scan_row[0]) if scan_row[0] else {}
    print(f"Profile Type: {profile_data.get('type')}")
    print(f"Total Rules Tested: {scan_row[1]}")
    print(f"Vulnerabilities: {vulns}")

    assert profile_data.get("type") == "LLM_API", "Profile should be LLM_API"

def test_4_agent(token):
    print("\n\n=== TEST 4: AI Agent ===")
    target = "http://localhost:9001/agent/execute"
    scan_id = submit_scan(target, token)
    result = poll_scan(scan_id, token)
    
    scan_row, vulns = verify_db_scan(scan_id)
    profile_data = json.loads(scan_row[0]) if scan_row[0] else {}
    print(f"Profile Type: {profile_data.get('type')}")
    print(f"Total Rules Tested: {scan_row[1]}")
    print(f"Vulnerabilities: {vulns}")

    assert profile_data.get("type") == "AGENT", "Profile should be AGENT"

def test_5_mcp(token):
    print("\n\n=== TEST 5: MCP Mode ===")
    target = "http://localhost:9001/agent/execute"
    scan_id = submit_scan(target, token, use_advanced_mcp=True)
    result = poll_scan(scan_id, token)
    
    scan_row, vulns = verify_db_scan(scan_id)
    profile_data = json.loads(scan_row[0]) if scan_row[0] else {}
    print(f"Profile Type: {profile_data.get('type')}")
    print(f"Total Rules Tested: {scan_row[1]}")
    print(f"Vulnerabilities: {vulns}")

if __name__ == "__main__":
    token = get_token()
    test_1_rest_api(token)
    test_2_llm(token)
    test_3_chatbot(token)
    test_4_agent(token)
    test_5_mcp(token)
    print("\n\n🚀 All Functional Tests Completed Successfully!")
