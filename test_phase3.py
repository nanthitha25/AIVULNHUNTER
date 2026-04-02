import requests
import time
import os

BASE_URL = "http://localhost:8000"
VULN_TARGET = "http://localhost:8081/api/v1/users/1" 
SECURE_TARGET = "http://localhost:8081/api/v1/not_found_endpoint" 

def get_token():
    res = requests.post(f"{BASE_URL}/api/v1/auth/demo-login")
    return res.json()["access_token"]

def get_priority(rule_id):
    import psycopg2
    conn = psycopg2.connect("postgresql://postgres:postgres@localhost:5432/aivulnhunter")
    cur = conn.cursor()
    cur.execute(f"SELECT priority_score FROM rl_weights WHERE rule_id = {rule_id};")
    res = cur.fetchone()
    cur.close()
    conn.close()
    return res[0] if res else 0.5

def run_phase3():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Check Initial Priority for Rule 12 (API01)
    initial_p12 = get_priority(12)
    print(f"Initial Priority for Rule 12: {initial_p12}")
    
    # 2. Run Scan against Vulnerable Target (Rule 12 hit)
    print(f"\nRunning scan against vulnerable target {VULN_TARGET}...")
    res = requests.post(f"{BASE_URL}/api/v1/scans/", headers=headers, json={"target": VULN_TARGET, "scan_type": "full"})
    scan_id = res.json()["scan_id"]
    print(f"Scan ID: {scan_id}")
    
    while True:
        poll = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}", headers=headers).json()
        if poll["status"] == "completed": break
        time.sleep(2)
    
    print(f"Vulnerabilities found: {len(poll.get('results', []))}")
    for v in poll.get('results', []):
        if v.get('rule_id') == 12 or v.get('owasp') == 'API01':
            print(f"Found Rule 12: {v.get('severity')}")
        
    new_p12 = get_priority(12)
    print(f"New Priority for Rule 12 (after hit): {new_p12}")
    if new_p12 > initial_p12:
        print("✅ SUCCESS: Priority increased after vulnerability found.")
    else:
        print("❌ FAILURE: Priority did not increase.")

    # 3. Test Secure Target (Rule 12 miss)
    print("\nRunning scan against secure target...")
    res = requests.post(f"{BASE_URL}/api/v1/scans/", headers=headers, json={"target": SECURE_TARGET, "scan_type": "full"})
    scan_id = res.json()["scan_id"]
    
    while True:
        poll = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}", headers=headers).json()
        if poll["status"] in ["completed", "failed"]: break
        time.sleep(2)
        
    final_p12 = get_priority(12)
    print(f"Final Priority for Rule 12 (after miss): {final_p12}")
    if final_p12 < new_p12:
        print("✅ SUCCESS: Priority decreased/penalized after secure result.")
    else:
        print("❌ FAILURE: Priority did not decrease.")

if __name__ == "__main__":
    # Ensure secure target exists in mock
    run_phase3()
