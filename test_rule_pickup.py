import requests
import time
import os

BASE_URL = "http://localhost:8000"
LLM_TARGET = "http://localhost:8081/v1/chat/completions"

def run_test():
    # 1. Login
    res = requests.post(f"{BASE_URL}/api/v1/auth/demo-login")
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Disable rule 1 (Prompt Injection)
    import psycopg2
    conn = psycopg2.connect("postgresql://postgres:postgres@localhost:5432/aivulnhunter")
    cur = conn.cursor()
    cur.execute("UPDATE rules SET enabled = false WHERE id = 1;")
    conn.commit()
    print("Rule 1 (Prompt Injection) disabled.")
    
    try:
        # 3. Start Scan
        print(f"Starting scan for {LLM_TARGET}...")
        res = requests.post(
            f"{BASE_URL}/api/v1/scans/",
            headers=headers,
            json={"target": LLM_TARGET, "scan_type": "full"}
        )
        if res.status_code != 200:
            print(f"Error starting scan: {res.text}")
            return
        scan_id = res.json()["scan_id"]
        
        # 4. Wait for completion
        status = "pending"
        while status in ["pending", "running"]:
            time.sleep(2)
            poll_res = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}", headers=headers)
            status = poll_res.json()["status"]
            
        print(f"Scan {scan_id} finished with status: {status}")
        
        # 5. Check results
        results = poll_res.json()["results"]
        rule_ids_found = [str(r["rule_id"]) for r in results]
        print(f"Rule IDs found as vulnerable: {rule_ids_found}")
        
        if "1" in rule_ids_found:
            print("❌ FAILURE: Disabled Rule 1 was still executed or reported!")
        else:
            print("✅ SUCCESS: Disabled Rule 1 was NOT found.")
            
    finally:
        # 6. Re-enable rule 1
        cur.execute("UPDATE rules SET enabled = true WHERE id = 1;")
        conn.commit()
        cur.close()
        conn.close()
        print("Rule 1 re-enabled.")

if __name__ == "__main__":
    run_test()
