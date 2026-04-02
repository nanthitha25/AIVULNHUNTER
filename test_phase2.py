import requests
import time
import sys

BASE_URL = "http://localhost:8000"
TARGETS = {
    "LLM": "http://localhost:8081/v1/chat/completions",
    "API": "http://localhost:8081/api/v1/users/1",
    "AGENT": "http://localhost:8081/api/v1/agent/execute"
}

def run_phase2():
    print("--- Phase 2: End-to-End Pipeline Execution ---")
    
    # 1. Login
    try:
        res = requests.post(f"{BASE_URL}/api/v1/auth/demo-login")
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
    except Exception as e:
        print(f"Login failed: {e}")
        return

    for name, url in TARGETS.items():
        print(f"\n[TEST] Target Type: {name} | URL: {url}")
        
        try:
            # 2. Submit Scan
            res = requests.post(
                f"{BASE_URL}/api/v1/scans/",
                headers=headers,
                json={"target": url, "scan_type": "full"}
            )
            if res.status_code != 200:
                print(f"Failed to start scan: {res.text}")
                continue
                
            scan_id = res.json()["scan_id"]
            print(f"Scan ID: {scan_id}")
            
            # 3. Poll
            status = "pending"
            while status in ["pending", "running"]:
                time.sleep(2)
                poll_res = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}", headers=headers)
                status = poll_res.json()["status"]
            
            print(f"Scan Finished: {status}")
            
            # 4. Verify Results
            data = poll_res.json()
            vulns = data.get("results", [])
            print(f"Vulnerabilities found: {len(vulns)}")
            for v in vulns:
                print(f" - {v.get('rule_id')} ({v.get('owasp', 'N/A')}): {v.get('severity')} | {v.get('name')}")
            
            if len(vulns) > 0:
                print(f"✅ {name} Target Test PASSED")
            else:
                print(f"❌ {name} Target Test FAILED (No vulnerabilities found)")
                
        except Exception as e:
            print(f"Error testing {name}: {e}")

if __name__ == "__main__":
    run_phase2()
