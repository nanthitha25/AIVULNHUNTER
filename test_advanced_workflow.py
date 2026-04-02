import requests
import time
import json
import sys

BASE_URL = "http://localhost:8000"
MOCK_API = "http://localhost:8081/api/v1/users/1"  # Target 1: REST API
MOCK_AGENT = "http://localhost:8081/api/v1/agent/execute"  # Target 2: AI Agent

def test_workflow():
    print("--- AivulnHunter Automated Advanced Workflow Test ---")
    
    # 1. Login to get token
    try:
        res = requests.post(f"{BASE_URL}/api/v1/auth/demo-login")
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
    except Exception as e:
        print(f"Failed to login: {e}")
        return

    targets = [MOCK_API, MOCK_AGENT]
    
    for target in targets:
        print(f"\n--- Testing Target: {target} ---")
        try:
            # 2. Start Scan
            res = requests.post(
                f"{BASE_URL}/api/v1/scans/",
                headers=headers,
                json={"target": target, "scan_type": "full"}
            )
            scan_id = res.json()["scan_id"]
            print(f"Started scan: {scan_id}")
            
            # 3. Poll for completion
            status = "pending"
            while status in ["pending", "running"]:
                time.sleep(2)
                print(f"Polling scan {scan_id}...")
                poll_res = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}", headers=headers)
                status = poll_res.json()["status"]
                
            print(f"Scan {scan_id} finished with status: {status}")
            
            # 4. Print Results
            result_data = poll_res.json()
            print(f"Profile: {result_data.get('target_profile', 'Unknown')}")
            vulns = result_data.get("results", [])
            print(f"Found {len(vulns)} vulnerabilities:")
            for v in vulns:
                 print(f" - {v.get('rule_id')} ({v.get('owasp', 'N/A')}): {v.get('severity')} - {v.get('findings')}")
                 
        except Exception as e:
            print(f"Error testing {target}: {e}")

if __name__ == "__main__":
    test_workflow()
