import requests
import time
import sys

BASE_URL = "http://localhost:8000"

def get_token():
    res = requests.post(f"{BASE_URL}/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    if res.status_code == 200:
        return res.json()["access_token"]
    else:
        print("Failed to login:", res.text)
        sys.exit(1)

def submit_scan(target, token):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"target": target, "scan_type": "full"}
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

def run_workflow():
    token = get_token()
    targets = [
        "http://localhost:8080/v1/chat/completions",
        "http://localhost:8080/api/v1/users/1",
        "http://localhost:8080/api/v1/agent/execute"
    ]
    
    for target in targets:
        print(f"--- Testing Target: {target} ---")
        scan_id = submit_scan(target, token)
        if scan_id:
            result = poll_scan(scan_id, token)
            print("Profile:", result.get("profile", {}).get("type"))
            vulns = result.get("results", [])
            print(f"Found {len(vulns)} vulnerabilities:")
            for v in vulns:
                print(f" - {v.get('owasp')}: {v.get('severity')}")
        print("\n")

if __name__ == "__main__":
    run_workflow()
