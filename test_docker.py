import requests
import time

# Hostnames as defined in docker-compose.yml
BACKEND_URL = "http://backend:8000/api/v1"
MOCK_TARGET = "http://mock_targets:8081/api/v1/users/1"

def test_docker_pipeline():
    # 1. Login to get token
    print(f"Logging in to {BACKEND_URL}...")
    try:
        res = requests.post(f"{BACKEND_URL}/auth/demo-login")
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
    except Exception as e:
        print(f"Login failed: {e}")
        return

    # 2. Start Scan
    print(f"Starting scan against {MOCK_TARGET}...")
    res = requests.post(f"{BACKEND_URL}/scans/", headers=headers, json={"target": MOCK_TARGET, "scan_type": "full"})
    if res.status_code != 200:
        print(f"Failed to start scan: {res.text}")
        return
    
    scan_id = res.json()["scan_id"]
    print(f"Scan started: {scan_id}")

    # 3. Poll for completion
    while True:
        res = requests.get(f"{BACKEND_URL}/scans/{scan_id}", headers=headers)
        status = res.json()["status"]
        print(f"Scan Status: {status}")
        if status == "completed":
            print("✅ SUCCESS: Scan completed in Docker environment!")
            print(f"Vulnerabilities found: {len(res.json().get('results', []))}")
            break
        elif status == "failed":
            print(f"❌ FAILURE: Scan failed: {res.text}")
            break
        time.sleep(2)

if __name__ == "__main__":
    test_docker_pipeline()
