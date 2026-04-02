
import requests
import time
import sys
import json

BASE_URL = "http://localhost:8000/api/v1"

def test_full_lifecycle():
    print("=== Testing Full Scan Lifecycle ===")
    
    # 1. Start Scan
    print("\n[1] Starting Scan...")
    target_url = "http://localhost:9000" # Assuming the vulnerable app is running here
    # Check if target is reachable first? No, let the scanner do it.
    
    try:
        response = requests.post(f"{BASE_URL}/scans/", json={"target": target_url})
        if response.status_code != 200:
            print(f"FAILED to start scan: {response.status_code} {response.text}")
            sys.exit(1)
            
        data = response.json()
        scan_id = data.get("scan_id")
        print(f"Scan started. ID: {scan_id}")
        print(f"Status: {data.get('status')}")
        
    except Exception as e:
        print(f"Error connecting to backend: {e}")
        sys.exit(1)

    # 2. Poll Status
    print("\n[2] Polling Status...")
    for i in range(20): # Verify for up to 20 seconds
        time.sleep(1)
        resp = requests.get(f"{BASE_URL}/scans/{scan_id}")
        status_data = resp.json()
        status = status_data.get("status")
        print(f"Status check {i+1}: {status}")
        
        if status in ["completed", "failed"]:
            break
            
    # 3. Verify Results
    print("\n[3] Verifying Results...")
    if status == "completed":
        print("Scan completed successfully!")
        vulns = status_data.get("vulnerabilities_found", 0)
        print(f"Vulnerabilities Found: {vulns}")
        if vulns > 0:
            print("Vulnerabilities detected - PASSED")
        else:
            print("No vulnerabilities? Check if target is vulnerable.")
        
        # Check results structure
        results = status_data.get("results", [])
        if results:
            print(f"First result: {results[0].get('owasp')} - {results[0].get('status')}")
    else:
        print(f"Scan finished with status: {status}")
        if status == "failed":
            print("Scan FAILED.")

    # 4. List Scans
    print("\n[4] Listing Scans...")
    resp = requests.get(f"{BASE_URL}/scans/")
    history = resp.json()
    found = False
    for s in history:
        if s["scan_id"] == scan_id:
            found = True
            print(f"Found scan {scan_id} in history.")
            break
    
    if not found:
        print("Scan NOT found in history - FAILED")

if __name__ == "__main__":
    # Ensure backend is running!
    try:
        requests.get("http://localhost:8000/")
    except:
        print("Backend not running on port 8000. Start it first!")
        sys.exit(1)
        
    test_full_lifecycle()
