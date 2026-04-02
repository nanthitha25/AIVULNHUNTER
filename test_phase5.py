import requests
import time
import os

BASE_URL = "http://localhost:8000"

def get_token():
    res = requests.post(f"{BASE_URL}/api/v1/auth/demo-login")
    return res.json()["access_token"]

def test_reports():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Start Scan
    target = "http://localhost:8081/api/v1/users/1"
    print(f"Starting scan against {target}...")
    res = requests.post(f"{BASE_URL}/api/v1/scans/", headers=headers, json={"target": target, "scan_type": "full"})
    scan_id = res.json()["scan_id"]
    
    # 2. Wait for completion
    while True:
        poll = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}", headers=headers).json()
        if poll["status"] == "completed": break
        time.sleep(2)
        
    print("Scan completed.")
    
    # 3. Generate Report
    print(f"Generating PDF report for {scan_id}...")
    report_data = {
        "target": poll["target"],
        "results": poll["results"],
        "scan_id": scan_id
    }
    res = requests.post(f"{BASE_URL}/api/v1/report/generate", headers=headers, json=report_data)
    
    if res.status_code == 200:
        data = res.json()
        print(f"✅ SUCCESS: Report generation triggered: {data['filename']}")
        download_url = data["download_url"]
        
        # 4. Download Report
        print(f"Downloading report from {download_url}...")
        # Note: download_url might be relative, prepend BASE_URL if needed
        # Looking at report.py: f"/report/download/{filename}"
        res_dl = requests.get(f"{BASE_URL}/api/v1{download_url}", headers=headers)
        if res_dl.status_code == 200 and "application/pdf" in res_dl.headers.get("Content-Type", ""):
            print(f"✅ SUCCESS: PDF report downloaded ({len(res_dl.content)} bytes)")
        else:
            print(f"❌ FAILURE: Download failed (Status {res_dl.status_code})")
    else:
        print(f"❌ FAILURE: Report generation failed (Status {res.status_code})")
        print(f"Error: {res.text}")

if __name__ == "__main__":
    test_reports()
