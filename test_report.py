import asyncio
import requests
import sys

def test_report():
    base_url = "http://localhost:8000/api/v1"
    
    # 1. Login
    login_res = requests.post(f"{base_url}/auth/demo-login")
    token = login_res.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # 2. Get a recent scan
    res = requests.get(f"{base_url}/scans/", headers=headers, params={"limit": 1})
    scans = res.json()
    if not scans:
        print("No scans found in history.")
        return
        
    latest_scan = scans[0]
    scan_id = latest_scan["scan_id"]
    target = latest_scan["target"]
    
    # 3. Fetch vulnerabilities for the scan
    # Wait, the endpoint to get scan details is /scans/<id>
    scan_details = requests.get(f"{base_url}/scans/{scan_id}", headers=headers).json()
    results = scan_details.get("results", [])
    
    # 4. Generate report
    print(f"Generating report for scan: {scan_id}")
    payload = {
        "target": target,
        "results": results,
        "scan_id": scan_id
    }
    
    gen_res = requests.post(f"{base_url}/report/generate", headers=headers, json=payload)
    if gen_res.status_code != 200:
        print(f"Failed to generate report: {gen_res.text}")
        return
        
    gen_data = gen_res.json()
    print(f"Generate response: {gen_data}")
    
    download_url = gen_data.get("download_url")
    if not download_url:
        print("No download URL returned!")
        return
        
    print(f"Downloading from {download_url}")
    # download_url is e.g. /report/download/filename
    # Let's hit the download endpoint
    # Note: report routes are mounted with prefix /api/v1/report, but the download_url might just be the path element
    # Check if download_url starts with /api/v1
    if not download_url.startswith("/api/v1"):
        dl_url = f"{base_url}{download_url}"
    else:
        dl_url = f"http://localhost:8000{download_url}"
        
    dl_res = requests.get(dl_url, headers=headers)
    if dl_res.status_code == 200:
        with open("downloaded_report.pdf", "wb") as f:
            f.write(dl_res.content)
        print("✅ Report downloaded successfully to downloaded_report.pdf")
    else:
        print(f"❌ Failed to download report: {dl_res.text}")

if __name__ == "__main__":
    test_report()
