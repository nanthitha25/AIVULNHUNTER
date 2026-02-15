# Trigger AivulnHunter Scan
import requests
import json
import time
import sys

# Backend API URL (where main.py is running)
API_URL = "http://localhost:8000"

# Target URL (where vulnerable_app.py is running)
TARGET_URL = "http://localhost:9000/chat"

def run_scan():
    print(f"🚀 Launching scan against {TARGET_URL}...")
    
    # 1. Start Scan
    try:
        payload = {"target": TARGET_URL, "scan_type": "full"}
        # Note: The backend API (main.py -> scan.py) might require authentication.
        # Let's check headers. The auth_guard.py uses a demo token.
        headers = {"Authorization": "Bearer demo-admin-token"}
        
        response = requests.post(f"{API_URL}/scan/", json=payload, headers=headers)
        
        if response.status_code != 200:
            print(f"❌ Failed to start scan: {response.text}")
            return
            
        data = response.json()
        scan_id = data.get("scan_id")
        print(f"✅ Scan started with ID: {scan_id}")
        
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("Make sure `python3 main.py` is running in another terminal!")
        return

    # 2. Poll for status
    print("⏳ Waiting for scan completion...")
    while True:
        try:
            status_resp = requests.get(f"{API_URL}/scan/{scan_id}", headers=headers)
            status_data = status_resp.json()
            status = status_data.get("status")
            
            # Print rudimentary progress bar
            print(".", end="", flush=True)
            
            if status in ["completed", "failed", "error"]:
                print(f"\n🏁 Scan finished with status: {status}")
                
                # 3. Display Results
                results = status_data.get("results", [])
                print(f"\n📊 Vulnerabilities Found: {len(results)}")
                
                print("\n--- DETAILED REPORT ---")
                for vuln in results:
                    severity = vuln.get('severity', 'UNKNOWN')
                    name = vuln.get('name', 'Unknown')
                    status = vuln.get('status', 'UNKNOWN')
                    
                    if status == "VULNERABLE":
                        print(f"🔴 [{severity}] {name}")
                        print(f"   Explanation: {vuln.get('explanation')}")
                        print(f"   Mitigation: {vuln.get('mitigation')}")
                        print("-" * 40)
                    elif status == "secure":
                        print(f"🟢 [SECURE] {name}")
                    else:
                        print(f"⚪ [{status}] {name}")
                
                break
            
            time.sleep(2)
            
        except Exception as e:
            print(f"\n❌ Error polling status: {e}")
            break

if __name__ == "__main__":
    run_scan()
