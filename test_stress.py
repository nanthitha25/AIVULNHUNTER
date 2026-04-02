import requests
import concurrent.futures
import time

BASE_URL = "http://localhost:8000/api/v1"
MOCK_API = "http://localhost:9001/api/v1/users/2"

def get_token():
    res = requests.post(f"{BASE_URL}/auth/demo-login")
    return res.json()["access_token"]

def submit_scan(target, token):
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.post(
        f"{BASE_URL}/scans/",
        headers=headers,
        json={"target": target, "scan_type": "full"}
    )
    if res.status_code == 200:
        return res.json()["scan_id"]
    return None

def poll_scan(scan_id, token):
    headers = {"Authorization": f"Bearer {token}"}
    while True:
        res = requests.get(f"{BASE_URL}/scans/{scan_id}", headers=headers)
        if res.status_code == 200:
            status = res.json().get("status")
            if status in ["completed", "failed", "error"]:
                return status
        time.sleep(2)

def main():
    token = get_token()
    # Let's run 10 concurrent scans
    num_scans = 10
    targets = [MOCK_API] * num_scans
    
    print(f"--- Stress Testing with {num_scans} Concurrent Scans ---")
    
    scan_ids = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_scans) as executor:
        futures = [executor.submit(submit_scan, target, token) for target in targets]
        for future in concurrent.futures.as_completed(futures):
            scan_id = future.result()
            if scan_id:
                scan_ids.append(scan_id)
                print(f"Enqueued Scan: {scan_id}")
            else:
                print("Failed to enqueue scan!")

    print(f"--- Waiting for {len(scan_ids)} scans to finish ---")
    start = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_scans) as executor:
        poll_futures = {executor.submit(poll_scan, sid, token): sid for sid in scan_ids}
        for future in concurrent.futures.as_completed(poll_futures):
            sid = poll_futures[future]
            try:
                status = future.result()
                print(f"Scan {sid} finished with status: {status}")
            except Exception as e:
                print(f"Scan {sid} polling failed: {e}")

    duration = time.time() - start
    print(f"--- All scans finished in {duration:.2f} seconds ---")

if __name__ == "__main__":
    main()
