import requests

def test_persistence():
    base_url = "http://localhost:8000/api/v1"
    
    # Login
    login_res = requests.post(f"{base_url}/auth/demo-login")
    token = login_res.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get all scans
    res = requests.get(f"{base_url}/scans/", headers=headers)
    scans = res.json()
    
    print(f"Total scans found in history: {len(scans)}")
    if len(scans) > 0:
        print("✅ DB Persistence Confirmed: Found existing scans.")
    else:
        print("❌ DB Persistence Failed: No scans found.")

if __name__ == "__main__":
    test_persistence()
