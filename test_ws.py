import asyncio
import websockets
import json
import requests
import sys

async def test_ws():
    base_url = "http://localhost:8000/api/v1"
    
    # login
    login_res = requests.post(f"{base_url}/auth/demo-login")
    token = login_res.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # create a scan
    target = "http://localhost:9001/api/v1/users/2"
    res = requests.post(f"{base_url}/scans/", headers=headers, json={"target": target})
    scan_id = res.json().get("scan_id")
    print(f"Started scan: {scan_id}")
    
    # connect to WS
    ws_url = f"ws://localhost:8000/api/v1/ws/scan/{scan_id}"
    print(f"Connecting to {ws_url}")
    
    try:
        async with websockets.connect(ws_url) as websocket:
            print("Connected to WebSocket.")
            
            # Wait for messages for a max of 10 seconds
            import time
            start = time.time()
            while time.time() - start < 10:
                try:
                    msg = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    data = json.loads(msg)
                    print(f"WS Message: {data}")
                    
                    if data.get("details", "").startswith("Scan complete"):
                        print("Scan completed successfully.")
                        break
                except asyncio.TimeoutError:
                    # just keep waiting
                    pass
    except Exception as e:
        print(f"WebSocket connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_ws())
