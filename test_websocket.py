import asyncio
import websockets
import json
import requests
import time

BASE_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/api/v1/ws"

def get_token():
    res = requests.post(f"{BASE_URL}/api/v1/auth/demo-login")
    return res.json()["access_token"]

async def test_websocket():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Start Scan
    target = "http://localhost:8081/api/v1/users/1"
    res = requests.post(f"{BASE_URL}/api/v1/scans/", headers=headers, json={"target": target, "scan_type": "full"})
    scan_id = res.json()["scan_id"]
    print(f"Scan ID: {scan_id}")
    
    # 2. Connect to WebSocket
    # Note: Backend expects scan_id in the URL or as first message?
    # Checking ws_manager usage: manager.send_progress(str(scan_db.id), ...)
    # Usually it's /ws/{scan_id} or just /ws
    
    uri = f"{WS_URL}/scan/{scan_id}"
    print(f"Connecting to {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected!")
            
            stages_seen = set()
            start_time = time.time()
            
            while time.time() - start_time < 30:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=5)
                    data = json.loads(message)
                    print(f"WS Message: {data}")
                    
                    if data.get("agent"):
                        stages_seen.add(data["agent"])
                    if data.get("agent") in ["Observer"] and data.get("progress") == 100:
                        print("Scan completed via WS!")
                        break
                except asyncio.TimeoutError:
                    print("Timeout waiting for WS message...")
                    break
                    
            expected_stages = {"TargetProfiling", "Strategy", "Executor", "Observer"}
            missing = expected_stages - stages_seen
            if not missing:
                print("✅ SUCCESS: All scan stages seen over WebSocket.")
            else:
                print(f"❌ FAILURE: Missing stages: {missing}")

    except Exception as e:
        print(f"WebSocket Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_websocket())
