import requests
import time
import json
import asyncio
import websockets

BASE_URL = "http://localhost:8000/api/v1"
MOCK_API = "http://localhost:9001/api/v1/users/2"

def get_token():
    res = requests.post(f"{BASE_URL}/auth/demo-login")
    return res.json()["access_token"]

async def listen_ws(scan_id):
    ws_url = f"ws://localhost:8000/api/v1/ws/scan/{scan_id}"
    try:
        async with websockets.connect(ws_url) as ws:
            print("Connected to WS for MCP Scan.")
            while True:
                msg = await ws.recv()
                data = json.loads(msg)
                print(f"WS Updates => {data.get('agent')}: {data.get('details')}")
                if data.get('type') == 'complete':
                    break
    except Exception as e:
        print(f"WS error: {e}")

async def test_mcp_layer():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    print("Triggering Advanced MCP Scan...")
    # Key part: scan_type="advanced_mcp"
    res = requests.post(
        f"{BASE_URL}/scans/",
        headers=headers,
        json={"target": MOCK_API, "scan_type": "advanced_mcp"}
    )
    scan_id = res.json()["scan_id"]
    print(f"Scan ID: {scan_id}")
    
    # Listen to WebSocket to confirm MCPAgent emits correctly
    # Start WS listener in background
    ws_task = asyncio.create_task(listen_ws(scan_id))
    
    # Poll for completion
    while True:
        res = requests.get(f"{BASE_URL}/scans/{scan_id}", headers=headers)
        data = res.json()
        if data.get("status") in ["completed", "failed", "error"]:
            print(f"\nFinal Status: {data.get('status')} with {data.get('vulnerabilities_found')} vulnerabilities.")
            print("Results:")
            for r in data.get("results", []):
                print(f"  - {r['name']} ({r['severity']}): {r['status']}")
            break
        await asyncio.sleep(1)
        
    await ws_task

if __name__ == "__main__":
    asyncio.run(test_mcp_layer())
