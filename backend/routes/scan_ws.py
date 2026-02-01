"""
WebSocket Endpoint for Scan Progress Updates

This module provides WebSocket endpoints for real-time progress tracking
during vulnerability scans.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from backend.ws_manager import manager
from backend.auth import get_current_admin
from typing import Optional

router = APIRouter(prefix="/ws", tags=["WebSocket"])


@router.websocket("/scan/{scan_id}")
async def scan_ws(
    websocket: WebSocket, 
    scan_id: str,
    token: Optional[str] = None
):
    """
    WebSocket endpoint for receiving real-time scan progress updates.
    
    The client should connect to this endpoint before starting a scan.
    Progress messages will be sent as JSON with the following format:
    {
        "agent": "Target Profiling",
        "progress": 25,
        "details": "started"  // optional
    }
    
    Progress values:
    - 0-100: Normal progress percentage
    - -1: Agent started or error state
    - -2: Agent completed
    
    Args:
        websocket: The WebSocket connection
        scan_id: Unique identifier for the scan
        token: Optional JWT token for authentication
    """
    # Note: WebSocket authentication is handled differently than HTTP
    # For production, you would validate the token here
    
    try:
        # Accept the connection
        await manager.connect(scan_id, websocket)
        print(f"[WS] Client connected to scan {scan_id}")
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for any client messages (keepalive, etc.)
                data = await websocket.receive_text()
                print(f"[WS] Received from {scan_id}: {data}")
                
                # Echo back to confirm connection is alive
                await manager.send(scan_id, {"status": "connected"})
                
            except WebSocketDisconnect:
                print(f"[WS] Client disconnected from scan {scan_id}")
                await manager.disconnect(scan_id)
                break
                
    except Exception as e:
        print(f"[WS] Error in scan {scan_id}: {e}")
        await manager.disconnect(scan_id)


@router.websocket("/scan/{scan_id}/auth")
async def scan_ws_authenticated(
    websocket: WebSocket,
    scan_id: str,
    token: str
):
    """
    WebSocket endpoint with JWT token authentication.
    
    Use this endpoint when you need to authenticate the WebSocket connection.
    The token should be passed as a query parameter.
    
    Example:
    ws://127.0.0.1:8000/ws/scan/{scan_id}/auth?token={jwt_token}
    """
    # Validate token (simplified - in production use proper JWT validation)
    from jose import jwt, JWTError
    
    SECRET_KEY = "super-secret-key"
    ALGORITHM = "HS256"
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            await websocket.close(code=4001)
            return
    except JWTError:
        await websocket.close(code=4001)
        return
    
    # Proceed with authenticated connection
    try:
        await manager.connect(scan_id, websocket)
        print(f"[WS] Authenticated client connected for scan {scan_id}")
        
        while True:
            try:
                data = await websocket.receive_text()
                await manager.send(scan_id, {"status": "alive"})
            except WebSocketDisconnect:
                await manager.disconnect(scan_id)
                break
                
    except Exception as e:
        print(f"[WS] Auth error in scan {scan_id}: {e}")
        await manager.disconnect(scan_id)

