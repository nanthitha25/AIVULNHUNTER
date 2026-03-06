"""
WebSocket Connection Manager for Real-time Progress Updates

This module manages WebSocket connections for the AivulnHunter scan pipeline,
enabling real-time progress updates to the frontend during vulnerability scans.
"""

from typing import Dict
from fastapi import WebSocket


class ConnectionManager:
    """
    Manages WebSocket connections for scan progress updates.
    
    Each scan has a unique scan_id that maps to a WebSocket connection.
    This allows multiple concurrent scans with real-time progress to each client.
    """
    
    def __init__(self):
        """Initialize the connection manager with an empty connections dictionary."""
        self.active: Dict[str, WebSocket] = {}
    
    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        """
        Accept a new WebSocket connection for a specific scan.
        
        Args:
            scan_id: Unique identifier for the scan
            websocket: The WebSocket connection to accept
        """
        await websocket.accept()
        self.active[scan_id] = websocket
        print(f"[WS] Client connected for scan {scan_id}. Active connections: {len(self.active)}")
    
    async def disconnect(self, scan_id: str) -> None:
        """
        Remove a WebSocket connection when the client disconnects.
        
        Args:
            scan_id: The scan_id to disconnect
        """
        if scan_id in self.active:
            del self.active[scan_id]
            print(f"[WS] Client disconnected for scan {scan_id}. Active connections: {len(self.active)}")
    
    async def send(self, scan_id: str, message: dict) -> bool:
        """
        Send a progress message to a specific scan's connected client.
        
        Args:
            scan_id: The target scan_id
            message: Dictionary containing progress data (agent, progress, etc.)
            
        Returns:
            True if message was sent successfully, False otherwise
        """
        ws = self.active.get(scan_id)
        if ws:
            try:
                await ws.send_json(message)
                return True
            except Exception as e:
                print(f"[WS] Error sending to scan {scan_id}: {e}")
                await self.disconnect(scan_id)
                return False
        return False
    
    async def send_progress(self, scan_id: str, agent: str, progress: int, details: str = "") -> None:
        """
        Convenience method to send a standardized progress update.
        
        Args:
            scan_id: The scan identifier
            agent: Name of the current agent (e.g., "Target Profiling")
            progress: Progress percentage (0-100)
            details: Optional additional details about the progress
        """
        await self.send(scan_id, {
            "agent": agent,
            "progress": progress,
            "details": details
        })
    
    async def send_agent_start(self, scan_id: str, agent: str) -> None:
        """Send notification that an agent has started."""
        await self.send_progress(scan_id, agent, -1, "started")
    
    async def send_agent_complete(self, scan_id: str, agent: str) -> None:
        """Send notification that an agent has completed."""
        await self.send_progress(scan_id, agent, -2, "completed")
    
    async def send_error(self, scan_id: str, error: str) -> None:
        """Send an error message for a scan."""
        await self.send(scan_id, {
            "agent": "Error",
            "progress": -1,
            "error": error
        })


# Global connection manager instance
manager = ConnectionManager()

