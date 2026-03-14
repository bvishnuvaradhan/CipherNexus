"""
WebSocket Manager — handles live client connections and broadcasts.
"""

from __future__ import annotations
import asyncio
import json
from datetime import datetime
from typing import List, Dict, Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

websocket_router = APIRouter()


class ConnectionManager:
    """Manages all active WebSocket connections and provides broadcast helpers."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[CONNECTED] WS client connected - total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"[DISCONNECTED] WS client disconnected - total: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Send a JSON message to every connected client."""
        if not self.active_connections:
            return
        text = json.dumps(message, default=str)
        dead: List[WebSocket] = []
        for ws in self.active_connections:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def broadcast_alert(self, alert: Dict):
        await self.broadcast({"type": "alert", "data": alert, "timestamp": datetime.utcnow().isoformat()})

    async def broadcast_agent_message(self, msg: Dict):
        await self.broadcast({"type": "agent_message", "data": msg, "timestamp": datetime.utcnow().isoformat()})

    async def broadcast_response(self, response: Dict):
        await self.broadcast({"type": "response", "data": response, "timestamp": datetime.utcnow().isoformat()})

    async def broadcast_threat_level(self, threat: Dict):
        await self.broadcast({"type": "threat_level", "data": threat, "timestamp": datetime.utcnow().isoformat()})

    async def broadcast_log(self, log: Dict):
        await self.broadcast({"type": "log", "data": log, "timestamp": datetime.utcnow().isoformat()})

    async def broadcast_status(self, status: Dict):
        await self.broadcast({"type": "status", "data": status, "timestamp": datetime.utcnow().isoformat()})


# Global singleton
manager = ConnectionManager()


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@websocket_router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send welcome handshake
        await websocket.send_text(json.dumps({
            "type": "connected",
            "data": {"message": "AI Cyber Defense System — live feed active"},
            "timestamp": datetime.utcnow().isoformat(),
        }))
        # Keep connection alive — heartbeat every 30 s
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Echo back ping/pong
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({
                    "type": "heartbeat",
                    "data": {"status": "alive"},
                    "timestamp": datetime.utcnow().isoformat(),
                }))
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[WARN] WebSocket endpoint error: {e}")
    finally:
        manager.disconnect(websocket)
