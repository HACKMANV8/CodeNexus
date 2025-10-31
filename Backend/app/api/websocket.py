"""
WebSocket Manager for Real-time Updates
Live attack streaming and dashboard updates
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime

logger = logging.getLogger(__name__)

class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_data: Dict[WebSocket, Dict[str, Any]] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_data[websocket] = {
            "client_id": client_id,
            "connected_at": datetime.utcnow(),
            "subscriptions": set(["attacks", "metrics"])
        }
        logger.info(f"WebSocket client connected: {client_id}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            client_data = self.connection_data.get(websocket, {})
            client_id = client_data.get("client_id", "unknown")
            
            self.active_connections.remove(websocket)
            if websocket in self.connection_data:
                del self.connection_data[websocket]
            
            logger.info(f"WebSocket client disconnected: {client_id}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send personal WebSocket message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: dict, subscription_type: str = "attacks"):
        disconnected = []
        
        for websocket in self.active_connections:
            client_subscriptions = self.connection_data.get(websocket, {}).get("subscriptions", set())
            
            if subscription_type in client_subscriptions:
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to broadcast WebSocket message: {e}")
                    disconnected.append(websocket)
        
        for websocket in disconnected:
            self.disconnect(websocket)

    async def handle_attack_event(self, attack_event: dict):
        message = {
            "type": "attack_event",
            "timestamp": datetime.utcnow().isoformat(),
            "data": attack_event
        }
        await self.broadcast(message, "attacks")

    async def handle_system_metrics(self, metrics: dict):
        message = {
            "type": "system_metrics",
            "timestamp": datetime.utcnow().isoformat(),
            "data": metrics
        }
        await self.broadcast(message, "metrics")

    async def handle_ml_prediction(self, prediction: dict):
        message = {
            "type": "ml_prediction",
            "timestamp": datetime.utcnow().isoformat(),
            "data": prediction
        }
        await self.broadcast(message, "ml_updates")

    async def handle_response_action(self, action: dict):
        message = {
            "type": "response_action",
            "timestamp": datetime.utcnow().isoformat(),
            "data": action
        }
        await self.broadcast(message, "responses")

    def get_connection_stats(self) -> Dict[str, Any]:
        return {
            "active_connections": len(self.active_connections),
            "connections": [
                {
                    "client_id": data["client_id"],
                    "connected_at": data["connected_at"],
                    "subscriptions": list(data["subscriptions"])
                }
                for data in self.connection_data.values()
            ]
        }

    async def handle_client_messages(self, websocket: WebSocket):
        try:
            while True:
                data = await websocket.receive_text()
                
                try:
                    message = json.loads(data)
                    await self._process_client_message(websocket, message)
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON received from WebSocket client")
                except Exception as e:
                    logger.error(f"Error processing client message: {e}")
                    
        except WebSocketDisconnect:
            self.disconnect(websocket)

    async def _process_client_message(self, websocket: WebSocket, message: dict):
        message_type = message.get("type")
        
        if message_type == "subscribe":
            subscriptions = message.get("subscriptions", [])
            if websocket in self.connection_data:
                self.connection_data[websocket]["subscriptions"] = set(subscriptions)
            
            await self.send_personal_message({
                "type": "subscription_updated",
                "subscriptions": subscriptions
            }, websocket)
            
        elif message_type == "ping":
            await self.send_personal_message({
                "type": "pong",
                "timestamp": datetime.utcnow().isoformat()
            }, websocket)

websocket_manager = WebSocketManager()

async def websocket_endpoint(websocket: WebSocket, client_id: str = "anonymous"):
    await websocket_manager.connect(websocket, client_id)
    
    try:
        await websocket_manager.handle_client_messages(websocket)
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)