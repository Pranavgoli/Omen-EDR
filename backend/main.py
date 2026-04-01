import sys
import os

# Add the parent directory of backend so we can import internal modules properly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import logging
import uuid
import secrets
from typing import List
from fastapi import Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Setup simple logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Omen EDR API",
    docs_url=None, # OWASP A02:2025 - Disable default docs in prod
    redoc_url=None
)

# OWASP A01:2025 - Stateful Session Token for local handshake
# This token is passed from start_tool.py via environment variables
SESSION_TOKEN = os.getenv("OMEN_SESSION_TOKEN", secrets.token_hex(16))

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], # OWASP A02:2025 - Strict CORS
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# OWASP A02:2025 - Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Global State to hold the latest scan results
# This avoids blocking when the frontend asks for data
class SystemState:
    def __init__(self):
        self.cpu_usage = 0
        self.ram_usage = 0
        self.total_processes = 0
        self.threats_found = 0
        self.scan_status = "idle"
        self.disk_usage = 0
        self.total_threads = 0
        self.processes = []

global_state = SystemState()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        # Iterate over a copy to allow safe removal during iteration
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

@app.websocket("/ws/stats")
async def websocket_endpoint(websocket: WebSocket, token: str = None):
    # OWASP A01:2025 - Strict Access Control
    if not token or token != SESSION_TOKEN:
        await websocket.close(code=1008) # Policy Violation
        return

    try:
        await manager.connect(websocket)
    except Exception:
        return
    
    try:
        while True:
            # We wait for the client to possibly send pings, but it's mostly server-push
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task function to update state every 5 seconds
async def scanner_task():
    global global_state
    
    # We will import the actual scanner logic here inside the task to avoid circular imports 
    # and to ensure it runs properly
    try:
        from backend.scanners.process_scanner import run_full_scan
    except ImportError as e:
        logger.error(f"Failed to import scanner: {e}")
        return

    logger.info("Starting background scanner loop...")
    while True:
        try:
            # Updating state securely
            global_state.scan_status = "scanning"
            
            # Offload synchronous heavy psutil operations to a thread pool
            loop = asyncio.get_running_loop()
            scan_results = await loop.run_in_executor(None, run_full_scan)
            
            global_state.cpu_usage = scan_results.get("cpu_usage", 0)
            global_state.ram_usage = scan_results.get("ram_usage", 0)
            global_state.disk_usage = scan_results.get("disk_usage", 0)
            global_state.total_threads = scan_results.get("total_threads", 0)
            global_state.processes = scan_results.get("processes", [])
            global_state.total_processes = len(global_state.processes)
            
            # Count processes with threat score >= 10 as requested
            global_state.threats_found = sum(1 for p in global_state.processes if p.get("threat_score", 0) >= 10)
            global_state.scan_status = "idle"

            # Push the new state to all connected websocket clients
            payload = {
                "cpu_usage": global_state.cpu_usage,
                "ram_usage": global_state.ram_usage,
                "disk_usage": global_state.disk_usage,
                "total_threads": global_state.total_threads,
                "total_processes": global_state.total_processes,
                "threats_found": global_state.threats_found,
                "scan_status": global_state.scan_status,
                "processes": global_state.processes
            }
            await manager.broadcast(json.dumps(payload))
            
        except Exception as e:
            logger.error(f"Error during scheduled scan: {e}")
            
        # Tick interval
        await asyncio.sleep(1)


@app.on_event("startup")
async def startup_event():
    # Start the continuous background scanner loop
    # We use create_task so it runs independently
    asyncio.create_task(scanner_task())
    logger.info("Keylogger Detector API started. Background scanner primed.")

@app.get("/api/health")
def read_health():
    return {"status": "ok", "message": "Omen KLD Backend is secured and running."}


async def verify_token(request: Request):
    token = request.headers.get("X-Omen-Token")
    if token != SESSION_TOKEN:
        logger.warning(f"Unauthorized access attempt from {request.client.host}")
        raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing Session Token.")
    return token


@app.post("/api/quarantine/{pid}")
async def quarantine_process(pid: int, token: str = Depends(verify_token)):
    # OWASP A03:2021/2025 - Input Validation
    if pid < 0:
        raise HTTPException(status_code=400, detail="Invalid PID")
        
    from backend.scanners.process_scanner import kill_process
    success, message = kill_process(pid)
    
    if success:
        return {"status": "success", "message": message}
    else:
        # A10:2025 - Return structured error info
        return JSONResponse(
            status_code=403 if "ERR_SYSTEM_PROTECTED" in message else 500,
            content={"status": "error", "message": message}
        )
