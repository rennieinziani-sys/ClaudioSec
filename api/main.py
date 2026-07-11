from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio, json, os, aiosqlite
from loguru import logger
from dotenv import load_dotenv
load_dotenv()

from core.database import (
    init_db, get_events, get_event_stats, insert_event,
    mark_event_resolved, save_incident_report, get_incident_reports,
    get_db_path, add_threat_ip, save_ai_analysis,
)
from core.ai_brain import (
    analyze_event, generate_incident_report,
    get_remediation, chat_with_analyst, run_ai_analysis_loop,
)
from alerts.alerter import send_alert, send_incident_report_alert
from monitors.log_analyzer import start_log_analyzer
from monitors.auth_process_monitor import start_auth_process_monitor
from monitors.file_integrity import start_file_integrity_monitor
from monitors.network_monitor import start_network_monitor


# ── WebSocket Manager ────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self): self.active = []

    async def connect(self, ws):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data):
        for ws in self.active[:]:
            try:
                await ws.send_json(data)
            except Exception:
                self.active.remove(ws)

manager = ConnectionManager()


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app):
    init_db()
    asyncio.create_task(start_log_analyzer())
    asyncio.create_task(start_auth_process_monitor())
    asyncio.create_task(start_file_integrity_monitor())
    asyncio.create_task(start_network_monitor())
    asyncio.create_task(run_ai_analysis_loop(30))
    asyncio.create_task(_broadcast_loop())
    logger.info("ClaudioSec operational")
    yield
    logger.info("ClaudioSec shutting down")


app = FastAPI(title="ClaudioSec", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Broadcast Loop ────────────────────────────────────────────────────────────

async def _broadcast_loop():
    last_id = 0
    while True:
        await asyncio.sleep(3)
        try:
            if not manager.active:
                continue
            async with aiosqlite.connect(get_db_path()) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT 20",
                    (last_id,)
                ) as c:
                    for row in await c.fetchall():
                        e = dict(row)
                        last_id = max(last_id, e["id"])
                        await manager.broadcast({"type": "new_event", "data": e})
        except Exception as ex:
            logger.debug(f"[Broadcast] {ex}")


# ── Models ────────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]

class ThreatIPRequest(BaseModel):
    ip: str
    threat_type: str
    confidence: int = 80
    source: str = "manual"

class ManualEventRequest(BaseModel):
    event_type: str
    severity: str
    title: str
    description: str
    source_ip: Optional[str] = None
    username: Optional[str] = None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "operational", "service": "ClaudioSec", "version": "1.0.0"}


@app.get("/api/stats")
async def get_stats():
    try:
        stats = await get_event_stats()
        import psutil
        stats["system"] = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
        }
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/events")
async def list_events(
    limit: int = Query(80, le=500),
    offset: int = 0,
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
):
    events = await get_events(limit=limit, offset=offset, severity=severity, resolved=resolved)
    return {"events": events, "count": len(events)}


@app.get("/api/events/{event_id}")
async def get_event(event_id: int):
    async with aiosqlite.connect(get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM events WHERE id = ?", (event_id,)) as c:
            row = await c.fetchone()
            if not row:
                raise HTTPException(404, "Event not found")
            return dict(row)


@app.post("/api/events/{event_id}/resolve")
async def resolve_event(event_id: int):
    await mark_event_resolved(event_id)
    return {"status": "resolved", "event_id": event_id}


@app.post("/api/events/{event_id}/analyze")
async def analyze_event_ep(event_id: int):
    async with aiosqlite.connect(get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM events WHERE id = ?", (event_id,)) as c:
            row = await c.fetchone()
            if not row:
                raise HTTPException(404, "Event not found")
            event = dict(row)

    analysis = await analyze_event(event)
    await save_ai_analysis(event_id, json.dumps(analysis))
    return {"event_id": event_id, "analysis": analysis}


@app.post("/api/events/manual")
async def create_manual_event(request: ManualEventRequest):
    event_id = await insert_event(
        event_type=request.event_type,
        severity=request.severity,
        source_module="manual",
        title=request.title,
        description=request.description,
        source_ip=request.source_ip,
        username=request.username,
    )
    return {"event_id": event_id, "status": "created"}


@app.get("/api/reports")
async def list_reports(limit: int = 20):
    reports = await get_incident_reports(limit)
    return {"reports": reports, "count": len(reports)}


@app.post("/api/reports/generate")
async def generate_report():
    events = await get_events(limit=50, resolved=False)
    if not events:
        raise HTTPException(400, "No unresolved events to report on")
    report = await generate_incident_report(events)
    rid = await save_incident_report(report)
    await send_incident_report_alert(report)
    return {"report_id": rid, "report": report}


@app.post("/api/chat")
async def chat(request: ChatRequest):
    try:
        stats = await get_event_stats()
        messages = [{"role": m.role, "content": m.content} for m in request.messages]
        response = await chat_with_analyst(messages, system_context={"stats": stats})
        return {"response": response}
    except Exception as e:
        logger.error(f"[Chat] Error: {e}")
        raise HTTPException(500, f"Chat error: {str(e)}")


@app.post("/api/remediation")
async def get_remediation_ep(data: Dict[str, Any]):
    event_type = data.get("event_type", "unknown")
    context = data.get("context", {})
    result = await get_remediation(event_type, context)
    return {"remediation": result}


@app.post("/api/threat-intel/ip")
async def add_ip(request: ThreatIPRequest):
    await add_threat_ip(request.ip, request.threat_type, request.confidence, request.source)
    return {"status": "added", "ip": request.ip}


@app.get("/api/system/stats")
async def system_stats():
    import psutil
    net = psutil.net_io_counters()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory": {
            "percent": psutil.virtual_memory().percent,
            "used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
            "total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        },
        "disk": {
            "percent": psutil.disk_usage("/").percent,
            "used_gb": round(psutil.disk_usage("/").used / (1024**3), 2),
            "total_gb": round(psutil.disk_usage("/").total / (1024**3), 2),
        },
        "network": {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
        },
        "connections": len(psutil.net_connections()),
        "processes": len(psutil.pids()),
    }


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send current stats on connect
        stats = await get_event_stats()
        await websocket.send_json({"type": "stats", "data": stats})
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if os.path.exists(html_path):
        return HTMLResponse(open(html_path, encoding="utf-8").read())
    return HTMLResponse("<h1>Dashboard not found. Use React frontend on port 3000.</h1>")