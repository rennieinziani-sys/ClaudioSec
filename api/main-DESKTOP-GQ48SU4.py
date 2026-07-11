from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
import asyncio, json, os, aiosqlite
from loguru import logger
from dotenv import load_dotenv
load_dotenv()

from core.database import init_db, get_events, get_event_stats, insert_event, mark_event_resolved, save_incident_report, get_incident_reports, get_db_path, add_threat_ip
from core.ai_brain import analyze_event, generate_incident_report, get_remediation, chat_with_analyst, run_ai_analysis_loop
from core.database import get_event_stats
from alerts.alerter import send_alert, send_incident_report_alert
from monitors.log_analyzer import start_log_analyzer
from monitors.auth_process_monitor import start_auth_process_monitor
from monitors.file_integrity import start_file_integrity_monitor
from monitors.network_monitor import start_network_monitor
from fastapi import WebSocket, WebSocketDisconnect, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class ConnectionManager:
    def __init__(self): self.active = []
    async def connect(self, ws):
        await ws.accept(); self.active.append(ws)
    def disconnect(self, ws): self.active.remove(ws)
    async def broadcast(self, data):
        for ws in self.active[:]:
            try: await ws.send_json(data)
            except: self.active.remove(ws)

manager = ConnectionManager()

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

app = FastAPI(title="ClaudioSec", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

async def _broadcast_loop():
    last_id = 0
    while True:
        await asyncio.sleep(3)
        try:
            async with aiosqlite.connect(get_db_path()) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT 20", (last_id,)) as c:
                    for row in await c.fetchall():
                        e = dict(row); last_id = max(last_id, e["id"])
                        await manager.broadcast({"type": "new_event", "data": e})
        except: pass

class ChatMessage(BaseModel): role: str; content: str
class ChatRequest(BaseModel): messages: List[ChatMessage]
class ThreatIPRequest(BaseModel): ip: str; threat_type: str; confidence: int = 80; source: str = "manual"
class ManualEventRequest(BaseModel): event_type: str; severity: str; title: str; description: str; source_ip: Optional[str] = None; username: Optional[str] = None

@app.get("/")
async def root(): return {"status": "operational", "service": "ClaudioSec"}

@app.get("/api/stats")
async def get_stats():
    stats = await get_event_stats()
    import psutil
    stats["system"] = {"cpu_percent": psutil.cpu_percent(), "memory_percent": psutil.virtual_memory().percent}
    return stats

@app.get("/api/events")
async def list_events(limit: int = 50, offset: int = 0, severity: Optional[str] = None, resolved: Optional[bool] = None):
    events = await get_events(limit=limit, offset=offset, severity=severity, resolved=resolved)
    return {"events": events, "count": len(events)}

@app.post("/api/events/{event_id}/resolve")
async def resolve_event(event_id: int):
    await mark_event_resolved(event_id); return {"status": "resolved"}

@app.post("/api/events/{event_id}/analyze")
async def analyze_event_ep(event_id: int):
    async with aiosqlite.connect(get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM events WHERE id = ?", (event_id,)) as c:
            row = await c.fetchone()
            if not row: raise HTTPException(404, "Not found")
    analysis = await analyze_event(dict(row))
    from core.database import save_ai_analysis
    await save_ai_analysis(event_id, json.dumps(analysis))
    return {"analysis": analysis}

@app.post("/api/reports/generate")
async def generate_report():
    events = await get_events(limit=50, resolved=False)
    report = await generate_incident_report(events)
    rid = await save_incident_report(report)
    return {"report_id": rid, "report": report}

@app.get("/api/reports")
async def list_reports(): return {"reports": await get_incident_reports(20)}

@app.post("/api/chat")
async def chat(request: ChatRequest):
    stats = await get_event_stats()
    messages = [{"role": m.role, "content": m.content} for m in request.messages]
    response = await chat_with_analyst(messages, system_context={"stats": stats})
    return {"response": response}

@app.post("/api/threat-intel/ip")
async def add_ip(request: ThreatIPRequest):
    await add_threat_ip(request.ip, request.threat_type, request.confidence, request.source)
    return {"status": "added"}

@app.get("/api/system/stats")
async def system_stats():
    import psutil
    return {"cpu_percent": psutil.cpu_percent(), "memory": {"percent": psutil.virtual_memory().percent}, "disk": {"percent": psutil.disk_usage("/").percent}}

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping": await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(open(os.path.join(os.path.dirname(__file__), "dashboard.html"), encoding="utf-8").read() if os.path.exists(os.path.join(os.path.dirname(__file__), "dashboard.html")) else DASHBOARD_HTML)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>ClaudioSec</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0a0e1a;color:#c9d1d9;min-height:100vh}
.header{background:#161b27;border-bottom:1px solid #30363d;padding:16px 24px;display:flex;align-items:center;gap:16px}
.header h1{color:#58a6ff;font-size:1.4rem;letter-spacing:2px}
.dot{width:10px;height:10px;border-radius:50%;background:#3fb950;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;padding:24px}
.card{background:#161b27;border:1px solid #30363d;border-radius:8px;padding:20px}
.card h3{color:#8b949e;font-size:.75rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.card .value{font-size:2rem;font-weight:bold;color:#58a6ff}
.card.crit .value{color:#f85149}.card.warn .value{color:#d29922}
.section{padding:0 24px 24px}
.section h2{color:#58a6ff;margin-bottom:12px;font-size:1rem;letter-spacing:1px}
.event{background:#161b27;border:1px solid #30363d;border-left:3px solid #30363d;border-radius:4px;padding:12px 16px;margin-bottom:8px;display:flex;gap:12px}
.event.critical{border-left-color:#f85149}.event.high{border-left-color:#d29922}.event.medium{border-left-color:#388bfd}.event.low{border-left-color:#3fb950}
.badge{padding:2px 8px;border-radius:4px;font-size:.7rem;text-transform:uppercase;font-weight:bold;white-space:nowrap}
.badge.critical{background:rgba(248,81,73,.2);color:#f85149}.badge.high{background:rgba(210,153,34,.2);color:#d29922}
.badge.medium{background:rgba(56,139,253,.2);color:#388bfd}.badge.low{background:rgba(63,185,80,.2);color:#3fb950}
.etitle{color:#c9d1d9;font-size:.9rem;margin-bottom:4px}.emeta{color:#8b949e;font-size:.75rem}
.chatbox{background:#161b27;border:1px solid #30363d;border-radius:8px;padding:16px;height:300px;overflow-y:auto;margin-bottom:12px}
.row{display:flex;gap:8px}
.row input{flex:1;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:10px 14px;border-radius:6px;font-family:inherit}
.row button{background:#1f6feb;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer}
.msg{margin-bottom:12px}.msg .role{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.msg.user .role{color:#58a6ff}.msg.assistant .role{color:#3fb950}
.msg .text{font-size:.85rem;line-height:1.5}
</style></head>
<body>
<div class="header"><div class="dot"></div><h1>🛡️ CLAUDIOSEC</h1><span style="color:#3fb950;font-size:.75rem">● LIVE</span><span style="margin-left:auto;color:#8b949e;font-size:.8rem" id="upd"></span></div>
<div class="grid">
  <div class="card"><h3>Total Events</h3><div class="value" id="s-tot">—</div></div>
  <div class="card crit"><h3>Critical</h3><div class="value" id="s-crit">—</div></div>
  <div class="card warn"><h3>Unresolved</h3><div class="value" id="s-unres">—</div></div>
  <div class="card"><h3>Last 24h</h3><div class="value" id="s-24">—</div></div>
  <div class="card"><h3>CPU</h3><div class="value" id="s-cpu">—</div></div>
  <div class="card"><h3>Memory</h3><div class="value" id="s-mem">—</div></div>
</div>
<div class="section"><h2>⚡ LIVE EVENTS</h2><div id="events">Loading...</div></div>
<div class="section"><h2>🤖 AI ANALYST</h2>
  <div class="chatbox" id="chat"></div>
  <div class="row"><input id="inp" placeholder="Ask the AI analyst..." onkeydown="if(event.key==='Enter')send()"/><button onclick="send()">Send</button></div>
</div>
<script>
const API=location.origin;let hist=[];
async function loadStats(){try{const d=await(await fetch(API+'/api/stats')).json();document.getElementById('s-tot').textContent=d.total_events??'—';document.getElementById('s-crit').textContent=d.critical_unresolved??'—';document.getElementById('s-unres').textContent=d.unresolved??'—';document.getElementById('s-24').textContent=d.last_24h??'—';document.getElementById('s-cpu').textContent=(d.system?.cpu_percent??'—')+'%';document.getElementById('s-mem').textContent=(d.system?.memory_percent??'—')+'%'}catch(e){}}
async function loadEvents(){try{const d=await(await fetch(API+'/api/events?limit=20')).json();const c=document.getElementById('events');if(!d.events?.length){c.innerHTML='<div style="color:#8b949e;padding:20px 0">No events yet.</div>';return}c.innerHTML=d.events.map(e=>`<div class="event ${e.severity}"><span class="badge ${e.severity}">${e.severity}</span><div><div class="etitle">${e.title}</div><div class="emeta">${e.source_module} · ${e.event_type} · ${(e.timestamp||'').slice(0,19).replace('T',' ')} UTC${e.source_ip?' · '+e.source_ip:''}</div></div></div>`).join('');document.getElementById('upd').textContent='Updated: '+new Date().toLocaleTimeString()}catch(e){}}
function connectWS(){const ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws');ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.type==='new_event'){loadEvents();loadStats()}};ws.onclose=()=>setTimeout(connectWS,3000)}
async function send(){const inp=document.getElementById('inp');const t=inp.value.trim();if(!t)return;inp.value='';hist.push({role:'user',content:t});addMsg('user',t);try{const d=await(await fetch(API+'/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({messages:hist})})).json();hist.push({role:'assistant',content:d.response});addMsg('assistant',d.response)}catch(e){addMsg('assistant','Error.')}}
function addMsg(role,text){const b=document.getElementById('chat');const d=document.createElement('div');d.className='msg '+role;d.innerHTML=`<div class="role">${role==='user'?'👤 You':'🤖 ClaudioSec AI'}</div><div class="text">${text.replace(/\n/g,'<br>')}</div>`;b.appendChild(d);b.scrollTop=b.scrollHeight}
loadStats();loadEvents();connectWS();setInterval(()=>{loadStats();loadEvents()},10000);
</script>
</body></html>"""